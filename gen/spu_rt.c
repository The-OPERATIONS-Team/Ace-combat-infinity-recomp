#include "spu_runtime.h"
#include "ppu_runtime.h"
#include "statecap.h"
#include "ptrace.h"
#include "spu_polldet.h"
#include "mtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static uint64_t spuprof_now(void);
static void     spuprof_blocked(uint64_t t0);
static void     spuprof_lock(uint64_t t0);

static uint8_t*  g_main = 0;
static uint64_t  g_mainsz = 0;
#pragma comment(lib, "winmm")
#pragma comment(lib, "synchronization")

static SpuThread* g_all_thr[16]; static volatile long g_all_n;
static void lockline_lost(uint32_t line, const SpuThread* by);
static void lockline_wake(uint32_t ea){
    if(g_main && (uint64_t)(ea & ~127u) + 128 <= g_mainsz)
        WakeByAddressAll(g_main + (ea & ~127u));
}
static void spu_statecap(const char* dir);
void spu_rt_set_mainmem(uint8_t* base, uint64_t size){
    g_main = base; g_mainsz = size;
    statecap_register("spu",spu_statecap);
    timeBeginPeriod(1);
}

static void (*g_dma_read_hook)(uint32_t ea, uint32_t sz);
static uint32_t g_dma_hook_lo, g_dma_hook_hi;
void spu_set_dma_read_hook(void (*h)(uint32_t, uint32_t), uint32_t lo, uint32_t hi){
    g_dma_read_hook = h; g_dma_hook_lo = lo; g_dma_hook_hi = hi;
}
static inline void dma_read_hook(uint32_t ea, uint32_t sz){
    if(g_dma_read_hook && ea < g_dma_hook_hi && ea + sz > g_dma_hook_lo)
        g_dma_read_hook(ea, sz);
}

struct SpuThread {
    SPUContext ctx;
    uint8_t*   ls;
    uint32_t   mfc_lsa, mfc_eah, mfc_eal, mfc_size, mfc_tag;
    uint32_t   resv_ea; uint8_t resv_data[128]; int resv_valid;
    uint32_t   atomic_stat;
    int32_t    poll_tokens;
    uint32_t   poll_refill_ms;
    SpdLlNew   ll;
    SpdCh      rc;
    uint32_t   slot;
    struct { uint32_t op, ea, sz, lsa; } mfc_ring[32];
    uint32_t   mfc_ring_n;
    struct { int active; uint32_t op, tag, list_ls, idx, n, cur_ls; } lstall;
    uint32_t   stall_stat;
    struct { void* fn; uint32_t from, to; } disp_ring[16];
    uint32_t   disp_n;
    uint32_t   out_mbox[4]; int out_n;
    uint32_t   in_mbox[4];  int in_n;
    uint32_t   out_intr[1]; int out_intr_n;
    uint32_t   sig1, sig2;
    uint32_t   event_mask, event_stat;
    uint64_t   dec_qpc;
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE cv;
    HANDLE     thread;
    void     (*run)(SPUContext*);
    volatile int running;
    uint32_t   stop_code;
};

static void lockline_lost(uint32_t line, const SpuThread* by){
    long n = g_all_n; if(n > 16) n = 16;
    for(long i = 0; i < n; i++){
        SpuThread* u = g_all_thr[i];
        if(!u || u == by) continue;
        if(!u->resv_valid || u->resv_ea != line) continue;
        u->resv_valid = 0;
        u->event_stat |= 0x400;
    }
}

enum {
    CH_RdEventStat=0, CH_WrEventMask=1, CH_WrEventAck=2,
    CH_RdSigNotify1=3, CH_RdSigNotify2=4, CH_WrDec=7, CH_RdDec=8,
    CH_RdMachStat=13, CH_WrSRR0=14, CH_RdSRR0=15,
    CH_MFC_LSA=16, CH_MFC_EAH=17, CH_MFC_EAL=18, CH_MFC_Size=19, CH_MFC_TagID=20,
    CH_MFC_Cmd=21, CH_MFC_WrTagMask=22, CH_MFC_WrTagUpdate=23, CH_MFC_RdTagStat=24,
    CH_MFC_RdListStallStat=25, CH_MFC_WrListStallAck=26, CH_MFC_RdAtomicStat=27,
    CH_SPU_WrOutMbox=28, CH_SPU_RdInMbox=29, CH_SPU_WrOutIntrMbox=30
};

static SpuThread* self(SPUContext* c){ return (SpuThread*)c->spu; }

#define ATOM_STRIPES SPD_STRIPES_NEW
typedef struct { SRWLOCK lk; char pad[64 - sizeof(SRWLOCK)]; } AtomStripe;
static __declspec(align(64)) AtomStripe g_atom_srw[ATOM_STRIPES];
static CRITICAL_SECTION g_pm_lock;
static volatile long g_atomic_lock_init;
#define MFC_PUTLLC_SUCCESS  0
#define MFC_PUTLLC_FAILURE  1
#define MFC_PUTLLUC_SUCCESS 2
#define MFC_GETLLAR_SUCCESS 4

static void atomic_lock_init(void){
    static volatile long state;
    if(state==2) return;
    if(InterlockedCompareExchange(&state,1,0)==0){
        for(int i=0;i<ATOM_STRIPES;i++) InitializeSRWLock(&g_atom_srw[i].lk);
        InitializeCriticalSection(&g_pm_lock);
        g_atomic_lock_init=1;
        InterlockedExchange(&state,2);
    } else while(state!=2) SwitchToThread();
}
static SRWLOCK* atom_srw(uint32_t ea){
    return &g_atom_srw[spd_stripe_new(ea)].lk;
}

uint32_t ppu_lwarx(PPUContext* ctx, uint8_t* base, uint32_t ea){
    atomic_lock_init();
    SRWLOCK* cs = atom_srw(ea);
    AcquireSRWLockShared(cs);
    uint32_t raw; memcpy(&raw, base+ea, 4);
    ReleaseSRWLockShared(cs);
    ctx->reserve_addr=ea; ctx->reserve_value=raw; ctx->reserve_valid=1;
    return __builtin_bswap32(raw);
}
uint64_t ppu_ldarx(PPUContext* ctx, uint8_t* base, uint32_t ea){
    atomic_lock_init();
    SRWLOCK* cs = atom_srw(ea);
    AcquireSRWLockShared(cs);
    uint64_t raw; memcpy(&raw, base+ea, 8);
    ReleaseSRWLockShared(cs);
    ctx->reserve_addr=ea; ctx->reserve_value=raw; ctx->reserve_valid=1;
    return __builtin_bswap64(raw);
}
void ppu_stwcx(PPUContext* ctx, uint8_t* base, uint32_t ea, uint32_t v){
    atomic_lock_init();
    int ok=0;
    SRWLOCK* cs = atom_srw(ea);
    AcquireSRWLockExclusive(cs);
    if(ctx->reserve_valid){
        uint32_t cur; memcpy(&cur, base+ea, 4);
        if(cur==(uint32_t)ctx->reserve_value){ uint32_t want=__builtin_bswap32(v); memcpy(base+ea,&want,4); ok=1; }
    }
    ReleaseSRWLockExclusive(cs);
    if(ok){ lockline_lost(ea & ~127u, 0); lockline_wake(ea); }
    ctx->reserve_valid=0; ctx->cr[0]=(uint8_t)((ok?2:0)|(ctx->so?1:0));
}
void ppu_stdcx(PPUContext* ctx, uint8_t* base, uint32_t ea, uint64_t v){
    atomic_lock_init();
    int ok=0;
    SRWLOCK* cs = atom_srw(ea);
    AcquireSRWLockExclusive(cs);
    if(ctx->reserve_valid){
        uint64_t cur; memcpy(&cur, base+ea, 8);
        if(cur==ctx->reserve_value){ uint64_t want=__builtin_bswap64(v); memcpy(base+ea,&want,8); ok=1; }
    }
    ReleaseSRWLockExclusive(cs);
    if(ok){ lockline_lost(ea & ~127u, 0); lockline_wake(ea); }
    ctx->reserve_valid=0; ctx->cr[0]=(uint8_t)((ok?2:0)|(ctx->so?1:0));
}

#define POLL_CAP   4096
#define POLL_RATE  1024
static void spu_poll_work(SpuThread* t){
    t->poll_tokens = POLL_CAP; t->ll.idle = 0; t->rc.n = 0;
    PTRC(t->slot, PT_WORK, 0, 0);
}

static void spu_poll_read(SpuThread* t, uint32_t ea, uint32_t sz){
    (void)ea;
    static int nopace = -1;
    static int rate = -1, pyield = -1;
    if(nopace < 0){
        nopace = getenv("PS3_SPU_NOPACE") ? 1 : 0;
        const char* r = getenv("PS3_SPU_POLLRATE");
        rate = (r && atoi(r) > 0) ? atoi(r) : POLL_RATE;
        pyield = getenv("PS3_SPU_POLLYIELD") ? 1 : 0;
    }
    if(nopace) return;
    if(sz > 512){ spu_poll_work(t); return; }
    DWORD now = GetTickCount();
    if(now != t->poll_refill_ms){
        DWORD dt = now - t->poll_refill_ms;
        t->poll_refill_ms = now;
        int32_t add = (dt > 64) ? POLL_CAP : (int32_t)dt * rate;
        t->poll_tokens = (t->poll_tokens > POLL_CAP - add) ? POLL_CAP : t->poll_tokens + add;
    }
    if(--t->poll_tokens < 0){ t->poll_tokens = 0;
        uint64_t tb=spuprof_now();
        if(pyield) SwitchToThread(); else Sleep(1);
        spuprof_blocked(tb); }
}

static void lswatch(SpuThread* t, uint32_t op, uint32_t lsa, uint32_t ea, uint32_t sz){
    static uint32_t lo, hi; static int init, save, quiet;
    if(!init){ init=1; const char* e=getenv("PS3_LSWATCH");
        if(e){ unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b); lo=a; hi=b;
               fprintf(stderr,"[LSWATCH] armed [0x%x,0x%x)\n",lo,hi); }
        save=getenv("PS3_LSWATCH_SAVE")?1:0;
        quiet=getenv("PS3_LSWATCH_QUIET")?1:0; }
    if(hi<=lo || lsa>=hi || lsa+sz<=lo || !sz) return;
    const uint8_t* s = (op & 0x40) ? g_main+ea : t->ls+lsa;
    if(!quiet)
        fprintf(stderr,"[LSWATCH] %lu t=%p op=%02x ls=0x%x ea=0x%x sz=0x%x pc=0x%x fw=%02x%02x%02x%02x\n",
                (unsigned long)GetTickCount(),(void*)t,op,lsa,ea,sz,t->ctx.pc,s[0],s[1],s[2],s[3]);
    if(save && (op&0x40) && sz>=0x400){
        static SRWLOCK lk = SRWLOCK_INIT;
        static struct { uint32_t ea, lsa, sz; } seen[256]; static int nseen;
        int prologue = (s[0]>=0x41 && s[0]<=0x44 && s[3]==0x02);
        AcquireSRWLockExclusive(&lk);
        int dup=0, cont=0;
        for(int i=0;i<nseen;i++){
            if(seen[i].ea==ea){ dup=1; break; }
            if(seen[i].ea+seen[i].sz==ea && seen[i].lsa+seen[i].sz==lsa) cont=1;
        }
        if(!dup && (prologue||cont) && nseen<256){
            seen[nseen].ea=ea; seen[nseen].lsa=lsa; seen[nseen].sz=sz; nseen++;
            char fn[64]; snprintf(fn,sizeof fn,"logs/stage_%06x.bin",ea);
            FILE* f=fopen(fn,"wb");
            if(f){ fwrite(g_main+ea,1,sz,f); fclose(f);
                   fprintf(stderr,"[LSWATCH] saved %s ls=0x%x sz=0x%x%s\n",
                           fn,lsa,sz,cont&&!prologue?" (continuation)":""); }
        }
        ReleaseSRWLockExclusive(&lk);
    }
}

static uint32_t g_tbl_lo, g_tbl_hi;
static void tbl_init(void){
    static int init; if(init) return; init=1;
    const char* e=getenv("PS3_TBLWATCH"); if(!e) return;
    unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b);
    if(b>a){ g_tbl_lo=a; g_tbl_hi=b;
             fprintf(stderr,"[TBLW] spu-side armed [0x%x,0x%x)\n",a,b); }
}
static void tbl_put(SpuThread* t, const char* kind, uint32_t ea, uint32_t sz,
                    const uint8_t* newsrc){
    tbl_init();
    if(!g_tbl_hi || ea>=g_tbl_hi || (uint64_t)ea+sz<=g_tbl_lo) return;
    uint32_t lo = ea>g_tbl_lo?ea:g_tbl_lo;
    uint32_t hi = (ea+sz<g_tbl_hi?ea+sz:g_tbl_hi);
    char b[640]; int o=snprintf(b,sizeof b,"[TBLW] %lu %s t=%p pc=0x%x ea=0x%x sz=0x%x |",
        (unsigned long)GetTickCount(),kind,(void*)t,t->ctx.pc,ea,sz);
    for(uint32_t a=lo&~3u; a<hi && o<(int)sizeof b-24; a+=4){
        const uint8_t* od=g_main+a; const uint8_t* nd=newsrc+(a-ea);
        uint32_t ov=(uint32_t)od[0]<<24|od[1]<<16|od[2]<<8|od[3];
        uint32_t nv=(uint32_t)nd[0]<<24|nd[1]<<16|nd[2]<<8|nd[3];
        if(ov!=nv) o+=snprintf(b+o,sizeof b-o," %x:%08x->%08x",a,ov,nv);
    }
    fprintf(stderr,"%s\n",b);
}

static void tbl_get(SpuThread* t, const char* kind, uint32_t ea, uint32_t sz){
    tbl_init();
    if(!g_tbl_hi || ea>=g_tbl_hi || (uint64_t)ea+sz<=g_tbl_lo) return;
    static struct { uint32_t ea, pc; volatile long n; } cap[96];
    static volatile long ncap;
    uint32_t pc=t->ctx.pc; long idx=-1;
    long lim = ncap<96?ncap:96;
    for(long i=0;i<lim;i++) if(cap[i].ea==ea && cap[i].pc==pc){ idx=i; break; }
    if(idx<0){ long k=InterlockedIncrement(&ncap)-1;
               if(k<96){ cap[k].ea=ea; cap[k].pc=pc; idx=k; } }
    long n = idx>=0 ? InterlockedIncrement(&cap[idx].n) : 1;
    if(n>24 && (n%8192)!=0) return;
    uint32_t lo = ea>g_tbl_lo?ea:g_tbl_lo;
    const uint8_t* d=g_main+lo;
    fprintf(stderr,"[TBLR] %lu %s t=%p pc=0x%x ea=0x%x sz=0x%x @%x= %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x (n=%ld)\n",
        (unsigned long)GetTickCount(),kind,(void*)t,pc,ea,sz,lo,
        d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],
        d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15],n);
}

static int mfc_drop(uint32_t ea, uint32_t sz){
    static uint32_t dlo=0, dhi=0; static int init=-1;
    if(init<0){ const char* e=getenv("PS3_MFCDROP");
        init = (e && sscanf(e,"%x:%x",&dlo,&dhi)==2) ? 1 : 0;
        if(init) fprintf(stderr,"[MFCDROP] armed [0x%x,0x%x)\n",dlo,dhi); }
    if(init && ea<dhi && ea+sz>dlo){
        static volatile long n; long k=InterlockedIncrement(&n);
        if(k<=4||(k%2048)==0)
            fprintf(stderr,"[MFCDROP] dropped PUT ea=0x%x sz=0x%x (n=%ld)\n",ea,sz,k);
        return 1;
    }
    return 0;
}

enum { MFCK_PUT, MFCK_GET, MFCK_NOP, MFCK_ZERO, MFCK_SNDSIG, MFCK_UNKNOWN };
static int mfc_kind(uint8_t op){
    if((op & 0xe0) == 0x20) return MFCK_PUT;
    if((op & 0xf0) == 0x40) return MFCK_GET;
    switch(op){
    case 0x80: case 0x81:
    case 0x8d: case 0x8f:
    case 0xc0: case 0xc8: case 0xcc:
        return MFCK_NOP;
    case 0x89: return MFCK_ZERO;
    case 0xa0: case 0xa1: case 0xa2: return MFCK_SNDSIG;
    default:   return MFCK_UNKNOWN;
    }
}

enum { MA_SMALL_SKEW, MA_BIG_UNALIGNED, MA_LIST_BASE, MA_LIST_SMALL, MA_LIST_UNALIGNED,
       MA_NONXFER, MA_N };
static const char* const g_mfc_anom_name[MA_N] = {
    "small xfer, LSA/EA low nibbles differ", "xfer >=16B not 16B-aligned",
    "list base LSA not 16B-aligned", "list element <16B at unaligned EA",
    "list element >=16B at unaligned EA", "non-transfer command" };
static int g_mfccensus = -1;
static volatile long g_mfc_opn[256], g_mfc_anom[MA_N];
static void mfc_anom(SpuThread* t, int kind, uint32_t op, uint32_t lsa, uint32_t ea, uint32_t sz){
    if(g_mfccensus <= 0) return;
    long k = InterlockedIncrement(&g_mfc_anom[kind]);
    if(k <= 12 || (k & (k-1)) == 0)
        fprintf(stderr,"[MFCCENSUS] %s: op=0x%02x lsa=0x%x ea=0x%x sz=0x%x pc=0x%x spu=%u (n=%ld)\n",
                g_mfc_anom_name[kind], op, lsa, ea, sz, t->ctx.pc, t->slot, k);
}
static void mfc_census(SpuThread* t, uint32_t op, uint32_t lsa, uint32_t ea, uint32_t sz){
    if(g_mfccensus < 0) g_mfccensus = getenv("PS3_MFCCENSUS") ? 1 : 0;
    if(!g_mfccensus) return;
    InterlockedIncrement(&g_mfc_opn[op & 0xff]);
    int kind = mfc_kind((uint8_t)op);
    if(kind == MFCK_NOP || kind == MFCK_ZERO || kind == MFCK_SNDSIG || kind == MFCK_UNKNOWN){
        if(op != 0xd0 && op != 0xb4 && op != 0xb0 && op != 0xb8) mfc_anom(t, MA_NONXFER, op, lsa, ea, sz);
    } else if(op & 0x04){
        if(lsa & 15u) mfc_anom(t, MA_LIST_BASE, op, lsa, ea, sz);
    } else if(sz){
        if(sz < 16){ if((lsa ^ ea) & 15u) mfc_anom(t, MA_SMALL_SKEW, op, lsa, ea, sz); }
        else if((lsa | ea) & 15u) mfc_anom(t, MA_BIG_UNALIGNED, op, lsa, ea, sz);
    }
    static volatile LONG last_ms;
    LONG now = (LONG)GetTickCount(), prev = last_ms;
    if((ULONG)(now - prev) >= 5000 && InterlockedCompareExchange(&last_ms, now, prev) == prev){
        char b[1024]; int o = snprintf(b, sizeof b, "[MFCCENSUS] ops:");
        for(int i = 0; i < 256 && o < (int)sizeof b - 32; i++)
            if(g_mfc_opn[i]) o += snprintf(b+o, sizeof b - o, " %02x=%ld", i, g_mfc_opn[i]);
        o += snprintf(b+o, sizeof b - o, " | anomalies:");
        for(int i = 0; i < MA_N && o < (int)sizeof b - 32; i++)
            o += snprintf(b+o, sizeof b - o, " %ld", g_mfc_anom[i]);
        fprintf(stderr, "%s\n", b);
    }
}

static int mfc_list_old(void){
    static int old = -1;
    if(old < 0) old = getenv("PS3_MFCLIST_OLD") ? 1 : 0;
    return old;
}
static void mfc_list_run(SpuThread* t){
    int get = mfc_kind((uint8_t)t->lstall.op) == MFCK_GET;
    int oldlist = mfc_list_old();
    while(t->lstall.idx < t->lstall.n){
        const uint8_t* el = t->ls + ((t->lstall.list_ls + t->lstall.idx*8) & SPU_LSMASK);
        uint32_t w0    = (uint32_t)el[0]<<24|el[1]<<16|el[2]<<8|el[3];
        uint32_t esz   = w0 & 0x7fff;
        uint32_t stall = w0 & 0x80000000u;
        uint32_t eal   = (uint32_t)el[4]<<24|el[5]<<16|el[6]<<8|el[7];
        uint32_t cur_ls = t->lstall.cur_ls;
        if(esz && (eal & 15u))
            mfc_anom(t, esz < 16 ? MA_LIST_SMALL : MA_LIST_UNALIGNED, t->lstall.op, cur_ls, eal, esz);
        if(!oldlist && esz < 16) cur_ls |= eal & 15u;
        if(esz && (uint64_t)eal+esz<=g_mainsz && (uint64_t)cur_ls+esz<=0x40000ull){
            if(get) dma_read_hook(eal, esz);
            lswatch(t, t->lstall.op, cur_ls, eal, esz);
            if(get && cur_ls<=0xa00 && cur_ls+esz>0xa00 && esz>=0x800){
                const uint8_t* s=g_main+eal+(0xa00-cur_ls);
                fprintf(stderr,"[SPU-DMA-A00] %lu getl ls=0x%x ea=0x%x sz=0x%x src@a00=%02x%02x%02x%02x\n",
                        (unsigned long)GetTickCount(),cur_ls,eal,esz,s[0],s[1],s[2],s[3]);
            }
            if(get) tbl_get(t,"GETL",eal,esz);
            if(get) memcpy(t->ls+cur_ls, g_main+eal, esz);
            else{
                static uint32_t wlo2=0, whi2=0; static int init2;
                if(!init2){ init2=1; const char* e=getenv("PS3_MFCWATCH");
                           if(e){ unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b); wlo2=a; whi2=b; } }
                if(whi2>wlo2 && eal<whi2 && eal+esz>wlo2)
                    fprintf(stderr,"[MFCWATCH] %lu PUTL ea=0x%x sz=0x%x ls=0x%x pc=0x%x\n",
                            (unsigned long)GetTickCount(),eal,esz,cur_ls,t->ctx.pc);
                tbl_put(t,"PUTL",eal,esz,t->ls+cur_ls);
                if(!mfc_drop(eal,esz))
                memcpy(g_main+eal, t->ls+cur_ls, esz);
            }
        }
        t->lstall.cur_ls += (esz+15)&~15u;
        t->lstall.idx++;
        if(stall){
            t->lstall.active = 1;
            t->stall_stat |= 1u << t->lstall.tag;
            static int ns; if(ns++<16)
                fprintf(stderr,"[MFC] list stall tag=%u el=%u/%u ls=0x%x pc=0x%x\n",
                        t->lstall.tag, t->lstall.idx, t->lstall.n,
                        t->lstall.list_ls, t->ctx.pc);
            return;
        }
    }
    t->lstall.active = 0;
}

static void mfc_do(SpuThread* t, uint32_t cmd){
    uint32_t lsa = t->mfc_lsa & SPU_LSMASK;
    uint32_t ea  = t->mfc_eal;
    uint32_t sz  = t->mfc_size;
    uint8_t  op  = (uint8_t)cmd;
    static int mon = -1;
    if(mon < 0){ const char* rg=getenv("PS3_ROGUARD");
                 mon = (getenv("PS3_SPUMON")||getenv("PS3_MFCWATCH")||
                        !(rg && rg[0]=='0')) ? 1 : 0; }
    if(mon){ uint32_t k = t->mfc_ring_n++ & 31;
      t->mfc_ring[k].op=op; t->mfc_ring[k].ea=ea; t->mfc_ring[k].sz=sz; t->mfc_ring[k].lsa=lsa; }
    if(!g_main) return;
    atomic_lock_init();
    mfc_census(t, op, lsa, ea, sz);

    switch(op){
    case 0xd0: {
        uint32_t cea = ea & ~127u;
        spu_poll_read(t, cea, 128);
        if(cea+128>g_mainsz){
            static volatile long n; long k=InterlockedIncrement(&n);
            if(k<=16||(k%100000)==0)
                fprintf(stderr,"[GETLLAR] OOR ea=0x%x lsa=0x%x pc=0x%x (n=%ld)\n",ea,lsa,t->ctx.pc,k);
            if(k==1){
                FILE* f=fopen("oor_ls.bin","wb");
                if(f){ fwrite(t->ls,1,0x40000,f); fclose(f); }
                char b[1024]; int o=snprintf(b,sizeof b,"[GETLLAR] OOR regs:");
                for(int r=2;r<32 && o<(int)sizeof b-24;r++)
                    o+=snprintf(b+o,sizeof b-o," r%d=%x",r,t->ctx.r[r].w[0]);
                fprintf(stderr,"%s\n",b);
            }
            return;
        }
        static int spumon = -1;
        if(spumon < 0) spumon = getenv("PS3_SPUMON") ? 1 : 0;
        if(spumon){
          static uint32_t seen[64]; static volatile long cnt[64]; static int ns=0;
          static volatile long total; static DWORD last_tick;
          int idx=-1;
          for(int i=0;i<ns;i++) if(seen[i]==cea){ idx=i; break; }
          if(idx<0 && ns<64){ idx=ns; seen[ns]=cea; ns++; fprintf(stderr,"[GETLLAR] new ea=0x%x lsa=0x%x\n",cea,lsa); }
          if(idx>=0) InterlockedIncrement(&cnt[idx]);
          if(InterlockedIncrement(&total)%100000==0){
              DWORD now=GetTickCount();
              if(now-last_tick>4000){ last_tick=now;
                  char b[2048]; int n=snprintf(b,sizeof b,"[GETLLAR] counts:");
                  for(int i=0;i<ns && n<(int)sizeof b-32;i++)
                      n+=snprintf(b+n,sizeof b-n," 0x%x=%ld",seen[i],cnt[i]);
                  fprintf(stderr,"%.*s\n",(int)sizeof b,b); } } }
        SRWLOCK* cs = atom_srw(cea);
        { uint64_t tl=spuprof_now();
          AcquireSRWLockShared(cs);
          spuprof_lock(tl); }
        memcpy(t->ls + (lsa&~127u), g_main + cea, 128);
        { static int yat=-1, pat;
          if(yat<0){ const char* e=getenv("PS3_SPU_LLYIELD");
                     yat = e ? atoi(e) : 16;
                     e = getenv("PS3_SPU_LLPARK");
                     pat = e ? atoi(e) : 64; }
          uint64_t tag = spd_tag128(g_main + cea);
          uint32_t idle = spd_ll_new(&t->ll, cea, tag);
          PTRC(t->slot, PT_GETLLAR, cea, (uint32_t)tag);
          if(yat > 0 && idle >= (uint32_t)yat){
              ReleaseSRWLockShared(cs);
              uint64_t tb=spuprof_now();
              if(pat > 0 && idle >= (uint32_t)pat){
                  unsigned long long cap;
                  memcpy(&cap, g_main+cea, 8);
                  WaitOnAddress(g_main+cea, &cap, 8, 1);
              } else SwitchToThread();
              spuprof_blocked(tb);
              AcquireSRWLockShared(cs);
              memcpy(t->ls + (lsa&~127u), g_main + cea, 128);
              spd_ll_new(&t->ll, cea, spd_tag128(g_main + cea));
          } }
        tbl_get(t,"GETLLAR",cea,128);
        memcpy(t->resv_data, g_main + cea, 128);
        t->resv_ea = cea; t->resv_valid = 1;
        ReleaseSRWLockShared(cs);
        t->atomic_stat |= MFC_GETLLAR_SUCCESS;
        t->mfc_size = 0; return;
    }
    case 0xb4: {
        uint32_t cea = ea & ~127u;
        int ok = 0;
        PTRC(t->slot, PT_PUTLLC, cea, 1);
        if(cea+128<=g_mainsz && t->resv_valid && t->resv_ea==cea){
            SRWLOCK* cs = atom_srw(cea);
            AcquireSRWLockExclusive(cs);
            if(memcmp(g_main+cea, t->resv_data, 128)==0){
                const uint8_t* lsrc = t->ls + (lsa&~127u);
                uint8_t* dst = g_main + cea;
                tbl_put(t,"PUTLLC",cea,128,lsrc);
                for(int i=0;i<128;i++)
                    if(lsrc[i]!=t->resv_data[i]) dst[i]=lsrc[i];
                ok=1;
            }
            ReleaseSRWLockExclusive(cs);
        }
        if(!ok){ tbl_init();
            if(g_tbl_hi && cea<g_tbl_hi && cea+128>g_tbl_lo){
                static volatile long nf; long k=InterlockedIncrement(&nf);
                if(k<=256 || (k%1000)==0)
                    fprintf(stderr,"[TBLW] %lu PUTLLC-FAIL t=%p pc=0x%x ea=0x%x resv=%d (n=%ld)\n",
                            (unsigned long)GetTickCount(),(void*)t,t->ctx.pc,cea,
                            t->resv_valid && t->resv_ea==cea, k);
            } }
        t->resv_valid = 0;
        if(ok){ lockline_lost(cea, t); lockline_wake(cea); }
        { static int spumon2 = -1;
          if(spumon2 < 0) spumon2 = getenv("PS3_SPUMON") ? 1 : 0;
          if(spumon2){ static volatile long n; long k=InterlockedIncrement(&n);
            if(k<=32||k%20000000==0) fprintf(stderr,"[PUTLLC] ea=0x%x ok=%d (n=%ld)\n",cea,ok,k); } }
        if(cea+128>g_mainsz){
            static volatile long n2; long k2=InterlockedIncrement(&n2);
            if(k2<=16||(k2%100000)==0)
                fprintf(stderr,"[PUTLLC] OOR ea=0x%x lsa=0x%x pc=0x%x (n=%ld)\n",ea,lsa,t->ctx.pc,k2);
        }
        t->atomic_stat |= ok ? MFC_PUTLLC_SUCCESS : MFC_PUTLLC_FAILURE;
        t->mfc_size = 0; return;
    }
    case 0xb0: case 0xb8: {
        uint32_t cea = ea & ~127u;
        if(cea+128<=g_mainsz){
            SRWLOCK* cs = atom_srw(cea);
            AcquireSRWLockExclusive(cs);
            tbl_put(t,"PUTLLUC",cea,128,t->ls+(lsa&~127u));
            memcpy(g_main+cea, t->ls + (lsa&~127u), 128);
            ReleaseSRWLockExclusive(cs);
            lockline_lost(cea, t); lockline_wake(cea);
        }
        t->atomic_stat |= MFC_PUTLLUC_SUCCESS;
        t->mfc_size = 0; return;
    }
    default: break;
    }

    if((uint64_t)ea + sz > g_mainsz || (uint64_t)lsa + sz > 0x40000ull){
        static int n; if(n++<16)
            fprintf(stderr,"[MFC] rejected dma op=0x%x lsa=0x%x ea=0x%x sz=0x%x\n",op,lsa,ea,sz);
        t->mfc_size = 0; return;
    }
    int kind = mfc_kind(op);
    if(kind != MFCK_PUT && kind != MFCK_GET){
        if(kind == MFCK_ZERO && sz){
            uint32_t lo = ea & ~127u;
            uint64_t hi = ((uint64_t)ea + sz + 127u) & ~127ull;
            if(hi <= g_mainsz){ memset(g_main + lo, 0, (size_t)(hi - lo));
                for(uint32_t l = lo; l < hi; l += 128){ lockline_lost(l, t); lockline_wake(l); } }
        }
        if(kind == MFCK_SNDSIG || kind == MFCK_UNKNOWN || kind == MFCK_ZERO){
            static volatile long n; long k = InterlockedIncrement(&n);
            if(k <= 16) fprintf(stderr,"[MFC] %s cmd 0x%02x lsa=0x%x ea=0x%x sz=0x%x pc=0x%x\n",
                                kind == MFCK_ZERO ? "sdcrz" : kind == MFCK_SNDSIG ? "sndsig (not routed)"
                                                                               : "unknown (ignored)",
                                op, lsa, ea, sz, t->ctx.pc);
        }
        t->mfc_size = 0; return;
    }
    int list = (op & 0x04) != 0;
    int get  = kind == MFCK_GET;
    if(list){
        if(sz < 8){ spu_poll_read(t, ea, 0); t->mfc_size = 0; return; }
        spu_poll_work(t);
        if(t->lstall.active){
            static int nw; if(nw++<16)
                fprintf(stderr,"[MFC] list cmd 0x%x tag=%u while tag=%u list stalled pc=0x%x\n",
                        op, t->mfc_tag, t->lstall.tag, t->ctx.pc);
        }
        t->lstall.active = 0;
        t->lstall.op = op;
        t->lstall.tag = t->mfc_tag & 31;
        t->lstall.list_ls = ea & SPU_LSMASK;
        t->lstall.idx = 0;
        t->lstall.n = sz/8;
        t->lstall.cur_ls = mfc_list_old() ? lsa : (lsa & ~15u);
        mfc_list_run(t);
        t->mfc_size = 0; return;
    }
    {
        static uint32_t wlo=0, whi=0; static int init;
        if(!init){ init=1; const char* e=getenv("PS3_MFCWATCH");
                   if(e){ unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b); wlo=a; whi=b;
                          fprintf(stderr,"[MFCWATCH] armed [0x%x,0x%x)\n",wlo,whi); } }
        if(whi>wlo && !get && ea<whi && ea+sz>wlo){
            fprintf(stderr,"[MFCWATCH] %lu PUT ea=0x%x sz=0x%x lsa=0x%x pc=0x%x\n",
                    (unsigned long)GetTickCount(),ea,sz,lsa,t->ctx.pc);
            static volatile long wn; long wk=InterlockedIncrement(&wn);
            if(wk<=8 || (wk%1024)==0){
                const uint8_t* p=t->ls+lsa;
                fprintf(stderr,"[MFCWATCH]   payload=%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
                        p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                        p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
                char rb[512]; int ro=snprintf(rb,sizeof rb,"[MFCWATCH]   ring:");
                uint32_t rn=t->mfc_ring_n;
                for(uint32_t j=rn>=8?rn-8:0; j<rn && ro<(int)sizeof rb-48; j++){
                    uint32_t k2=j&31;
                    ro+=snprintf(rb+ro,sizeof rb-ro," %02x:ea=%x,ls=%x,sz=%x",
                                 t->mfc_ring[k2].op,t->mfc_ring[k2].ea,
                                 t->mfc_ring[k2].lsa,t->mfc_ring[k2].sz);
                }
                fprintf(stderr,"%s\n",rb);
                for(uint32_t j=rn>=8?rn-8:0; j<rn; j++){
                    uint32_t k2=j&31;
                    if(!(t->mfc_ring[k2].op&0x40)) continue;
                    uint32_t gea=t->mfc_ring[k2].ea;
                    if((uint64_t)gea+16>g_mainsz) continue;
                    const uint8_t* s=g_main+gea;
                    fprintf(stderr,"[MFCWATCH]   src %02x@%x= %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
                            t->mfc_ring[k2].op,gea,
                            s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],
                            s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15]);
                }
                { static uint32_t snap_pcs[8]; static volatile long nsnap;
                  uint32_t spc=t->ctx.pc; int seen=0; long ns=nsnap;
                  for(long si=0;si<ns&&si<8;si++) if(snap_pcs[si]==spc) seen=1;
                  if(!seen){ long slot=InterlockedIncrement(&nsnap)-1;
                      if(slot<8){ snap_pcs[slot]=spc;
                          char fn[64]; snprintf(fn,sizeof fn,"mfcw_%05x.bin",spc);
                          FILE* f=fopen(fn,"wb");
                          if(f){ fwrite(t->ls,1,0x40000,f); fclose(f);
                                 fprintf(stderr,"[MFCWATCH]   LS dumped to %s\n",fn); } } } }
            }
        }
    }
    lswatch(t, op, lsa, ea, sz);
    if(get && lsa<=0xa00 && lsa+sz>0xa00 && sz>=0x800){
        static struct { uint32_t ea, sz; uint8_t* snap; } pmcache[16];
        static int npm=0;
        static const uint32_t known_fw[] = { 0x42377002u  , 0x436e8402u  ,
                                             0x4306dc02u  ,   0x4363de02u   };
        const uint8_t* s=g_main+ea;
        uint32_t fw=(uint32_t)s[0]<<24|s[1]<<16|s[2]<<8|s[3];
        int known=0; for(int i=0;i<4;i++) if(fw==known_fw[i]) known=1;
        EnterCriticalSection(&g_pm_lock);
        int slot=-1;
        for(int i=0;i<npm;i++) if(pmcache[i].ea==ea && pmcache[i].sz==sz){ slot=i; break; }
        if(slot<0 && known && npm<16){
            uint8_t* snap=(uint8_t*)malloc(sz);
            if(snap){
                memcpy(snap,s,sz);
                pmcache[npm].ea=ea; pmcache[npm].sz=sz; pmcache[npm].snap=snap;
                npm++;
                fprintf(stderr,"[SPU-PM] snapshot ea=0x%x sz=0x%x fw=%08x\n",ea,sz,fw);
            }
        } else if(slot>=0 && memcmp(pmcache[slot].snap,s,sz)!=0){
            uint32_t d=0; while(d<sz && pmcache[slot].snap[d]==s[d]) d++;
            fprintf(stderr,"[SPU-PM] RESTORE ea=0x%x sz=0x%x first_diff=+0x%x cur_fw=%08x\n",
                    ea,sz,d,fw);
            memcpy(g_main+ea,pmcache[slot].snap,sz);
        }
        LeaveCriticalSection(&g_pm_lock);
        { static int lg=0; if(lg++<64)
          fprintf(stderr,"[SPU-DMA-A00] %lu get ls=0x%x ea=0x%x sz=0x%x src@a00=%02x%02x%02x%02x\n",
                (unsigned long)GetTickCount(),lsa,ea,sz,s[0xa00-lsa],s[0xa00-lsa+1],s[0xa00-lsa+2],s[0xa00-lsa+3]); }
    }
    if(ea>=0xc06a80 && ea<0xc14a10){
        static int logged=0;
        if(logged++<16) fprintf(stderr,"[SPU-DMA] %s ls=0x%x ea=0x%x sz=0x%x (c06a80 range)\n",
                                get?"get":"put",lsa,ea,sz);
    }
    { static int pw=-2;
      if(pw==-2){ pw = getenv("PS3_SPU_POSTWATCH") ? 0 : -1; }
      if(pw>=0 && pw<48 && ea+sz>0x30400280u && ea<0x306DA480u){
          const uint8_t* d = get ? g_main+ea : t->ls+lsa;
          fprintf(stderr,"[SPU-POST] %s ls=0x%x ea=0x%x sz=0x%x data=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                  get?"get":"PUT",lsa,ea,sz,d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7]);
          pw++;
      } }
    PTRC(t->slot, PT_DMA, ea, sz);
    if(get){ spu_poll_read(t, ea, sz); dma_read_hook(ea, sz);
             tbl_get(t,"GET",ea,sz);
             memcpy(t->ls + lsa, g_main + ea, sz); }
    else{
        spu_poll_work(t);
        tbl_put(t,"PUT",ea,sz,t->ls+lsa);
        if(!mfc_drop(ea,sz))
        memcpy(g_main + ea, t->ls + lsa, sz);
        if(sz <= 2048)
            for(uint32_t l = ea & ~127u; l < ea + sz; l += 128) lockline_wake(l);
    }
    if(get && ((lsa>=0x900 && lsa<0x3000) || (lsa>=0x4000 && lsa<0x8000))){
        static int logged=0;
        if(logged++<256) fprintf(stderr,"[SPU-DMA] get ls=0x%x ea=0x%x sz=0x%x\n",lsa,ea,sz);
    }
    t->mfc_size = 0;
}

static int (*g_intr_hook)(SpuThread*, uint32_t intr, uint32_t data1) = 0;
void spu_set_intr_hook(int (*h)(SpuThread*, uint32_t, uint32_t)){ g_intr_hook = h; }

uint32_t spu_rdch(SPUContext* c, uint32_t ch){
    SpuThread* t = self(c);
    switch(ch){
        case CH_SPU_RdInMbox: {
            spu_poll_work(t);
            EnterCriticalSection(&t->lock);
            while(t->in_n==0) SleepConditionVariableCS(&t->cv,&t->lock,50);
            uint32_t v=t->in_mbox[0];
            for(int i=1;i<t->in_n;i++) t->in_mbox[i-1]=t->in_mbox[i];
            t->in_n--; LeaveCriticalSection(&t->lock); return v;
        }
        case CH_RdSigNotify1: { EnterCriticalSection(&t->lock); uint32_t v=t->sig1; t->sig1=0; LeaveCriticalSection(&t->lock); if(v) spu_poll_work(t); return v; }
        case CH_RdSigNotify2: { EnterCriticalSection(&t->lock); uint32_t v=t->sig2; t->sig2=0; LeaveCriticalSection(&t->lock); if(v) spu_poll_work(t); return v; }
        case CH_MFC_RdTagStat:
            return 0xffffffffu & ~(t->lstall.active ? (1u<<t->lstall.tag) : 0u);
        case CH_MFC_RdListStallStat: { uint32_t v=t->stall_stat; t->stall_stat=0; return v; }
        case CH_MFC_RdAtomicStat: { uint32_t v=t->atomic_stat; t->atomic_stat=0; return v; }
        case CH_RdDec: {
            LARGE_INTEGER now, fq;
            QueryPerformanceCounter(&now); QueryPerformanceFrequency(&fq);
            uint64_t base = t->dec_qpc ? t->dec_qpc : (t->dec_qpc = (uint64_t)now.QuadPart);
            uint64_t ticks = (uint64_t)((now.QuadPart - (int64_t)base) * 79800000.0
                                        / (double)fq.QuadPart);
            return c->dec - (uint32_t)ticks;
        }
        case CH_RdEventStat: return t->event_stat & t->event_mask;
        case CH_RdMachStat: return 1;
        case CH_RdSRR0: return c->srr0;
        default: return 0;
    }
}

static uint32_t rchcnt_now(SpuThread* t, uint32_t ch){
    switch(ch){
        case CH_SPU_RdInMbox: return (uint32_t)t->in_n;
        case CH_SPU_WrOutMbox: return (uint32_t)(4 - t->out_n);
        case CH_SPU_WrOutIntrMbox: return (uint32_t)(1 - t->out_intr_n);
        case CH_MFC_Cmd: return 16;
        case CH_MFC_RdTagStat: return 1;
        case CH_MFC_RdListStallStat: return t->stall_stat?1:0;
        case CH_RdSigNotify1: return t->sig1?1:0;
        case CH_RdSigNotify2: return t->sig2?1:0;
        case CH_RdEventStat: return (t->event_stat & t->event_mask) ? 1 : 0;
        default: return 1;
    }
}

uint32_t spu_rchcnt(SPUContext* c, uint32_t ch){
    SpuThread* t = self(c);
    uint32_t v = rchcnt_now(t, ch);
    static int yat=-1, pat;
    if(yat<0){ const char* e=getenv("PS3_SPU_CHYIELD"); yat = e ? atoi(e) : 64;
               e = getenv("PS3_SPU_CHPARK");            pat = e ? atoi(e) : 512; }
    PTRC(t->slot, PT_RCHCNT, ch, v);
    if(yat<=0 || !spd_ch_blocking(ch)) return v;
    uint32_t streak = spd_ch(&t->rc, ch, v);
    if(streak < (uint32_t)yat) return v;
    uint64_t tb=spuprof_now();
    if(pat>0 && streak>=(uint32_t)pat){
        EnterCriticalSection(&t->lock);
        SleepConditionVariableCS(&t->cv, &t->lock, 1);
        LeaveCriticalSection(&t->lock);
    } else SwitchToThread();
    spuprof_blocked(tb);
    v = rchcnt_now(t, ch);
    spd_ch(&t->rc, ch, v);
    return v;
}

void spu_wrch(SPUContext* c, uint32_t ch, uint32_t val){
    SpuThread* t = self(c);
    switch(ch){
        case CH_MFC_LSA:  t->mfc_lsa=val; break;
        case CH_MFC_EAH:  t->mfc_eah=val; break;
        case CH_MFC_EAL:  t->mfc_eal=val; break;
        case CH_MFC_Size: t->mfc_size=val; break;
        case CH_MFC_TagID:t->mfc_tag=val; break;
        case CH_MFC_Cmd:  mfc_do(t, val); break;
        case CH_MFC_WrTagMask: case CH_MFC_WrTagUpdate: break;
        case CH_MFC_WrListStallAck:
            if(t->lstall.active && t->lstall.tag == (val & 31)) mfc_list_run(t);
            break;
        case CH_WrDec: {
            LARGE_INTEGER now; QueryPerformanceCounter(&now);
            t->dec_qpc = (uint64_t)now.QuadPart;
            c->dec = val; break;
        }
        case CH_WrEventMask: t->event_mask=val; break;
        case CH_WrEventAck:  t->event_stat &= ~val; break;
        case CH_WrSRR0:   c->srr0=val; break;
        case CH_SPU_WrOutMbox: {
            spu_poll_work(t);
            EnterCriticalSection(&t->lock);
            if(t->out_n<4) t->out_mbox[t->out_n++]=val;
            WakeAllConditionVariable(&t->cv); LeaveCriticalSection(&t->lock); break;
        }
        case CH_SPU_WrOutIntrMbox: {
            spu_poll_work(t);
            if(g_intr_hook){
                uint32_t data1=0; int have=0;
                EnterCriticalSection(&t->lock);
                if(t->out_n>0){ data1=t->out_mbox[0];
                    for(int i=1;i<t->out_n;i++) t->out_mbox[i-1]=t->out_mbox[i];
                    t->out_n--; have=1; }
                LeaveCriticalSection(&t->lock);
                if(g_intr_hook(t, val, have?data1:0)) break;
            }
            EnterCriticalSection(&t->lock);
            if(t->out_intr_n<1) t->out_intr[t->out_intr_n++]=val;
            WakeAllConditionVariable(&t->cv); LeaveCriticalSection(&t->lock); break;
        }
        default: break;
    }
}

void spu_stop(SPUContext* c, uint32_t code){
    SpuThread* t = self(c);
    fprintf(stderr,"[SPU-STOP] %lu t=%p pc=0x%x code=0x%x r0=0x%x r3=0x%x bias=0x%x res4c00=%02x%02x%02x%02x\n",
            (unsigned long)GetTickCount(), (void*)t, c->pc, code,
            c->r[0].w[0], c->r[3].w[0], (uint32_t)c->pc_bias,
            c->ls[0x4c00], c->ls[0x4c01], c->ls[0x4c02], c->ls[0x4c03]);
    t->stop_code = code; t->running = 0;
    EnterCriticalSection(&t->lock); WakeAllConditionVariable(&t->cv); LeaveCriticalSection(&t->lock);
}
void spu_unimpl(const char* m, uint32_t pc){ fprintf(stderr,"[SPU unimpl %s @0x%x]\n", m, pc); }

void spu_push_inmbox(SpuThread* t, uint32_t v){
    EnterCriticalSection(&t->lock);
    if(t->in_n<4) t->in_mbox[t->in_n++]=v;
    WakeAllConditionVariable(&t->cv); LeaveCriticalSection(&t->lock);
}
int spu_pop_outmbox(SpuThread* t, uint32_t* out){
    EnterCriticalSection(&t->lock);
    int ok = t->out_n>0;
    if(ok){ *out=t->out_mbox[0]; for(int i=1;i<t->out_n;i++) t->out_mbox[i-1]=t->out_mbox[i]; t->out_n--;
            WakeAllConditionVariable(&t->cv); }
    LeaveCriticalSection(&t->lock); return ok;
}
void spu_signal(SpuThread* t, int which, uint32_t v){
    EnterCriticalSection(&t->lock);
    if(which==2) t->sig2|=v; else t->sig1|=v;
    WakeAllConditionVariable(&t->cv); LeaveCriticalSection(&t->lock);
}

static SpuBodyFn (*g_resolver)(uint32_t pc, const uint8_t* ls) = 0;
void spu_set_resolver(SpuBodyFn (*r)(uint32_t, const uint8_t*)){ g_resolver = r; }

#define SPUP_MAX 128
static struct { void* fn; volatile LONG64 ticks, calls; } g_spup[SPUP_MAX];
static volatile LONG g_spup_n;
static volatile LONG64 g_spup_res_ticks, g_spup_res_calls;
static volatile LONG64 g_spup_wait_ticks, g_spup_wait_calls;
static volatile LONG64 g_spup_lock_ticks, g_spup_lock_calls;
static int g_spup_on = -1;
static double g_spup_freq;
static volatile LONG64 g_spup_w0;
static volatile LONG g_spup_force;
static int g_spup_print;
static void spuprof_init(void){
    if(g_spup_on>=0) return;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    g_spup_freq=(double)f.QuadPart;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    InterlockedCompareExchange64(&g_spup_w0,q.QuadPart,0);
    g_spup_print=getenv("PS3_SPUPROF")?1:0;
    g_spup_on=(g_spup_print||g_spup_force)?1:0;
}
static uint64_t spuprof_now(void){
    if(g_spup_on<=0) return 0;
    LARGE_INTEGER q; QueryPerformanceCounter(&q); return (uint64_t)q.QuadPart;
}
static void spuprof_bump(void* fn, uint64_t t0){
    if(g_spup_on<=0||!t0) return;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    LONG64 dt=(LONG64)((uint64_t)q.QuadPart-t0);
    LONG n=g_spup_n;
    for(LONG i=0;i<n;i++) if(g_spup[i].fn==fn){
        InterlockedExchangeAdd64(&g_spup[i].ticks,dt);
        InterlockedIncrement64(&g_spup[i].calls); return; }
    LONG slot=InterlockedIncrement(&g_spup_n)-1;
    if(slot>=SPUP_MAX){ g_spup_n=SPUP_MAX; return; }
    g_spup[slot].fn=fn;
    InterlockedExchangeAdd64(&g_spup[slot].ticks,dt);
    InterlockedIncrement64(&g_spup[slot].calls);
}
static void spuprof_add(SpuBodyFn fn, uint64_t t0){ spuprof_bump((void*)fn,t0); }
static void spuprof_resolve(uint64_t t0){
    if(g_spup_on<=0||!t0) return;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    InterlockedExchangeAdd64(&g_spup_res_ticks,(LONG64)((uint64_t)q.QuadPart-t0));
    InterlockedIncrement64(&g_spup_res_calls);
}
static void spuprof_blocked(uint64_t t0){
    if(g_spup_on<=0||!t0) return;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    InterlockedExchangeAdd64(&g_spup_wait_ticks,(LONG64)((uint64_t)q.QuadPart-t0));
    InterlockedIncrement64(&g_spup_wait_calls);
}
static void spuprof_lock(uint64_t t0){
    if(g_spup_on<=0||!t0) return;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    InterlockedExchangeAdd64(&g_spup_lock_ticks,(LONG64)((uint64_t)q.QuadPart-t0));
    InterlockedIncrement64(&g_spup_lock_calls);
}
static void spuprof_name(void* fn, char* out, size_t cap){
    if(fn==(void*)spu_interp){ snprintf(out,cap,"INTERP"); return; }
    for(unsigned i=0;i<g_spu_njob_guest;i++)
        if((void*)g_spu_job_guest[i].fn==fn){
            snprintf(out,cap,"job_%06x",g_spu_job_guest[i].ea); return; }
    for(unsigned i=0;i<g_spu_nbodies;i++)
        if((void*)g_spu_bodies[i].fn==fn){
            snprintf(out,cap,"body%u@%05x",i,g_spu_bodies[i].entry); return; }
    snprintf(out,cap,"fn_%p",fn);
}
static char g_spup_nm[SPUP_MAX][32];
static void* g_spup_nmfn[SPUP_MAX];

void spu_mtrace_enable(int on){
    if(on){
        if(g_spup_freq<=0.0){ LARGE_INTEGER f; QueryPerformanceFrequency(&f);
                              g_spup_freq=(double)f.QuadPart; }
        InterlockedExchange(&g_spup_force,1);
        g_spup_on=1;
    } else {
        InterlockedExchange(&g_spup_force,0);
        g_spup_on=g_spup_print?1:0;
    }
}

int spu_mtrace_drain(const char** name, uint32_t* calls, uint32_t* us, int max,
                     uint32_t* wait_us, uint32_t* lock_us, uint32_t* resolve_us){
    double tk2us = g_spup_freq>0.0 ? 1000000.0/g_spup_freq : 0.0;
    LONG n=g_spup_n; if(n>SPUP_MAX) n=SPUP_MAX;
    int out=0;
    for(LONG i=0;i<n && out<max;i++){
        LONG64 tk=InterlockedExchange64(&g_spup[i].ticks,0);
        LONG64 ca=InterlockedExchange64(&g_spup[i].calls,0);
        if(!tk && !ca) continue;
        void* fn=g_spup[i].fn;
        if(g_spup_nmfn[i]!=fn){ g_spup_nmfn[i]=fn;
                                spuprof_name(fn,g_spup_nm[i],sizeof g_spup_nm[i]); }
        name[out]=g_spup_nm[i];
        calls[out]=(uint32_t)ca;
        us[out]=(uint32_t)((double)tk*tk2us);
        out++;
    }
    LONG64 w=InterlockedExchange64(&g_spup_wait_ticks,0);
    LONG64 l=InterlockedExchange64(&g_spup_lock_ticks,0);
    LONG64 r=InterlockedExchange64(&g_spup_res_ticks,0);
    InterlockedExchange64(&g_spup_wait_calls,0);
    InterlockedExchange64(&g_spup_lock_calls,0);
    InterlockedExchange64(&g_spup_res_calls,0);
    if(wait_us)    *wait_us   =(uint32_t)((double)w*tk2us);
    if(lock_us)    *lock_us   =(uint32_t)((double)l*tk2us);
    if(resolve_us) *resolve_us=(uint32_t)((double)r*tk2us);
    return out;
}

static void spuprof_tick(void){
    if(g_spup_on<=0||!g_spup_print) return;
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    LONG64 w0=g_spup_w0;
    double secs=(double)((uint64_t)q.QuadPart-(uint64_t)w0)/g_spup_freq;
    if(secs<5.0) return;
    if(InterlockedCompareExchange64(&g_spup_w0,q.QuadPart,w0)!=w0) return;
    struct { void* fn; LONG64 ms, calls; } row[SPUP_MAX]; int nr=0;
    LONG n=g_spup_n; if(n>SPUP_MAX) n=SPUP_MAX;
    double tot=0;
    for(LONG i=0;i<n;i++){
        LONG64 tk=InterlockedExchange64(&g_spup[i].ticks,0);
        LONG64 ca=InterlockedExchange64(&g_spup[i].calls,0);
        double ms=(double)tk/g_spup_freq*1000.0/secs;
        tot+=ms;
        if(ms<0.5) continue;
        row[nr].fn=g_spup[i].fn; row[nr].ms=(LONG64)ms;
        row[nr].calls=(LONG64)(ca/secs); nr++;
    }
    LONG64 rtk=InterlockedExchange64(&g_spup_res_ticks,0);
    LONG64 rca=InterlockedExchange64(&g_spup_res_calls,0);
    double rms=(double)rtk/g_spup_freq*1000.0/secs;
    LONG64 wtk=InterlockedExchange64(&g_spup_wait_ticks,0);
    LONG64 wca=InterlockedExchange64(&g_spup_wait_calls,0);
    double wms=(double)wtk/g_spup_freq*1000.0/secs;
    for(int i=0;i<nr;i++) for(int k=i+1;k<nr;k++)
        if(row[k].ms>row[i].ms){ __typeof__(row[0]) tmp=row[i]; row[i]=row[k]; row[k]=tmp; }
    LONG64 ltk=InterlockedExchange64(&g_spup_lock_ticks,0);
    LONG64 lca=InterlockedExchange64(&g_spup_lock_calls,0);
    double lms=(double)ltk/g_spup_freq*1000.0/secs;
    char line[1024]; int o=snprintf(line,sizeof line,
        "[SPUPROF] busy=%.0f wait=%.0f lock=%.0f(%lld/s) cpu=%.0fms/s resolve=%.0fms/s(%lld/s)",
        tot,wms,lms,(long long)(lca/secs),tot-wms-lms,rms,(long long)(rca/secs));
    for(int i=0;i<nr&&i<10&&o<(int)sizeof line-48;i++){
        char nm[32]; spuprof_name(row[i].fn,nm,sizeof nm);
        o+=snprintf(line+o,sizeof line-o," %s=%lld(%lld/s)",
                    nm,(long long)row[i].ms,(long long)row[i].calls);
    }
    fprintf(stderr,"%s\n",line);
}

volatile DWORD spu_trace_until = 0;
static volatile long g_jqt_n = 0;

static uint32_t g_spindump_pc, g_spindump_cnt;
static volatile long g_spindump_fired;
static void spin_dump(SpuThread* t);

static void spu_thread_prio(void){
    static int prio = -99;
    if(prio == -99){
        const char* e = getenv("PS3_SPU_PRIO");
        prio = e ? atoi(e) : THREAD_PRIORITY_BELOW_NORMAL;
    }
    if(prio) SetThreadPriority(GetCurrentThread(), prio);
}
static DWORD WINAPI spu_thread_main(LPVOID p){
    SpuThread* t = (SpuThread*)p;
    t->running = 1;
    spu_thread_prio();
    spuprof_init();
    SpuBodyFn fn = t->run;
    static uint32_t tr_lo, tr_hi; static int tr_init;
    if(!tr_init){ tr_init=1; const char* e=getenv("PS3_SPUTRANS");
        if(e){ unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b); tr_lo=a; tr_hi=b;
               fprintf(stderr,"[SPUTRANS] armed [0x%x,0x%x)\n",a,b); } }
    static int sd_init;
    if(!sd_init){ sd_init=1; const char* e=getenv("PS3_SPINDUMP");
        if(e){ unsigned a=0,b=256; sscanf(e,"%x:%u",&a,&b);
               g_spindump_pc=a; g_spindump_cnt=b?b:256;
               fprintf(stderr,"[SPINDUMP] armed pc=0x%x count=%u\n",a,g_spindump_cnt); } }
    uint32_t spin_n = 0;
    while (fn){
        uint32_t from = t->ctx.pc;
        SpuBodyFn ran = fn;
        uint64_t t_body = spuprof_now();
        fn(&t->ctx);
        spuprof_add(ran, t_body);
        { uint32_t di=t->disp_n&15; t->disp_ring[di].fn=(void*)ran;
          t->disp_ring[di].from=from; t->disp_ring[di].to=t->ctx.pc; t->disp_n++; }
        if(tr_hi>tr_lo && ((from>=tr_lo&&from<tr_hi) || (t->ctx.pc>=tr_lo&&t->ctx.pc<tr_hi)))
            fprintf(stderr,"[SPUTRANS] %lu t=%p 0x%x -> 0x%x lr=0x%x\n",
                    (unsigned long)GetTickCount(),(void*)t,from,t->ctx.pc,t->ctx.r[0].w[0]);
        {
            static int jqt = -1;
            if (jqt < 0) jqt = getenv("PS3_JQTRACE") ? 1 : 0;
            if (jqt && GetTickCount() < spu_trace_until && g_jqt_n < 2000000){
                InterlockedIncrement(&g_jqt_n);
                fprintf(stderr,"[JQT] %lu t=%p %x->%x lr=%x r3=%x_%x r4=%x_%x r5=%x_%x\n",
                        (unsigned long)GetTickCount(),(void*)t,from,t->ctx.pc,
                        t->ctx.r[0].w[0],
                        t->ctx.r[3].w[0],t->ctx.r[3].w[1],
                        t->ctx.r[4].w[0],t->ctx.r[4].w[1],
                        t->ctx.r[5].w[0],t->ctx.r[5].w[1]);
            }
        }
        if (g_spindump_pc && !g_spindump_fired){
            if (from==g_spindump_pc || t->ctx.pc==g_spindump_pc) spin_n++;
            else spin_n = 0;
            if (spin_n>=g_spindump_cnt && !InterlockedExchange(&g_spindump_fired,1))
                spin_dump(t);
        }
        if (!t->running) break;
        static int spudisp = -1;
        if (spudisp < 0) spudisp = getenv("PS3_SPUDISP") ? 1 : 0;
        if (spudisp && t->ctx.pc==0x4c00){
            static volatile long n; long k=InterlockedIncrement(&n);
            if (k<200 || k%200==0)
                fprintf(stderr,"[SPU-DISP] %lu job@0x4c00 (n=%ld)\n",(unsigned long)GetTickCount(),k);
        }
        if (t->ctx.pc == from){
            static volatile long nlk; long k=InterlockedIncrement(&nlk);
            if (k<=16 || k%100000==0)
                fprintf(stderr,"[SPU] LIVELOCK-GUARD pc=0x%x t=%p (n=%ld) - interp step\n",
                        t->ctx.pc,(void*)t,k);
            fn = spu_interp; continue;
        }
        if (t->ctx.pc==0x3050){
            static volatile long ntk; long k=InterlockedIncrement(&ntk);
            if (k<=24) fprintf(stderr,"[TASK-REG] %lu #%ld r3=%08x_%08x r4=%08x_%08x r5=%08x_%08x r6=%08x_%08x\n",
                (unsigned long)GetTickCount(),k,
                t->ctx.r[3].w[0],t->ctx.r[3].w[1], t->ctx.r[4].w[0],t->ctx.r[4].w[1],
                t->ctx.r[5].w[0],t->ctx.r[5].w[1], t->ctx.r[6].w[0],t->ctx.r[6].w[1]);
        }
        { uint64_t t_res=spuprof_now();
          fn = g_resolver ? g_resolver(t->ctx.pc, t->ls) : 0;
          spuprof_resolve(t_res); }
        spuprof_tick();
    }
    t->running = 0;
    return 0;
}

static void spin_dump(SpuThread* t){
    fprintf(stderr,"[SPIN] FIRED %lu t=%p pc=0x%x cnt=%u - regs/mfc/ls/guest dump\n",
            (unsigned long)GetTickCount(),(void*)t,t->ctx.pc,g_spindump_cnt);
    for(int r=0;r<128;r+=4){
        char b[256]; int o=snprintf(b,sizeof b,"[SPIN] r%-3d",r);
        for(int j=0;j<4;j++){ const SpuReg* q=&t->ctx.r[r+j];
            o+=snprintf(b+o,sizeof b-o," %08x_%08x_%08x_%08x",q->w[0],q->w[1],q->w[2],q->w[3]); }
        fprintf(stderr,"%s\n",b);
    }
    fprintf(stderr,"[SPIN] resv ea=0x%x valid=%d atomic_stat=0x%x stall_stat=0x%x "
            "lstall(active=%d tag=%u) tagmask-irrelevant out_n=%d in_n=%d sig1=0x%x sig2=0x%x\n",
            t->resv_ea,t->resv_valid,t->atomic_stat,t->stall_stat,
            t->lstall.active,t->lstall.tag,t->out_n,t->in_n,t->sig1,t->sig2);
    for(int k=0;k<32;k++){ uint32_t i=(t->mfc_ring_n+k)&31;
        fprintf(stderr,"[SPIN] mfc[%02d] op=0x%02x ea=0x%08x sz=0x%x lsa=0x%x\n",
                k,t->mfc_ring[i].op,t->mfc_ring[i].ea,t->mfc_ring[i].sz,t->mfc_ring[i].lsa); }
    { static const int kr[]={0,3,82,83,85,100};
      for(int i=0;i<6;i++){ uint32_t a=t->ctx.r[kr[i]].w[0]&0x3fff0; const uint8_t* q=t->ls+a;
          fprintf(stderr,"[SPIN] ls[r%d=0x%05x] %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                  kr[i],a,q[0],q[1],q[2],q[3],q[4],q[5],q[6],q[7],
                  q[8],q[9],q[10],q[11],q[12],q[13],q[14],q[15]); } }
    { uint32_t eas[40]; int n=0;
      for(int k=0;k<32;k++){ uint32_t e=t->mfc_ring[k].ea&~0x7fu; int dup=0;
          for(int j=0;j<n;j++) if(eas[j]==e) dup=1;
          if(!dup && n<40) eas[n++]=e; }
      { uint32_t extra[2]={ t->resv_ea&~0x7fu, t->ctx.r[3].w[1]&~0x7fu };
        for(int x=0;x<2;x++){ int dup=0;
            for(int j=0;j<n;j++) if(eas[j]==extra[x]) dup=1;
            if(!dup && n<40) eas[n++]=extra[x]; } }
      for(int j=0;j<n;j++){ uint32_t e=eas[j];
          if(!g_main || !e || (uint64_t)e+0x100>g_mainsz) continue;
          for(uint32_t row=0;row<0x100;row+=0x20){
              char h[256]; int o=snprintf(h,sizeof h,"[SPIN] ea 0x%08x:",e+row);
              for(uint32_t k2=0;k2<0x20;k2+=4){ const uint8_t* q=g_main+e+row+k2;
                  o+=snprintf(h+o,sizeof h-o," %02x%02x%02x%02x",q[0],q[1],q[2],q[3]); }
              fprintf(stderr,"%s\n",h); } } }
    for(long i=0;i<g_all_n && i<16;i++){ SpuThread* u=g_all_thr[i];
        char fn[64]; snprintf(fn,sizeof fn,"logs\\spin_ls_t%ld.bin",i);
        FILE* f=fopen(fn,"wb"); if(f){ fwrite(u->ls,1,0x40000,f); fclose(f); }
        fprintf(stderr,"[SPIN] t%ld=%p%s pc=0x%x r0=0x%x r3=%08x_%08x resv=0x%x -> %s\n",
                i,(void*)u,u==t?" (FIRING)":"",u->ctx.pc,u->ctx.r[0].w[0],
                u->ctx.r[3].w[0],u->ctx.r[3].w[1],u->resv_ea,f?fn:"WRITE-FAILED"); }
    fprintf(stderr,"[SPIN] dump complete; game continues\n");
}
static DWORD WINAPI spu_monitor(LPVOID p){
    (void)p;
    static uint32_t sdump_ea; static int sdump_init;
    if(!sdump_init){ sdump_init=1; const char* e=getenv("PS3_SPURSDUMP");
        if(e){ sdump_ea=(uint32_t)strtoul(e,0,16);
               fprintf(stderr,"[SPURSDUMP] armed ea=0x%x\n",sdump_ea); } }
    for(;;){ Sleep(5000);
        char b[512]; int n=snprintf(b,sizeof b,"[SPU-PC]");
        for(long i=0;i<g_all_n;i++){ SpuThread* t=g_all_thr[i];
            n+=snprintf(b+n,sizeof b-n," t%ld=%s0x%x/r3=0x%x/mfc=%u/tok=%d",i,t->running?"":"DEAD:",t->ctx.pc,t->ctx.r[3].w[0],t->mfc_ring_n,t->poll_tokens); }
        fprintf(stderr,"%s\n",b);
        if(sdump_ea && g_main && (uint64_t)sdump_ea+0x180<=g_mainsz){
            for(uint32_t row=0;row<0x180;row+=0x20){
                char h[256]; int o=snprintf(h,sizeof h,"[SPURSDUMP] +%03x:",row);
                for(uint32_t k2=0;k2<0x20;k2+=4){
                    const uint8_t* q=g_main+sdump_ea+row+k2;
                    o+=snprintf(h+o,sizeof h-o," %02x%02x%02x%02x",q[0],q[1],q[2],q[3]);
                }
                fprintf(stderr,"%s\n",h);
            }
        }
        { static uint32_t last[16]; long best=-1; uint32_t bestd=0;
          for(long i=0;i<g_all_n&&i<16;i++){ uint32_t d=g_all_thr[i]->mfc_ring_n-last[i];
              if(d>bestd){ bestd=d; best=i; } last[i]=g_all_thr[i]->mfc_ring_n; }
          if(best>=0 && bestd>1000){ SpuThread* t=g_all_thr[best];
              char m[1024]; int o=snprintf(m,sizeof m,"[SPU-MFC] t%ld d=%u:",best,bestd);
              for(int k=0;k<32 && o<(int)sizeof m-48;k++){
                  const uint32_t idx=(t->mfc_ring_n+k)&31;
                  o+=snprintf(m+o,sizeof m-o," %02x/%x/%x",t->mfc_ring[idx].op,t->mfc_ring[idx].ea,t->mfc_ring[idx].sz); }
              fprintf(stderr,"%s\n",m); } } }
    return 0;
}
int spu_host_tids(unsigned long* out, int cap){
    long n=g_all_n; if(n>16) n=16;
    int m=0;
    for(long i=0;i<n && m<cap;i++){
        SpuThread* t=g_all_thr[i];
        if(t && t->thread) out[m++]=GetThreadId(t->thread);
    }
    return m;
}
int spu_describe_tid(unsigned long tid, char* out, int cap){
    long n=g_all_n; if(n>16) n=16;
    for(long i=0;i<n;i++){
        SpuThread* t=g_all_thr[i];
        if(!t || !t->thread || GetThreadId(t->thread)!=tid) continue;
        int o=snprintf(out,cap,"spu%ld pc=0x%x staged lsa=0x%x ea=0x%x sz=0x%x tag=%u | mfc:",
                       i,t->ctx.pc,t->mfc_lsa,t->mfc_eal,t->mfc_size,t->mfc_tag);
        uint32_t rn=t->mfc_ring_n;
        for(uint32_t j=rn>=6?rn-6:0;j<rn && o<cap-48;j++){ uint32_t k=j&31;
            o+=snprintf(out+o,cap-o," %02x:ea=%x,ls=%x,sz=%x",t->mfc_ring[k].op,
                        t->mfc_ring[k].ea,t->mfc_ring[k].lsa,t->mfc_ring[k].sz); }
        if(t->disp_n && o<cap-64){ uint32_t d=(t->disp_n-1)&15;
            o+=snprintf(out+o,cap-o," | last body %p 0x%x->0x%x",t->disp_ring[d].fn,
                        t->disp_ring[d].from,t->disp_ring[d].to); }
        return 1;
    }
    return 0;
}
SpuThread* spu_thread_alloc(void){
    SpuThread* t = (SpuThread*)calloc(1,sizeof *t);
    t->ls = (uint8_t*)calloc(1,0x40000);
    t->ctx.ls = t->ls; t->ctx.lsmask = SPU_LSMASK; t->ctx.spu = t;
    InitializeCriticalSection(&t->lock); InitializeConditionVariable(&t->cv);
    { long i=InterlockedIncrement(&g_all_n)-1; if(i<16) g_all_thr[i]=t;
      t->slot = (uint32_t)i;
      if(i==0 && getenv("PS3_SPUMON")) CreateThread(0,0,spu_monitor,0,0,0); }
    return t;
}
void spu_thread_write_ls(SpuThread* t, uint32_t lsaddr, const void* src, uint32_t n){
    if(!t || lsaddr+n>0x40000) return;
    if(src) memcpy(t->ls+lsaddr, src, n); else memset(t->ls+lsaddr, 0, n);
}
void spu_thread_set_arg64(SpuThread* t, int reg, uint64_t v){
    if(!t || reg<0 || reg>127) return;
    t->ctx.r[reg].w[0]=(uint32_t)(v>>32); t->ctx.r[reg].w[1]=(uint32_t)v;
}
void spu_thread_start_at(SpuThread* t, void (*run)(SPUContext*), uint32_t entry){
    if(!t) return;
    t->ctx.pc = entry; t->run = run;
    t->thread = CreateThread(0,0,spu_thread_main,t,0,0);
}
int spu_thread_running(SpuThread* t){ return t ? t->running : 0; }
uint32_t spu_thread_stop_code(SpuThread* t){ return t ? t->stop_code : 0; }
uint32_t spu_thread_pc(SpuThread* t){ return t ? t->ctx.pc : 0; }

SpuThread* spu_thread_create(void (*run)(SPUContext*), const uint8_t* image,
                             uint32_t img_lsaddr, uint32_t img_size, uint32_t entry){
    SpuThread* t = spu_thread_alloc();
    if(image && img_lsaddr+img_size<=0x40000) memcpy(t->ls+img_lsaddr, image, img_size);
    spu_thread_start_at(t, run, entry);
    return t;
}
void spu_thread_join(SpuThread* t){ if(t&&t->thread) WaitForSingleObject(t->thread,INFINITE); }
uint8_t* spu_thread_ls(SpuThread* t){ return t?t->ls:0; }

static void spu_statecap(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/spu.txt",dir);
    FILE* f=fopen(p,"wb"); if(!f) return;
    long n=g_all_n; if(n>16) n=16;
    fprintf(f,"%ld SPU worker%s\n\n",n,n==1?"":"s");
    for(long i=0;i<n;i++){
        SpuThread* t=g_all_thr[i]; if(!t) continue;
        fprintf(f,"================ SPU %ld (host tid %lu) ================\n",
                i,t->thread?(unsigned long)GetThreadId(t->thread):0ul);
        fprintf(f,"running=%d pc=0x%05x srr0=0x%05x stop_code=0x%x pc_bias=%d\n",
                t->running,t->ctx.pc,t->ctx.srr0,t->stop_code,t->ctx.pc_bias);
        fprintf(f,"resv: ea=0x%08x valid=%d atomic_stat=0x%x stall_stat=0x%x "
                  "lstall(active=%d op=0x%x tag=%u list_ls=0x%x idx=%u/%u)\n",
                t->resv_ea,t->resv_valid,t->atomic_stat,t->stall_stat,
                t->lstall.active,t->lstall.op,t->lstall.tag,t->lstall.list_ls,
                t->lstall.idx,t->lstall.n);
        fprintf(f,"mbox: out_n=%d in_n=%d intr_n=%d sig1=0x%08x sig2=0x%08x "
                  "event_mask=0x%x event_stat=0x%x\n",
                t->out_n,t->in_n,t->out_intr_n,t->sig1,t->sig2,
                t->event_mask,t->event_stat);
        for(int k=0;k<t->out_n&&k<4;k++)  fprintf(f,"  out_mbox[%d]=0x%08x\n",k,t->out_mbox[k]);
        for(int k=0;k<t->in_n&&k<4;k++)   fprintf(f,"  in_mbox[%d]=0x%08x\n",k,t->in_mbox[k]);
        fprintf(f,"\ndispatch (oldest first):\n");
        for(int k=0;k<16;k++){
            uint32_t j=(t->disp_n+k)&15;
            if(!t->disp_ring[j].fn) continue;
            char nm[48]; spuprof_name(t->disp_ring[j].fn,nm,sizeof nm);
            fprintf(f,"  %-24s 0x%05x -> 0x%05x\n",nm,
                    t->disp_ring[j].from,t->disp_ring[j].to);
        }
        fprintf(f,"\nmfc (oldest first):\n");
        for(int k=0;k<32;k++){
            uint32_t j=(t->mfc_ring_n+k)&31;
            if(!t->mfc_ring[j].op&&!t->mfc_ring[j].ea) continue;
            fprintf(f,"  op=0x%02x ea=0x%08x size=0x%-6x lsa=0x%05x\n",
                    t->mfc_ring[j].op,t->mfc_ring[j].ea,
                    t->mfc_ring[j].sz,t->mfc_ring[j].lsa);
        }
        fprintf(f,"\nregisters (word lanes, preferred slot first):\n");
        for(int r=0;r<128;r+=2){
            fprintf(f,"  r%-3d",r);
            for(int j=0;j<2;j++){ const SpuReg* q=&t->ctx.r[r+j];
                fprintf(f,"  %08x %08x %08x %08x",q->w[0],q->w[1],q->w[2],q->w[3]); }
            fputc('\n',f);
        }
        fputc('\n',f);
        char lp[300]; snprintf(lp,sizeof lp,"%s/spu_ls_%ld.bin",dir,i);
        FILE* lf=fopen(lp,"wb");
        if(lf){ fwrite(t->ls,1,0x40000,lf); fclose(lf); }
    }
    fclose(f);
}
