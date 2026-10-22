#include "ppu_runtime.h"
#include "spu_runtime.h"
#include "rsx.h"
#include "vk_present.h"
#include "hprof.h"
#include "statecap.h"
#include "capture.h"
#include "mtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <io.h>
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <xinput.h>
#include <math.h>
#pragma comment(lib, "xinput9_1_0")
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
#endif

static uint8_t*  g_base = 0;
static uint64_t  g_size = 0;
static uint32_t  g_mempool_block = 64;
static uint32_t  g_heap = 0x1f000000u;
static uint32_t  g_heap_hi;
static CRITICAL_SECTION g_lock;

static __declspec(thread) uint64_t t_gid;
static uint32_t g_curfn_decl_dummy;
int ppc_t7job_log(unsigned fn, unsigned long long arg){
    static int on=-1; if(on<0) on=getenv("PS3_T7JOB")?1:0;
    if(on){ static volatile long n; long k=InterlockedIncrement((volatile long*)&n);
        if(k<=4096||(k%64)==0)
            fprintf(stderr,"[T7JOB] %lu fn=0x%x arg=0x%llx (n=%ld)\n",
                    (unsigned long)GetTickCount(),fn,arg,k); }
    return 0;
}
static volatile long g_u0wp_state;
static unsigned g_u0wp_lo, g_u0wp_hi;
static unsigned g_u0wp_trig;
static LONG WINAPI u0wp_veh(EXCEPTION_POINTERS* ep){
    if(g_u0wp_state!=2 ||
       ep->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION ||
       ep->ExceptionRecord->ExceptionInformation[0]!=1)
        return EXCEPTION_CONTINUE_SEARCH;
    uint8_t* a=(uint8_t*)ep->ExceptionRecord->ExceptionInformation[1];
    if(a<g_base+g_u0wp_lo || a>=g_base+g_u0wp_hi) return EXCEPTION_CONTINUE_SEARCH;
    uint8_t* pg=(uint8_t*)((uintptr_t)a & ~0xfffull);
    DWORD old; VirtualProtect(pg,0x1000,PAGE_READWRITE,&old);
    static volatile long nh; long k=InterlockedIncrement(&nh);
    if(k<=2048){
        uint64_t mbase=(uint64_t)GetModuleHandleA(0);
        fprintf(stderr,"[U0WP] %lu WRITE ea=0x%llx curfn=sub_%x t%llu tid=%lu rip-off=0x%llx (hit %ld)\n",
            (unsigned long)GetTickCount(),(unsigned long long)(a-g_base),g_curfn,
            (unsigned long long)t_gid,GetCurrentThreadId(),
            (unsigned long long)(ep->ContextRecord->Rip-mbase),k);
        if(k<=16){
            uint64_t* sp=(uint64_t*)ep->ContextRecord->Rsp; int printed=0;
            fprintf(stderr,"[U0WP] stack-scan:");
            for(int i=0;i<1024 && printed<8;i++){
                uint64_t v; if(IsBadReadPtr(sp+i,8)) break; v=sp[i];
                if(v>mbase+0x1000 && v<mbase+0x10000000){
                    fprintf(stderr," +0x%llx",(unsigned long long)(v-mbase)); printed++; } }
            fprintf(stderr,"\n");
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI c8scan_thread(LPVOID p);
static volatile LONG g_c8_hiwater;
static volatile LONG g_c8_gate_budget = 30000;
int ppc_cpylog(unsigned dst, unsigned src, unsigned len, unsigned long long lr){
    static int on=-1; if(on<0) on=getenv("PS3_CPYLOG")?1:0;
    if (dst>=0x38000000u && dst<0x39000000u){
        LONG end=(LONG)(dst+len), cur;
        while ((cur=g_c8_hiwater), (uint32_t)cur<(uint32_t)end){
            if (InterlockedCompareExchange(&g_c8_hiwater,end,cur)==cur) break;
        }
    }
    if(on && dst>=0x1fc00000u && dst<0x2f500000u){
        static volatile long n; long k=InterlockedIncrement((volatile long*)&n);
        if(k<=262144||(k%256)==0)
            fprintf(stderr,"[CPY] %lu dst=0x%x src=0x%x len=0x%x fn=sub_%x lr=0x%llx t%llu (n=%ld)\n",
                    (unsigned long)GetTickCount(),dst,src,len,g_curfn,lr,
                    (unsigned long long)t_gid,k);
    }
    {
        static unsigned lo=0, hi=0, lo2=0, hi2=0; static int uon=-1;
        if(uon<0){ const char* e=getenv("PS3_CPYU0"); int n;
            uon = (e && (n=sscanf(e,"%x:%x,%x:%x",&lo,&hi,&lo2,&hi2))>=2) ? 1 : 0;
            if(uon && n<4){ lo2=0; hi2=0; } }
        if(uon && ((dst<hi && dst+len>lo) || (dst<hi2 && dst+len>lo2))){
            const uint8_t* s = g_base + src;
            unsigned nb = len>>4, black=0, i;
            for(i=0;i<nb;i++){
                const uint8_t* b = s + ((size_t)i<<4);
                if(*(const uint64_t*)b==0xffffffffffffffffull &&
                   *(const uint64_t*)(b+8)==0) black++;
            }
            fprintf(stderr,"[CPYU0] %lu dst=0x%x src=0x%x len=0x%x black=%u/%u lr=0x%llx t%llu "
                    "src0=%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x "
                    "%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
                    (unsigned long)GetTickCount(),dst,src,len,black,nb,lr,(unsigned long long)t_gid,
                    s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],
                    s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15],
                    s[16],s[17],s[18],s[19],s[20],s[21],s[22],s[23],
                    s[24],s[25],s[26],s[27],s[28],s[29],s[30],s[31]);
        }
    }
    {
        static long c8s=-1;
        if (c8s<0 && InterlockedCompareExchange(&c8s,0,-1)==-1){
            if (getenv("PS3_C8SCAN")){
                CreateThread(0,0,c8scan_thread,0,0,0);
                fprintf(stderr,"[C8SCAN] observer started\n");
            }
        }
    }
    {
        static int won=-1;
        if(won<0){ const char* e=getenv("PS3_U0WP"); unsigned lo,hi,tr;
            if(e && sscanf(e,"%x:%x:%x",&lo,&hi,&tr)==3){
                g_u0wp_lo=(lo+0xfffu)&~0xfffu; g_u0wp_hi=hi&~0xfffu; g_u0wp_trig=tr;
                AddVectoredExceptionHandler(1,u0wp_veh);
                g_u0wp_state=1; won=1;
            } else won=0; }
        if(won==1 && g_u0wp_state==1 && dst>=g_u0wp_trig && dst<g_u0wp_trig+0x8000){
            unsigned np=0, blk=0, ea;
            for(ea=g_u0wp_lo; ea+16<=g_u0wp_hi; ea+=0x1000){
                const uint8_t* b=g_base+ea; np++;
                if(*(const uint64_t*)b==0xffffffffffffffffull &&
                   *(const uint64_t*)(b+8)==0) blk++;
            }
            g_u0wp_state=2;
            DWORD old; VirtualProtect(g_base+g_u0wp_lo,g_u0wp_hi-g_u0wp_lo,PAGE_READONLY,&old);
            fprintf(stderr,"[U0WP] %lu ARMED [0x%x,0x%x) trig-dst=0x%x black-pages=%u/%u\n",
                    (unsigned long)GetTickCount(),g_u0wp_lo,g_u0wp_hi,dst,blk,np);
        }
    }
    return 0;
}
static DWORD WINAPI c8scan_thread(LPVOID p){
    (void)p;
    static const uint8_t sig[12]={0x3f,0x0f,0x8f,0x90,0x3f,0x1b,0x9b,0x9c,
                                  0x3f,0x22,0xa2,0xa3};
    static struct { uint32_t ea; uint8_t last[0x60]; int used; } seen[16];
    for(;;){
        uint64_t hi = g_size < 0x39000000ull ? g_size : 0x39000000ull;
        for (uint64_t ea=0x36000000ull; ea+0x70<=hi; ea+=16){
            if (memcmp(g_base+ea+0x10, sig, 12)) continue;
            int si=-1;
            for (int k2=0;k2<16;k2++) if (seen[k2].used && seen[k2].ea==(uint32_t)ea){ si=k2; break; }
            if (si<0){ for (int k2=0;k2<16;k2++) if (!seen[k2].used){ si=k2; seen[k2].used=1; seen[k2].ea=(uint32_t)ea; memset(seen[k2].last,0xa5,0x60); break; } }
            if (si<0) continue;
            if (memcmp(seen[si].last, g_base+ea, 0x60)){
                memcpy(seen[si].last, g_base+ea, 0x60);
                char hb[0x60*2+16]; int ho=0;
                for (int b2=0;b2<0x60;b2++){ ho+=snprintf(hb+ho,sizeof hb-ho,"%02x",seen[si].last[b2]);
                    if ((b2&15)==15 && b2!=0x5f) hb[ho++]=' '; }
                hb[ho]=0;
                fprintf(stderr,"[C8SCAN] %lu table@0x%llx = %s\n",
                        (unsigned long)GetTickCount(),(unsigned long long)ea,hb);
            }
        }
        Sleep(200);
    }
}
int ppc_t7post_log(unsigned obj, unsigned desc, unsigned long long arg, unsigned long long lr){
    static int on=-1; if(on<0) on=getenv("PS3_T7JOB")?1:0;
    if(on){
        static unsigned pump_desc; static volatile long n;
        long k=InterlockedIncrement((volatile long*)&n);
        if(k==1) pump_desc=desc;
        if(desc==pump_desc){ if(k<=64||(k%16384)==0)
            fprintf(stderr,"[T7POST] %lu obj=0x%x desc=0x%x arg=0x%llx lr=0x%llx PUMP (n=%ld)\n",
                    (unsigned long)GetTickCount(),obj,desc,arg,lr,k); }
        else
            fprintf(stderr,"[T7POST] %lu obj=0x%x desc=0x%x arg=0x%llx lr=0x%llx (n=%ld)\n",
                    (unsigned long)GetTickCount(),obj,desc,arg,lr,k);
    }
    return 0;
}
void ppu_unimpl(const char* what, uint32_t addr){
    static volatile long n; long k=InterlockedIncrement(&n);
    if(k<=64||(k%1048576)==0)
        fprintf(stderr,"[UNIMPL] %s @ 0x%x fn=sub_%x t%llu (n=%ld)\n",
                what, addr, g_curfn,(unsigned long long)t_gid,k);
}
uint64_t ppu_timebase(void){
    LARGE_INTEGER c,f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
    return (uint64_t)((double)c.QuadPart * (79800000.0 / (double)f.QuadPart));
}

static char g_tty_line[1024];
static unsigned g_tty_n;
static void tty_flush(void){
    if(!g_tty_n) return;
    fprintf(stderr,"[TTY] %.*s\n",(int)g_tty_n,g_tty_line);
    g_tty_n=0; fflush(stderr);
}
static void tty_out(const uint8_t* mem, uint32_t buf, uint32_t len){
    for(uint32_t i=0;i<len && (uint64_t)buf+i<g_size;i++){
        char ch=(char)mem[buf+i];
        if(ch=='\r') continue;
        if(ch=='\n' || g_tty_n+1>=sizeof g_tty_line){ tty_flush(); if(ch=='\n') continue; }
        g_tty_line[g_tty_n++]=ch;
    }
    fflush(stderr);
}
static void miss0_dump(void);
static void lookup_miss_dump(uint32_t addr);
void ppu_miss(uint32_t addr){
    static volatile long n; long k=InterlockedIncrement(&n);
    if(k<=40) fprintf(stderr,"[MISS] sub_%x from=sub_%x t%llu\n", addr, g_curfn, (unsigned long long)t_gid);
    if(addr==0 && k<=8) miss0_dump();
}
void ppu_lookup_miss(uint32_t addr){
    static volatile long n; long k=InterlockedIncrement(&n);
    if(k<=60){
        fprintf(stderr,"[LOOKUP-MISS] indirect 0x%x from sub_%x t%llu\n",
                addr, g_curfn, (unsigned long long)t_gid);
        if(k<=12) lookup_miss_dump(addr);
    }
}

#ifdef _WIN32
static LONG WINAPI ppu_seh(EXCEPTION_POINTERS* ep){
    {
        DWORD c = ep->ExceptionRecord->ExceptionCode;
        if (c != EXCEPTION_ACCESS_VIOLATION){
            const char* nm = c==0xC00000FDu ? "STACK_OVERFLOW" :
                             c==0xC000001Du ? "ILLEGAL_INSTRUCTION" :
                             c==0xC0000094u ? "INT_DIVIDE_BY_ZERO" :
                             c==0xC0000096u ? "PRIV_INSTRUCTION" :
                             c==0xC0000374u ? "HEAP_CORRUPTION" :
                             c==0xC0000409u ? "FASTFAIL/STACK_BUFFER_OVERRUN" :
                             c==0x80000003u ? "BREAKPOINT" :
                             c==0xC0000006u ? "IN_PAGE_ERROR" : "?";
            uint64_t mb=(uint64_t)GetModuleHandleA(0);
            fprintf(stderr,"[FAULT] code=0x%08lx (%s) rip=%p rip-off=0x%llx "
                    "curfn=sub_%x tid=%lu\n",(unsigned long)c,nm,
                    (void*)ep->ContextRecord->Rip,
                    (unsigned long long)(ep->ContextRecord->Rip-mb),
                    g_curfn,GetCurrentThreadId());
            fflush(stderr);
        }
    }
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION){
        void* a=(void*)ep->ExceptionRecord->ExceptionInformation[1];
        long long ea=(long long)((uint8_t*)a-g_base);
        uint64_t mbase=(uint64_t)GetModuleHandleA(0);
        fprintf(stderr,"[SEGV] guest_ea=0x%llx (%s) addr=%p acc=%llu rip=%p rip-off=0x%llx curfn=sub_%x tid=%lu\n", ea,
            ea>=0&&(unsigned long long)ea<g_size?"in-range":"OUT-OF-RANGE", a,
            (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
            (void*)ep->ContextRecord->Rip,
            (unsigned long long)(ep->ContextRecord->Rip-mbase), g_curfn, GetCurrentThreadId());
        {
            CONTEXT* c=ep->ContextRecord;
            fprintf(stderr,"[SEGV] rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rbp=%llx rsp=%llx\n"
                           "[SEGV] r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx\n",
                c->Rax,c->Rbx,c->Rcx,c->Rdx,c->Rsi,c->Rdi,c->Rbp,c->Rsp,
                c->R8,c->R9,c->R10,c->R11,c->R12,c->R13,c->R14,c->R15);
        }
        {
            uint64_t* sp=(uint64_t*)ep->ContextRecord->Rsp; int printed=0;
            fprintf(stderr,"[SEGV] stack-scan:");
            for(int i=0;i<4096 && printed<24;i++){
                uint64_t v; if(IsBadReadPtr(sp+i,8)) break; v=sp[i];
                if(v>mbase+0x1000 && v<mbase+0x10000000){ fprintf(stderr," +0x%llx",(unsigned long long)(v-mbase)); printed++; }
            }
            fprintf(stderr,"\n");
        }
        fflush(stderr);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

__declspec(thread) volatile uint32_t g_curfn = 0;
static __declspec(thread) volatile int g_cursc = -1;
static __declspec(thread) const char* volatile g_curhle = 0;
typedef struct { uint64_t id; volatile uint32_t* fn; volatile int* sc; const char* volatile * hle; DWORD htid; } PpuMonRec;
static PpuMonRec g_ppumon[64]; static volatile int g_nppumon=0;
static void ppumon_register(uint64_t id){
    int i=0;
    for(;i<g_nppumon;i++) if(!g_ppumon[i].fn) break;
    if(i>=64) return;
    g_ppumon[i].id=id; g_ppumon[i].htid=GetCurrentThreadId();
    g_ppumon[i].sc=&g_cursc; g_ppumon[i].hle=&g_curhle;
    g_ppumon[i].fn=&g_curfn;
    if(i==g_nppumon) g_nppumon=i+1;
}
static void ppumon_unregister(void){
    DWORD htid=GetCurrentThreadId();
    int n=g_nppumon; if(n>64) n=64;
    for(int i=0;i<n;i++) if(g_ppumon[i].htid==htid){
        g_ppumon[i].fn=0;
        g_ppumon[i].sc=0; g_ppumon[i].hle=0; g_ppumon[i].htid=0;
    }
}
static DWORD WINAPI ppu_monitor(LPVOID p){
    (void)p;
    for(;;){ Sleep(5000);
        fprintf(stderr,"[PPU-PC]");
        for(int i=0;i<g_nppumon;i++){
            if(!g_ppumon[i].fn) continue;
            fprintf(stderr," t%llu=sub_%x",(unsigned long long)g_ppumon[i].id,*g_ppumon[i].fn);
            int sc=*g_ppumon[i].sc; const char* h=*g_ppumon[i].hle;
            if(sc>=0) fprintf(stderr,"/sc%d",sc);
            if(h) fprintf(stderr,"/%s",h);
        }
        fprintf(stderr,"\n");
    }
}
static DWORD WINAPI ppu_prof(LPVOID p){
    (void)p;
    enum{PCAP=512,TCAP=64};
    static uint32_t pf[TCAP][PCAP]; static uint32_t pc[TCAP][PCAP];
    static int pn[TCAP]; static uint32_t tot[TCAP];
    DWORD last=GetTickCount();
    for(;;){
        Sleep(1);
        int nt=g_nppumon; if(nt>TCAP) nt=TCAP;
        for(int i=0;i<nt;i++){
            if(!g_ppumon[i].fn) continue;
            uint32_t fn=*g_ppumon[i].fn; if(!fn) continue;
            int j=-1; for(int k2=0;k2<pn[i];k2++) if(pf[i][k2]==fn){ j=k2; break; }
            if(j<0 && pn[i]<PCAP){ j=pn[i]; pf[i][j]=fn; pc[i][j]=0; pn[i]++; }
            if(j>=0){ pc[i][j]++; tot[i]++; }
        }
        DWORD now=GetTickCount();
        if(now-last>10000){
            last=now;
            for(int i=0;i<nt;i++){
                if(!tot[i]) continue;
                fprintf(stderr,"[PROF] t%llu n=%u:",(unsigned long long)g_ppumon[i].id,tot[i]);
                for(int pass=0;pass<8;pass++){
                    uint32_t best=0; int bi=-1;
                    for(int k2=0;k2<pn[i];k2++) if(pc[i][k2]>best){ best=pc[i][k2]; bi=k2; }
                    if(bi<0) break;
                    fprintf(stderr," sub_%x=%.1f%%",pf[i][bi],100.0*pc[i][bi]/tot[i]);
                    pc[i][bi]=0;
                }
                fprintf(stderr,"\n");
            }
            for(int i=0;i<nt;i++){ for(int k2=0;k2<pn[i];k2++) pc[i][k2]=0; pn[i]=0; tot[i]=0; }
        }
    }
}
static int g_scprof = -1;
static int g_evfprof = -1;
enum{SCP_NSC=1024, SCP_HCAP=512, SCP_NT=64};
static volatile LONG64 g_scp_cnt[SCP_NSC], g_scp_tk[SCP_NSC];
static volatile LONG64 g_scp_ttk[SCP_NT][SCP_NSC];
static volatile LONG64 g_scp_tct[SCP_NT][SCP_NSC];
static const char* volatile g_scph_name[SCP_HCAP];
static volatile LONG64 g_scph_cnt[SCP_HCAP], g_scph_tk[SCP_HCAP];
static volatile LONG g_scph_n;
static void scprof_hle_add(const char* name, LONG64 dt){
    LONG n=g_scph_n; if(n>SCP_HCAP) n=SCP_HCAP;
    for(LONG i=0;i<n;i++) if(g_scph_name[i]==name){
        InterlockedIncrement64(&g_scph_cnt[i]); InterlockedExchangeAdd64(&g_scph_tk[i],dt); return; }
    LONG i=InterlockedIncrement(&g_scph_n)-1;
    if(i<SCP_HCAP){ g_scph_name[i]=name;
        InterlockedIncrement64(&g_scph_cnt[i]); InterlockedExchangeAdd64(&g_scph_tk[i],dt); }
}
static double scprof_tk2us(void){
    static double v;
    if(v<=0.0){ LARGE_INTEGER f; QueryPerformanceFrequency(&f);
                v=1000000.0/(double)f.QuadPart; }
    return v;
}
static int ppu_mtrace_ppu(MtrcPpuRow* out, int max, const char** hle){
    int n=g_nppumon; if(n>64) n=64;
    int o=0;
    for(int i=0;i<n && o<max;i++){
        if(!g_ppumon[i].fn) continue;
        out[o].tid    =(uint32_t)g_ppumon[i].id;
        out[o].htid   =(uint32_t)g_ppumon[i].htid;
        out[o].curfn  =*g_ppumon[i].fn;
        out[o].sc     =g_ppumon[i].sc?*g_ppumon[i].sc:-1;
        out[o].str_hle=0;
        hle[o]        =g_ppumon[i].hle?*g_ppumon[i].hle:0;
        o++;
    }
    return o;
}
static int ppu_mtrace_hle(const char** name, uint32_t* calls, uint32_t* us, int max){
    double k=scprof_tk2us();
    LONG n=g_scph_n; if(n>SCP_HCAP) n=SCP_HCAP;
    int o=0;
    for(LONG i=0;i<n && o<max;i++){
        if(!g_scph_cnt[i] && !g_scph_tk[i]) continue;
        LONG64 c=InterlockedExchange64(&g_scph_cnt[i],0);
        LONG64 t=InterlockedExchange64(&g_scph_tk[i],0);
        name[o]=g_scph_name[i]; calls[o]=(uint32_t)c;
        us[o]=(uint32_t)((double)t*k); o++;
    }
    return o;
}
static int ppu_mtrace_sc(MtrcScRow* out, int max){
    double k=scprof_tk2us();
    int o=0;
    for(int i=0;i<SCP_NSC && o<max;i++){
        if(!g_scp_cnt[i] && !g_scp_tk[i]) continue;
        LONG64 c=InterlockedExchange64(&g_scp_cnt[i],0);
        LONG64 t=InterlockedExchange64(&g_scp_tk[i],0);
        out[o].num=(uint32_t)i; out[o].calls=(uint32_t)c;
        out[o].us=(uint32_t)((double)t*k); o++;
    }
    return o;
}
static void ppu_mtrace_enable(int on){
    g_scprof = on ? 1 : (getenv("PS3_SCPROF")?1:0);
    spu_mtrace_enable(on);
}
static void ppu_mtrace_register(void){
    static const MtrcProviders mp = {
        ppu_mtrace_ppu, ppu_mtrace_hle, ppu_mtrace_sc,
        spu_mtrace_drain, ppu_mtrace_enable };
    mtrc_set_providers(&mp);
}

static DWORD WINAPI scprof_dump(LPVOID p){
    (void)p;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    double tk2ms = 1000.0/(double)f.QuadPart;
    for(;;){ Sleep(5000);
        static LONG64 c[SCP_NSC], t[SCP_NSC];
        for(int i=0;i<SCP_NSC;i++){ c[i]=InterlockedExchange64(&g_scp_cnt[i],0); t[i]=InterlockedExchange64(&g_scp_tk[i],0); }
        fprintf(stderr,"[SCPROF] sc:");
        for(int pass=0;pass<12;pass++){
            LONG64 best=0; int bi=-1;
            for(int i=0;i<SCP_NSC;i++) if(t[i]>best){ best=t[i]; bi=i; }
            if(bi<0) break;
            fprintf(stderr," %d:%lld/%.1fms",bi,(long long)c[bi],t[bi]*tk2ms); t[bi]=0;
        }
        fprintf(stderr,"\n");
        LONG hn=g_scph_n; if(hn>SCP_HCAP) hn=SCP_HCAP;
        static LONG64 hc[SCP_HCAP], ht[SCP_HCAP];
        for(LONG i=0;i<hn;i++){ hc[i]=InterlockedExchange64(&g_scph_cnt[i],0); ht[i]=InterlockedExchange64(&g_scph_tk[i],0); }
        fprintf(stderr,"[SCPROF] hle:");
        for(int pass=0;pass<12;pass++){
            LONG64 best=0; LONG bi=-1;
            for(LONG i=0;i<hn;i++) if(ht[i]>best){ best=ht[i]; bi=i; }
            if(bi<0) break;
            fprintf(stderr," %s:%lld/%.1fms",g_scph_name[bi],(long long)hc[bi],ht[bi]*tk2ms); ht[bi]=0;
        }
        fprintf(stderr,"\n");
        for(int t2=0;t2<SCP_NT;t2++){
            static LONG64 tt[SCP_NSC], tc2[SCP_NSC]; LONG64 sum=0;
            for(int i=0;i<SCP_NSC;i++){ tt[i]=InterlockedExchange64(&g_scp_ttk[t2][i],0); tc2[i]=InterlockedExchange64(&g_scp_tct[t2][i],0); sum+=tt[i]; }
            if(sum*tk2ms < 50.0) continue;
            fprintf(stderr,"[SCPROF] t%d sc-total=%.0fms:",t2,sum*tk2ms);
            for(int pass=0;pass<4;pass++){
                LONG64 best=0; int bi=-1;
                for(int i=0;i<SCP_NSC;i++) if(tt[i]>best){ best=tt[i]; bi=i; }
                if(bi<0) break;
                fprintf(stderr," %d:%lld/%.0fms",bi,(long long)tc2[bi],tt[bi]*tk2ms); tt[bi]=0;
            }
            fprintf(stderr,"\n");
        }
    }
}
static DWORD g_fifo_htid;
extern int spu_host_tids(unsigned long* out, int cap);
static void cpuprof_label(DWORD tid, char* out, size_t cap){
    for(int i=0;i<g_nppumon;i++) if(g_ppumon[i].fn&&g_ppumon[i].htid==tid){ snprintf(out,cap,"ppu%llu",(unsigned long long)g_ppumon[i].id); return; }
    unsigned long stid[16]; int ns=spu_host_tids(stid,16);
    for(int i=0;i<ns;i++) if(stid[i]==tid){ snprintf(out,cap,"spu%d",i); return; }
    if(tid==g_fifo_htid){ snprintf(out,cap,"fifo"); return; }
    snprintf(out,cap,"h%lu",(unsigned long)tid);
}
static DWORD g_audio_htid, g_cripump_htid;
static int hprof_label(unsigned long tid, char* out, unsigned cap){
    for(int i=0;i<g_nppumon;i++) if(g_ppumon[i].fn&&g_ppumon[i].htid==tid){
        snprintf(out,cap,"ppu%llu",(unsigned long long)g_ppumon[i].id); return 1; }
    unsigned long stid[16]; int ns=spu_host_tids(stid,16);
    for(int i=0;i<ns;i++) if(stid[i]==tid){ snprintf(out,cap,"spu%d",i); return 1; }
    if(tid==g_fifo_htid && tid){ snprintf(out,cap,"fifo"); return 1; }
    if(tid==g_audio_htid && tid){ snprintf(out,cap,"audio"); return 1; }
    if(tid==g_cripump_htid && tid){ snprintf(out,cap,"cripump"); return 1; }
    return 0;
}
static DWORD WINAPI cpuprof_dump(LPVOID p){
    (void)p;
    enum{TC=256};
    static DWORD tid[TC]; static ULONGLONG lastt[TC]; static int nt;
    DWORD pid=GetCurrentProcessId(); DWORD self=GetCurrentThreadId();
    ULONGLONG lastwall=GetTickCount64();
    for(;;){ Sleep(5000);
        ULONGLONG now=GetTickCount64(); double wall=(double)(now-lastwall); lastwall=now;
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        if(snap==INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te; te.dwSize=sizeof te;
        char line[1024]; int o=snprintf(line,sizeof line,"[CPUPROF]");
        double total=0;
        typedef struct { DWORD t; double pc; } CpuRow;
        CpuRow cur[TC]; int nc=0;
        if(Thread32First(snap,&te)) do {
            if(te.th32OwnerProcessID!=pid || te.th32ThreadID==self) continue;
            HANDLE h=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,te.th32ThreadID);
            if(!h) continue;
            FILETIME cr,ex,kt,ut;
            if(GetThreadTimes(h,&cr,&ex,&kt,&ut)){
                ULONGLONG t100=((ULONGLONG)kt.dwHighDateTime<<32|kt.dwLowDateTime)
                              +((ULONGLONG)ut.dwHighDateTime<<32|ut.dwLowDateTime);
                int j=-1; for(int i=0;i<nt;i++) if(tid[i]==te.th32ThreadID){ j=i; break; }
                if(j<0 && nt<TC){ j=nt; tid[j]=te.th32ThreadID; lastt[j]=t100; nt++; }
                else if(j>=0){
                    double ms=(double)(t100-lastt[j])/10000.0; lastt[j]=t100;
                    double pc=100.0*ms/wall; total+=pc;
                    if(pc>2.0 && nc<TC){ cur[nc].t=te.th32ThreadID; cur[nc].pc=pc; nc++; }
                }
            }
            CloseHandle(h);
        } while(Thread32Next(snap,&te));
        CloseHandle(snap);
        for(int i=0;i<nc;i++) for(int k=i+1;k<nc;k++) if(cur[k].pc>cur[i].pc){ CpuRow tmp=cur[i]; cur[i]=cur[k]; cur[k]=tmp; }
        o+=snprintf(line+o,sizeof line-o," total=%.0f%%",total);
        for(int i=0;i<nc && o<(int)sizeof line-32;i++){
            char nm[24]; cpuprof_label(cur[i].t,nm,sizeof nm);
            o+=snprintf(line+o,sizeof line-o," %s=%.0f%%",nm,cur[i].pc);
        }
        fprintf(stderr,"%s\n",line);
    }
}
void ppu_dbg_bctr(PPUContext* ctx, uint32_t addr){
    static int n=0; if(n++>=40) return;
    fprintf(stderr,"[BCTR] @0x%x ctr=0x%llx r2=0x%llx r9=0x%llx r11=0x%llx r0=0x%llx\n",
        addr,(unsigned long long)ctx->ctr,(unsigned long long)ctx->r[2],
        (unsigned long long)ctx->r[9],(unsigned long long)ctx->r[11],(unsigned long long)ctx->r[0]);
}
#ifdef PPU_TRACE
static DWORD WINAPI ppu_watchdog(LPVOID p){
    (void)p;
    for(;;){ Sleep(3000); fprintf(stderr,"[WATCHDOG] curfn=sub_%x\n", g_curfn); }
}
#endif

volatile int g_trace_n = 0;
static uint32_t g_trace_addr[16];
static volatile long g_trace_cnt[16];
typedef struct { uint32_t fn, ea, len; } TraceDump;
static TraceDump g_trdump[8]; static int g_ntrdump=0;
static __declspec(thread) uint64_t t_gid;
static volatile long g_traceall_left = 0;
static uint64_t g_traceall_tid = 0;
static long g_traceall_arm_cnt = 0;
static uint32_t g_traceall_arm_delay = 0;
static int g_tracestr = 0;
static uint32_t g_trderef_fn, g_trderef_len;
static int g_trpeek = -1;
static long g_tracemax = 64;
static DWORD WINAPI traceall_arm(LPVOID p){
    (void)p;
    Sleep(g_traceall_arm_delay);
    InterlockedExchange(&g_traceall_left, g_traceall_arm_cnt);
    fprintf(stderr,"[TR] traceall armed\n");
    return 0;
}
static struct { uint64_t tid; PPUContext* ctx; DWORD htid; } g_ctxreg[64];
static volatile long g_nctxreg;
static uint64_t guest_tid_of(DWORD htid){
    long nc=g_nctxreg; if(nc>64) nc=64;
    for(long i=0;i<nc;i++) if(g_ctxreg[i].htid==htid) return g_ctxreg[i].tid;
    return 0;
}
static uint32_t g_watch_fn, g_watch_off, g_watch_len;
static volatile uint32_t g_watch_ea;
static uint8_t g_watch_snap[64];
static volatile uint32_t g_hw_ea; static uint32_t g_hw_delay, g_hw_auto, g_hw_off;
static uint32_t g_argw_lo, g_argw_hi;
static void miss0_dump(void){
    long nc=g_nctxreg; if(nc>64) nc=64;
    for(long i=0;i<nc;i++){
        if(!g_ctxreg[i].ctx || g_ctxreg[i].tid!=t_gid) continue;
        PPUContext* c=g_ctxreg[i].ctx;
        fprintf(stderr,"[MISS0] t%llu lr=0x%llx ctr=0x%llx r1=0x%llx r3=0x%llx r4=0x%llx r29=0x%llx r30=0x%llx r31=0x%llx\n",
            (unsigned long long)t_gid,(unsigned long long)c->lr,(unsigned long long)c->ctr,
            (unsigned long long)c->r[1],(unsigned long long)c->r[3],(unsigned long long)c->r[4],
            (unsigned long long)c->r[29],(unsigned long long)c->r[30],(unsigned long long)c->r[31]);
        for(int rn=29;rn<=31;rn++){
            uint32_t node=(uint32_t)c->r[rn];
            if(node<0x10000 || (uint64_t)node+0x20>g_size) continue;
            uint32_t vt=(uint32_t)PPU_LW(g_base,node);
            uint32_t opd=(vt>=0x10000&&(uint64_t)vt+0x1c<=g_size)?(uint32_t)PPU_LW(g_base,vt+0x18):0;
            uint32_t code=(opd>=0x10000&&(uint64_t)opd+4<=g_size)?(uint32_t)PPU_LW(g_base,opd):0;
            fprintf(stderr,"[MISS0]   r%d=0x%x: w0..7 %08x %08x %08x %08x %08x %08x %08x %08x | vt=0x%x opd18=0x%x code=0x%x\n",
                rn,node,
                (uint32_t)PPU_LW(g_base,node),(uint32_t)PPU_LW(g_base,node+4),
                (uint32_t)PPU_LW(g_base,node+8),(uint32_t)PPU_LW(g_base,node+12),
                (uint32_t)PPU_LW(g_base,node+16),(uint32_t)PPU_LW(g_base,node+20),
                (uint32_t)PPU_LW(g_base,node+24),(uint32_t)PPU_LW(g_base,node+28),
                vt,opd,code);
        }
        break;
    }
    fflush(stderr);
}
static void lookup_miss_dump(uint32_t addr){
    long nc=g_nctxreg; if(nc>64) nc=64;
    for(long i=0;i<nc;i++){
        if(!g_ctxreg[i].ctx || g_ctxreg[i].tid!=t_gid) continue;
        PPUContext* c=g_ctxreg[i].ctx;
        uint32_t obj=(uint32_t)c->r[3];
        fprintf(stderr,"[LOOKUP-MISS]   target=0x%x lr=0x%llx r1=0x%llx r3=0x%x "
                "r4=0x%llx r31=0x%llx\n",addr,(unsigned long long)c->lr,
                (unsigned long long)c->r[1],obj,(unsigned long long)c->r[4],
                (unsigned long long)c->r[31]);
        if(obj>=0x10000 && (uint64_t)obj+0x20<=g_size){
            uint32_t vt=(uint32_t)PPU_LW(g_base,obj);
            fprintf(stderr,"[LOOKUP-MISS]   obj 0x%x: %08x %08x %08x %08x "
                    "%08x %08x %08x %08x\n",obj,
                    (uint32_t)PPU_LW(g_base,obj),(uint32_t)PPU_LW(g_base,obj+4),
                    (uint32_t)PPU_LW(g_base,obj+8),(uint32_t)PPU_LW(g_base,obj+12),
                    (uint32_t)PPU_LW(g_base,obj+16),(uint32_t)PPU_LW(g_base,obj+20),
                    (uint32_t)PPU_LW(g_base,obj+24),(uint32_t)PPU_LW(g_base,obj+28));
            if(vt>=0x10000 && (uint64_t)vt+0x20<=g_size)
                fprintf(stderr,"[LOOKUP-MISS]   vtable 0x%x: %08x %08x [+8]=%08x "
                        "%08x %08x %08x %08x %08x\n",vt,
                        (uint32_t)PPU_LW(g_base,vt),(uint32_t)PPU_LW(g_base,vt+4),
                        (uint32_t)PPU_LW(g_base,vt+8),(uint32_t)PPU_LW(g_base,vt+12),
                        (uint32_t)PPU_LW(g_base,vt+16),(uint32_t)PPU_LW(g_base,vt+20),
                        (uint32_t)PPU_LW(g_base,vt+24),(uint32_t)PPU_LW(g_base,vt+28));
            else
                fprintf(stderr,"[LOOKUP-MISS]   vtable 0x%x is not a readable "
                        "guest address - the object itself is bad\n",vt);
        } else {
            fprintf(stderr,"[LOOKUP-MISS]   r3=0x%x is not a guest pointer\n",obj);
        }
        break;
    }
    fflush(stderr);
}
static void evf_dump(void);
static DWORD WINAPI stacks_main(LPVOID p){
    uint32_t delay=((uint32_t*)p)[0], period=((uint32_t*)p)[1];
    static uint64_t last_lr[64]; static uint32_t last_r1[64];
    Sleep(delay);
    for(;;){
        fprintf(stderr,"[STACKS] ---- %lu ----\n",(unsigned long)GetTickCount());
        evf_dump();
        long n=g_nctxreg; if(n>64) n=64;
        for(long i=0;i<n;i++){
            PPUContext* c=g_ctxreg[i].ctx; if(!c) continue;
            uint32_t sp=(uint32_t)c->r[1];
            fprintf(stderr,"[STACKS] t%llu lr=0x%llx r1=0x%x:",(unsigned long long)g_ctxreg[i].tid,
                    (unsigned long long)c->lr,sp);
            for(int d=0; d<16; d++){
                if((uint64_t)sp+24>g_size) break;
                uint32_t back=(uint32_t)PPU_LW(g_base,sp+4);
                if(back<=sp || (uint64_t)back+24>g_size) break;
                uint32_t lr=(uint32_t)PPU_LW(g_base,back+20);
                fprintf(stderr," 0x%x",lr);
                sp=back;
            }
            fprintf(stderr,"\n");
            if(c->lr==last_lr[i] && (uint32_t)c->r[1]==last_r1[i] && c->lr){
                char b[1024]; int o=snprintf(b,sizeof b,"[WEDGE] t%llu regs:",(unsigned long long)g_ctxreg[i].tid);
                for(int rn=0;rn<32 && o<(int)sizeof b-24;rn++)
                    o+=snprintf(b+o,sizeof b-o," r%d=%llx",rn,(unsigned long long)c->r[rn]);
                fprintf(stderr,"%s\n",b);
                for(int rn=3;rn<32;rn++){
                    if(rn>12 && rn<27) continue;
                    uint32_t ea=(uint32_t)c->r[rn];
                    if(ea<0x10000 || (uint64_t)ea+32>g_size || (c->r[rn]>>32)) continue;
                    fprintf(stderr,"[WEDGE]   r%d=0x%x: %08x %08x %08x %08x %08x %08x %08x %08x\n",rn,ea,
                        (uint32_t)PPU_LW(g_base,ea),(uint32_t)PPU_LW(g_base,ea+4),
                        (uint32_t)PPU_LW(g_base,ea+8),(uint32_t)PPU_LW(g_base,ea+12),
                        (uint32_t)PPU_LW(g_base,ea+16),(uint32_t)PPU_LW(g_base,ea+20),
                        (uint32_t)PPU_LW(g_base,ea+24),(uint32_t)PPU_LW(g_base,ea+28));
                }
            }
            last_lr[i]=c->lr; last_r1[i]=(uint32_t)c->r[1];
        }
        Sleep(period);
    }
}
void ppu_trace_hit(uint32_t addr, PPUContext* ctx){
    { static __declspec(thread) int t_reg;
      if(!t_reg){ t_reg=1;
          long i=InterlockedIncrement(&g_nctxreg)-1;
          if(i<64){ g_ctxreg[i].tid=t_gid; g_ctxreg[i].ctx=ctx; g_ctxreg[i].htid=GetCurrentThreadId(); } } }
    if (g_watch_fn && addr==g_watch_fn){
        uint32_t ea=(uint32_t)ctx->r[1]+g_watch_off;
        if((uint64_t)ea+g_watch_len<=g_size){
            g_watch_ea=0;
            memcpy(g_watch_snap,g_base+ea,g_watch_len);
            g_watch_ea=ea;
        }
        if(g_hw_auto && !g_hw_ea)
            g_hw_ea=(uint32_t)ctx->r[1]+g_hw_off;
    }
    if (g_argw_hi){
        uint32_t hit=0;
        if ((uint32_t)ctx->r[1]>=g_argw_lo && (uint32_t)ctx->r[1]<g_argw_hi) hit=1;
        for(int rn=3;rn<=8 && !hit;rn++)
            if ((uint32_t)ctx->r[rn]>=g_argw_lo && (uint32_t)ctx->r[rn]<g_argw_hi) hit=rn;
        if (hit){
            static volatile long aw_n; long ak=InterlockedIncrement(&aw_n);
            if (ak<=400 || (ak%2048)==0)
                fprintf(stderr,"[AW] %lu t%llu fn=0x%x lr=0x%llx r1=0x%llx r3=0x%llx r4=0x%llx r5=0x%llx r6=0x%llx (n=%ld)\n",
                    (unsigned long)GetTickCount(),(unsigned long long)t_gid,addr,
                    (unsigned long long)ctx->lr,(unsigned long long)ctx->r[1],
                    (unsigned long long)ctx->r[3],(unsigned long long)ctx->r[4],
                    (unsigned long long)ctx->r[5],(unsigned long long)ctx->r[6],ak);
        }
    }
    if (g_trderef_fn && addr==g_trderef_fn){
        uint32_t o3=(uint32_t)ctx->r[3];
        int want=1;
        if (g_argw_hi && (uint64_t)o3+g_trderef_len<=g_size){
            want=0;
            for(uint32_t o=0;o<g_trderef_len && !want;o+=4){
                uint32_t w=(uint32_t)PPU_LW(g_base,o3+o);
                if(w>=g_argw_lo&&w<g_argw_hi) want=1;
            }
            for(int pw=0;pw<2 && !want;pw++){
                uint32_t p=(uint32_t)PPU_LW(g_base,o3+pw*4);
                if(p>=0x10000 && (uint64_t)p+0x30<=g_size)
                    for(uint32_t o=0;o<0x30 && !want;o+=4){
                        uint32_t w=(uint32_t)PPU_LW(g_base,p+o);
                        if(w>=g_argw_lo&&w<g_argw_hi) want=1;
                    }
            }
            {
              uint32_t hdr=(uint32_t)PPU_LW(g_base,o3);
              if(hdr>=0x10000 && (uint64_t)hdr+8<=g_size){
                  uint32_t da=(uint32_t)PPU_LW(g_base,hdr+4);
                  if(da>=0x10000 && (uint64_t)da+0x50<=g_size)
                      for(int di=0;di<4 && !want;di++){
                          uint32_t wr=(uint32_t)PPU_LW(g_base,da+di*20+12);
                          uint32_t bs=(uint32_t)PPU_LW(g_base,da+di*20+16);
                          if(!bs) continue;
                          uint32_t d0=bs+wr, d1=d0+(uint32_t)ctx->r[5];
                          if(d0<g_argw_hi && d1>g_argw_lo) want=1;
                      }
              } }
        }
        static volatile long td_n;
        long tk=want?InterlockedIncrement(&td_n):999;
        if (tk<=48){
            fprintf(stderr,"[TD] %lu t%llu fn=0x%x r3=0x%x r4=0x%llx r5=0x%llx:\n",
                (unsigned long)GetTickCount(),(unsigned long long)t_gid,addr,o3,
                (unsigned long long)ctx->r[4],(unsigned long long)ctx->r[5]);
            if ((uint64_t)o3+g_trderef_len<=g_size){
                fprintf(stderr,"[TD]   obj:");
                for(uint32_t o=0;o<g_trderef_len;o+=4) fprintf(stderr," %08x",(uint32_t)PPU_LW(g_base,o3+o));
                fprintf(stderr,"\n");
                for(int pw=0;pw<2;pw++){
                    uint32_t p=(uint32_t)PPU_LW(g_base,o3+pw*4);
                    if(p>=0x10000 && (uint64_t)p+0x30<=g_size){
                        fprintf(stderr,"[TD]   [+%d]=0x%x:",pw*4,p);
                        for(uint32_t o=0;o<0x30;o+=4) fprintf(stderr," %08x",(uint32_t)PPU_LW(g_base,p+o));
                        fprintf(stderr,"\n");
                    }
                }
                { uint32_t hdr=(uint32_t)PPU_LW(g_base,o3);
                  if(hdr>=0x10000 && (uint64_t)hdr+8<=g_size){
                      uint32_t da=(uint32_t)PPU_LW(g_base,hdr+4);
                      if(da>=0x10000 && (uint64_t)da+0x50<=g_size){
                          fprintf(stderr,"[TD]   descs@0x%x:",da);
                          for(uint32_t o=0;o<0x50;o+=4) fprintf(stderr," %08x",(uint32_t)PPU_LW(g_base,da+o));
                          fprintf(stderr,"\n");
                      }
                  } }
            }
        }
    }
    { static int bd=-1; if(bd<0) bd=getenv("PS3_BATCHDBG")?1:0;
      if(bd && addr==0x82cdb0u){
        static volatile long bn; long bk=InterlockedIncrement(&bn);
        if(bk>3500 && bk<=3512){
            uint32_t node=(uint32_t)ctx->r[4];
            if(node && (uint64_t)node+0x20<=g_size){
                uint32_t vt=(uint32_t)PPU_LW(g_base,node);
                uint32_t opd=(vt&&(uint64_t)vt+0x1c<=g_size)?(uint32_t)PPU_LW(g_base,vt+0x18):0;
                uint32_t code=(opd&&(uint64_t)opd+4<=g_size)?(uint32_t)PPU_LW(g_base,opd):0;
                fprintf(stderr,"[BD] k=%ld node=0x%x vt=0x%x opd18=0x%x code=0x%x node0..7: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                    bk,node,vt,opd,code,
                    (uint32_t)PPU_LW(g_base,node),(uint32_t)PPU_LW(g_base,node+4),
                    (uint32_t)PPU_LW(g_base,node+8),(uint32_t)PPU_LW(g_base,node+12),
                    (uint32_t)PPU_LW(g_base,node+16),(uint32_t)PPU_LW(g_base,node+20),
                    (uint32_t)PPU_LW(g_base,node+24),(uint32_t)PPU_LW(g_base,node+28));
            }
        }
      } }
    if (g_traceall_left>0 && t_gid==g_traceall_tid){
        long left=InterlockedDecrement(&g_traceall_left);
        if (left>=0) fprintf(stderr,"[TA] sub_%x lr=%llx r3=%llx r1=%llx r29=%llx r30=%llx r31=%llx\n",addr,
            (unsigned long long)ctx->lr,(unsigned long long)ctx->r[3],
            (unsigned long long)ctx->r[1],(unsigned long long)ctx->r[29],
            (unsigned long long)ctx->r[30],(unsigned long long)ctx->r[31]);
    }
    for (int i=0;i<g_trace_n;i++){
        if (g_trace_addr[i]!=addr) continue;
        long k=InterlockedIncrement(&g_trace_cnt[i]);
        if ((uint64_t)ctx->r[3] >= g_size){
            static volatile long bt_n=0; long bk=InterlockedIncrement(&bt_n);
            if (bk<=6){
                fprintf(stderr,"[BTRACE!] fn=0x%x BAD r3=0x%llx r4=0x%llx lr=0x%llx r1=0x%x r29=0x%llx r31=0x%llx\n",
                    addr,(unsigned long long)ctx->r[3],(unsigned long long)ctx->r[4],
                    (unsigned long long)ctx->lr,(uint32_t)ctx->r[1],
                    (unsigned long long)ctx->r[29],(unsigned long long)ctx->r[31]);
                uint32_t sp=(uint32_t)ctx->r[1];
                for(int d=0; d<24; d++){
                    if((uint64_t)sp+24>g_size) break;
                    uint32_t back=(uint32_t)PPU_LW(g_base,sp+4);
                    if(back<=sp || (uint64_t)back+24>g_size) break;
                    uint32_t lr=(uint32_t)PPU_LW(g_base,back+20);
                    fprintf(stderr,"[BTRACE!]   #%d sp=0x%x -> lr=0x%x%s\n",d,sp,lr,
                        (lr>=0x10000&&lr<0xd69368)?"":"  (bad)");
                    sp=back;
                }
            }
        }
        if (k<=g_tracemax || (k%1024)==0){
            uint32_t pk=0;
            if (g_trpeek>=0){
                uint32_t pea=(uint32_t)ctx->r[3]+(uint32_t)g_trpeek;
                if ((uint64_t)pea+4<=g_size)
                    pk=((uint32_t)g_base[pea]<<24)|((uint32_t)g_base[pea+1]<<16)|
                       ((uint32_t)g_base[pea+2]<<8)|g_base[pea+3];
            }
            char pkbuf[24]={0};
            if (g_trpeek>=0) snprintf(pkbuf,sizeof pkbuf," peek=%08x",pk);
            fprintf(stderr,"[TR] %lu t%llu fn=0x%x lr=0x%llx r3=0x%llx r4=0x%llx r1=0x%llx r31=0x%llx k=%ld%s\n",
                (unsigned long)GetTickCount(),
                (unsigned long long)t_gid, addr,
                (unsigned long long)ctx->lr, (unsigned long long)ctx->r[3],
                (unsigned long long)ctx->r[4], (unsigned long long)ctx->r[1],
                (unsigned long long)ctx->r[31], k, pkbuf);
            if (g_tracestr){
                for (int rn=3;rn<=6;rn++){
                    uint32_t ea=(uint32_t)ctx->r[rn];
                    if (!ea || (uint64_t)ea+64>g_size) continue;
                    const uint8_t* p=g_base+ea; int sn=0;
                    while (sn<63 && p[sn]>=0x20 && p[sn]<0x7f) sn++;
                    if (sn>=3 && p[sn]==0)
                        fprintf(stderr,"[TRSTR] fn=0x%x r%d=\"%.*s\"\n",addr,rn,sn,(const char*)p);
                }
            }
            if ((uint64_t)ctx->r[3] >= g_size){
                fprintf(stderr,"[BTRACE] fn=0x%x BAD r3=0x%llx r4=0x%llx r31=0x%llx r1=0x%x - stack words in code range:\n",
                        addr,(unsigned long long)ctx->r[3],(unsigned long long)ctx->r[4],
                        (unsigned long long)ctx->r[31],(uint32_t)ctx->r[1]);
                uint32_t sp=(uint32_t)ctx->r[1];
                for(uint32_t o=0;o<0x300 && (uint64_t)sp+o+4<=g_size;o+=4){
                    uint32_t w=(uint32_t)PPU_LW(g_base,sp+o);
                    if(w>=0x10000 && w<0xd69368)
                        fprintf(stderr,"[BTRACE]   [r1+0x%x]=0x%x\n",o,w);
                }
                uint32_t node=(uint32_t)ctx->r[31];
                if((uint64_t)node+12<=g_size){
                    uint32_t obj=(uint32_t)PPU_LW(g_base,node+8);
                    fprintf(stderr,"[BTRACE]   node=0x%x obj=LW(node+8)=0x%x\n",node,obj);
                    if((uint64_t)obj+4<=g_size){
                        uint32_t vt=(uint32_t)PPU_LW(g_base,obj);
                        fprintf(stderr,"[BTRACE]   vtable=0x%x\n",vt);
                        for(int s=0;s<=32;s+=4){
                            if((uint64_t)vt+s+8>g_size) break;
                            uint32_t opd=(uint32_t)PPU_LW(g_base,vt+s);
                            uint32_t code=((uint64_t)opd+4<=g_size)?(uint32_t)PPU_LW(g_base,opd):0;
                            fprintf(stderr,"[BTRACE]   vtable[+%d] opd=0x%x code=0x%x\n",s,opd,code);
                        }
                    }
                }
            }
        }
        if (k<=8){
            for (int j=0;j<g_ntrdump;j++){
                if (g_trdump[j].fn!=addr) continue;
                uint32_t ea=g_trdump[j].ea, len=g_trdump[j].len;
                if ((uint64_t)ea+len>g_size) continue;
                fprintf(stderr,"[TRDUMP] fn=0x%x ea=0x%x len=0x%x",addr,ea,len);
                for (uint32_t b=0;b<len;b++){
                    if((b&15)==0) fprintf(stderr,"\n  %08x ",ea+b);
                    fprintf(stderr,"%02x ",g_base[ea+b]);
                }
                fprintf(stderr,"\n");
            }
        }
        return;
    }
}
static LONG WINAPI hw_veh(EXCEPTION_POINTERS* ep){
    if(ep->ExceptionRecord->ExceptionCode!=EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c=ep->ContextRecord;
    uint64_t v=0;
    if((uint64_t)g_hw_ea+8<=g_size){ memcpy(&v,g_base+g_hw_ea,8); v=__builtin_bswap64(v); }
    int legit_fn = (g_curfn==0x825490u||g_curfn==0x8254e8u);
    if(legit_fn && (v>>32)==0) return EXCEPTION_CONTINUE_EXECUTION;
    static volatile long nlog;
    {
      static volatile uint64_t lastkey;
      uint64_t key=((uint64_t)g_curfn<<32)^(ep->ContextRecord->Rip&0xffffffffull);
      if(key==lastkey) return EXCEPTION_CONTINUE_EXECUTION;
      lastkey=key; }
    if(InterlockedIncrement(&nlog)<=96){
        uint64_t modbase=(uint64_t)GetModuleHandleA(NULL);
        fprintf(stderr,"[HWWATCH] %lu WRITE by t%llu (tid=%lu) rip=+0x%llx curfn=sub_%x val=0x%llx\n",
                (unsigned long)GetTickCount(),(unsigned long long)t_gid,GetCurrentThreadId(),
                (unsigned long long)(c->Rip-modbase),g_curfn,(unsigned long long)v);
        { long nc=g_nctxreg; if(nc>64) nc=64;
          for(long i=0;i<nc;i++) if(g_ctxreg[i].ctx && g_ctxreg[i].tid==t_gid){
              PPUContext* gc=g_ctxreg[i].ctx;
              fprintf(stderr,"[HWWATCH]   lr=0x%llx r1=0x%llx r3=0x%llx r4=0x%llx r5=0x%llx r11=0x%llx\n",
                  (unsigned long long)gc->lr,(unsigned long long)gc->r[1],
                  (unsigned long long)gc->r[3],(unsigned long long)gc->r[4],
                  (unsigned long long)gc->r[5],(unsigned long long)gc->r[11]);
              { uint32_t sp=(uint32_t)gc->r[1];
                fprintf(stderr,"[HWWATCH]   stack:");
                for(int d=0; d<12; d++){
                    if((uint64_t)sp+24>g_size) break;
                    uint32_t back=(uint32_t)PPU_LW(g_base,sp+4);
                    if(back<=sp || (uint64_t)back+24>g_size) break;
                    fprintf(stderr," 0x%x",(uint32_t)PPU_LW(g_base,back+20));
                    sp=back;
                }
                fprintf(stderr,"\n"); }
              break; } }
        fflush(stderr);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI hw_arm_main(LPVOID p){
    (void)p;
    if(g_hw_auto){ while(!g_hw_ea) Sleep(50); Sleep(200); }
    else Sleep(g_hw_delay);
    AddVectoredExceptionHandler(1,hw_veh);
    uint64_t ha=(uint64_t)(g_base+g_hw_ea);
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    THREADENTRY32 te; te.dwSize=sizeof te; int armed=0;
    DWORD me=GetCurrentThreadId(), pid=GetCurrentProcessId();
    if(Thread32First(snap,&te)) do{
        if(te.th32OwnerProcessID!=pid || te.th32ThreadID==me) continue;
        HANDLE ht=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,te.th32ThreadID);
        if(!ht) continue;
        if(SuspendThread(ht)!=(DWORD)-1){
            CONTEXT c; memset(&c,0,sizeof c); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
            if(GetThreadContext(ht,&c)){
                c.Dr0=ha;
                c.Dr7=(c.Dr7&~0xf00ffull)|0x1ull|(0x1ull<<16)|(0x2ull<<18);
                if(SetThreadContext(ht,&c)) armed++;
            }
            ResumeThread(ht);
        }
        CloseHandle(ht);
    } while(Thread32Next(snap,&te));
    CloseHandle(snap);
    fprintf(stderr,"[HWWATCH] armed ea=0x%x host=0x%llx on %d threads\n",g_hw_ea,(unsigned long long)ha,armed);
    return 0;
}
static void fswatch_check(const char* who, uint32_t buf, uint32_t nb, int fd, PPUContext* ctx){
    static uint32_t lo=0, hi=0; static int init;
    if(!init){ init=1; const char* e=getenv("PS3_FSWATCH");
               if(e){ unsigned a=0,b=0; sscanf(e,"%x:%x",&a,&b); lo=a; hi=b;
                      fprintf(stderr,"[FSWATCH] armed [0x%x,0x%x)\n",lo,hi); } }
    if(hi>lo && buf<hi && buf+nb>lo)
        fprintf(stderr,"[FSWATCH] %lu %s fd=%d buf=0x%x nb=0x%x lr=0x%llx fn=sub_%x t%llu\n",
                (unsigned long)GetTickCount(),who,fd,buf,nb,
                (unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid);
}
static DWORD WINAPI watch_main(LPVOID p){
    (void)p;
    for(;;){
        uint32_t ea=g_watch_ea; uint32_t len=g_watch_len;
        if(ea && (uint64_t)ea+len<=g_size && memcmp(g_base+ea,g_watch_snap,len)){
            fprintf(stderr,"[WATCH] %lu ea=0x%x CHANGED\n  old:",(unsigned long)GetTickCount(),ea);
            for(uint32_t i=0;i<len;i++) fprintf(stderr," %02x",g_watch_snap[i]);
            fprintf(stderr,"\n  new:");
            for(uint32_t i=0;i<len;i++) fprintf(stderr," %02x",g_base[ea+i]);
            fprintf(stderr,"\n[WATCH] curfns:");
            for(int i=0;i<g_nppumon;i++) if(g_ppumon[i].fn)
                fprintf(stderr," t%llu=sub_%x",(unsigned long long)g_ppumon[i].id,*g_ppumon[i].fn);
            fprintf(stderr,"\n[WATCH] lr/r1:");
            { long nc=g_nctxreg; if(nc>64) nc=64;
              for(long i=0;i<nc;i++){ PPUContext* c=g_ctxreg[i].ctx; if(!c) continue;
                  fprintf(stderr," t%llu=0x%llx/0x%x",(unsigned long long)g_ctxreg[i].tid,
                          (unsigned long long)c->lr,(uint32_t)c->r[1]); } }
            fprintf(stderr,"\n");
            memcpy(g_watch_snap,g_base+ea,len);
        }
        Sleep(0);
    }
    return 0;
}
static void trace_init(void){
    const char* e=getenv("PS3_TRACE");
    if (e){
        int n=0;
        while(*e && n<16){
            char* end; uint32_t a=(uint32_t)strtoul(e,&end,16);
            if (end==e) break;
            if (a) g_trace_addr[n++]=a;
            e=end; while(*e==','||*e==' ') e++;
        }
        g_trace_n=n;
        fprintf(stderr,"[TR] watching %d fns:",n);
        for(int i=0;i<n;i++) fprintf(stderr," 0x%x",g_trace_addr[i]);
        fprintf(stderr,"\n");
    }
    e=getenv("PS3_STACKS");
    if (e){
        static uint32_t sp2[2]; sp2[0]=20000; sp2[1]=5000;
        sscanf(e,"%u:%u",&sp2[0],&sp2[1]);
        if(!g_trace_n) g_trace_n=-1;
        CreateThread(0,0,stacks_main,sp2,0,0);
        fprintf(stderr,"[STACKS] armed delay=%u period=%u\n",sp2[0],sp2[1]);
    }
    e=getenv("PS3_HWWATCH");
    if (e){
        if(!strncmp(e,"auto:",5)){
            g_hw_auto=1; g_hw_off=(uint32_t)strtoul(e+5,0,16);
            fprintf(stderr,"[HWWATCH] auto mode off=0x%x (arms at watch-fn entry)\n",g_hw_off);
        } else {
            unsigned ea=0; unsigned dly=15000; sscanf(e,"%x:%u",&ea,&dly);
            g_hw_ea=ea; g_hw_delay=dly;
            fprintf(stderr,"[HWWATCH] pending ea=0x%x delay=%ums\n",ea,dly);
        }
        CreateThread(0,0,hw_arm_main,0,0,0);
    }
    e=getenv("PS3_WATCH");
    if (e){
        unsigned fn=0,off=0,len=16; sscanf(e,"%x:%x:%x",&fn,&off,&len);
        if(len>64) len=64;
        g_watch_fn=fn; g_watch_off=off; g_watch_len=len;
        if(!g_trace_n) g_trace_n=-1;
        CreateThread(0,0,watch_main,0,0,0);
        fprintf(stderr,"[WATCH] armed fn=0x%x off=0x%x len=0x%x\n",fn,off,len);
    }
    e=getenv("PS3_TRACEDEREF");
    if (e){
        unsigned fn=0,len=0x40; sscanf(e,"%x:%x",&fn,&len);
        if(len>0x100) len=0x100;
        g_trderef_fn=fn; g_trderef_len=len;
        if(!g_trace_n) g_trace_n=-1;
        fprintf(stderr,"[TD] armed fn=0x%x len=0x%x\n",fn,len);
    }
    e=getenv("PS3_ARGWATCH");
    if (e){
        unsigned lo=0,hi=0; sscanf(e,"%x:%x",&lo,&hi);
        g_argw_lo=lo; g_argw_hi=hi;
        if(!g_trace_n) g_trace_n=-1;
        fprintf(stderr,"[AW] armed [0x%x,0x%x)\n",lo,hi);
    }
    if (getenv("PS3_TRACESTR")) g_tracestr=1;
    e=getenv("PS3_TRPEEK");
    if (e) g_trpeek=(int)strtol(e,0,0);
    e=getenv("PS3_TRACEMAX");
    if (e) g_tracemax=strtol(e,0,0);
    e=getenv("PS3_TRACEALL");
    if (e){
        unsigned long long tid=0; long cnt=2000; unsigned long dly=8000;
        sscanf(e,"%llu:%ld:%lu",&tid,&cnt,&dly);
        g_traceall_tid=tid; g_traceall_arm_cnt=cnt; g_traceall_arm_delay=(uint32_t)dly;
        if (!g_trace_n) g_trace_n=-1;
        CreateThread(0,0,traceall_arm,0,0,0);
        fprintf(stderr,"[TR] traceall t%llu count=%ld delay=%lums\n",tid,cnt,dly);
    }
    e=getenv("PS3_TRACEDUMP");
    if (e){
        while(*e && g_ntrdump<8){
            char* end; uint32_t fn=(uint32_t)strtoul(e,&end,16); if(end==e||*end!=':') break;
            e=end+1; uint32_t ea=(uint32_t)strtoul(e,&end,16); if(end==e||*end!=':') break;
            e=end+1; uint32_t len=(uint32_t)strtoul(e,&end,16); if(end==e) break;
            if (len>0x1000) len=0x1000;
            g_trdump[g_ntrdump].fn=fn; g_trdump[g_ntrdump].ea=ea; g_trdump[g_ntrdump].len=len; g_ntrdump++;
            e=end; while(*e==','||*e==' ') e++;
        }
        fprintf(stderr,"[TR] %d trace dumps armed\n",g_ntrdump);
    }
}
extern void spu_rt_set_mainmem(uint8_t* base, uint64_t size);
static void fs_cleanup(void);
static SpuBodyFn spu_resolve(uint32_t pc, const uint8_t* ls);
static int spu_intr_route(SpuThread* st, uint32_t intr, uint32_t data1);
static DWORD WINAPI dump_thread(LPVOID p);
static volatile uint32_t g_watch_page = 0;
static volatile long g_watch_hits = 0;
static HANDLE g_watch_rearm_ev = 0;
static LONG WINAPI watch_veh(EXCEPTION_POINTERS* ep){
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || !g_watch_page)
        return EXCEPTION_CONTINUE_SEARCH;
    uint8_t* a=(uint8_t*)ep->ExceptionRecord->ExceptionInformation[1];
    if (a < g_base+g_watch_page || a >= g_base+g_watch_page+0x1000)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD old; VirtualProtect(g_base+g_watch_page,0x1000,PAGE_READWRITE,&old);
    long k=InterlockedIncrement(&g_watch_hits);
    uint64_t mbase=(uint64_t)GetModuleHandleA(0);
    fprintf(stderr,"[watch] WRITE ea=0x%llx curfn=sub_%x t%llu rip-off=0x%llx (hit %ld)\n",
        (unsigned long long)(a-g_base), g_curfn, (unsigned long long)t_gid,
        (unsigned long long)(ep->ContextRecord->Rip-mbase), k);
    if (k<64 && g_watch_rearm_ev) SetEvent(g_watch_rearm_ev);
    return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI watch_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_WATCHWR"); if(!e) return 0;
    uint32_t ea=0,ms=1000; sscanf(e,"%i,%u",&ea,&ms);
    if(!ea) return 0;
    g_watch_rearm_ev=CreateEventA(0,FALSE,FALSE,0);
    AddVectoredExceptionHandler(1,watch_veh);
    Sleep(ms);
    g_watch_page = ea & ~0xFFFu;
    DWORD old; VirtualProtect(g_base+g_watch_page,0x1000,PAGE_READONLY,&old);
    fprintf(stderr,"[watch] armed page 0x%x\n",g_watch_page);
    for(;;){ WaitForSingleObject(g_watch_rearm_ev,INFINITE); Sleep(1);
        VirtualProtect(g_base+g_watch_page,0x1000,PAGE_READONLY,&old); }
}
static uint32_t g_tblw_lo, g_tblw_hi;
static volatile long g_tblw_armed, g_tblw_noise;
static __declspec(thread) struct { uint8_t *addr, *page; uint32_t oldv[2]; int pend, inrange; } t_tblw;
static LONG WINAPI tblw_veh(EXCEPTION_POINTERS* ep){
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if(code==EXCEPTION_ACCESS_VIOLATION){
        if(!g_tblw_armed || ep->ExceptionRecord->ExceptionInformation[0]!=1)
            return EXCEPTION_CONTINUE_SEARCH;
        uint8_t* a=(uint8_t*)ep->ExceptionRecord->ExceptionInformation[1];
        uint8_t* pg=g_base+(g_tblw_lo&~0xfffu);
        if(a<pg || a>=pg+0x1000) return EXCEPTION_CONTINUE_SEARCH;
        DWORD old; VirtualProtect(pg,0x1000,PAGE_READWRITE,&old);
        t_tblw.addr=a; t_tblw.page=pg; t_tblw.pend=1;
        t_tblw.inrange = (a>=g_base+g_tblw_lo && a<g_base+g_tblw_hi);
        if(t_tblw.inrange){
            const uint8_t* w=g_base+(((uint32_t)(a-g_base))&~3u);
            t_tblw.oldv[0]=(uint32_t)w[0]<<24|w[1]<<16|w[2]<<8|w[3];
            t_tblw.oldv[1]=(uint32_t)w[4]<<24|w[5]<<16|w[6]<<8|w[7];
        } else InterlockedIncrement(&g_tblw_noise);
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if(code==EXCEPTION_SINGLE_STEP && t_tblw.pend){
        t_tblw.pend=0;
        ep->ContextRecord->EFlags &= ~0x100u;
        if(t_tblw.inrange){
            uint32_t ea=(uint32_t)(t_tblw.addr-g_base);
            const uint8_t* w=g_base+(ea&~3u);
            uint32_t n0=(uint32_t)w[0]<<24|w[1]<<16|w[2]<<8|w[3];
            uint32_t n1=(uint32_t)w[4]<<24|w[5]<<16|w[6]<<8|w[7];
            static volatile long nh; long k=InterlockedIncrement(&nh);
            if(k<=1024 || (k%64)==0){
                uint64_t mbase=(uint64_t)GetModuleHandleA(0);
                fprintf(stderr,"[TBLW] %lu HOST-WR ea=0x%x %08x->%08x +4:%08x->%08x curfn=sub_%x t%llu rip-off=0x%llx (hit %ld)\n",
                    (unsigned long)GetTickCount(), ea&~3u,
                    t_tblw.oldv[0],n0, t_tblw.oldv[1],n1, g_curfn,
                    (unsigned long long)t_gid,
                    (unsigned long long)(ep->ContextRecord->Rip-mbase), k);
            }
        }
        DWORD old; VirtualProtect(t_tblw.page,0x1000,PAGE_READONLY,&old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void tblw_arm(void){
    if(InterlockedExchange(&g_tblw_armed,1)) return;
    DWORD old; VirtualProtect(g_base+(g_tblw_lo&~0xfffu),0x1000,PAGE_READONLY,&old);
    fprintf(stderr,"[TBLW] %lu host-side veh ARMED page 0x%x\n",
            (unsigned long)GetTickCount(), g_tblw_lo&~0xfffu);
}
static DWORD WINAPI tblw_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_TBLWATCH"); if(!e) return 0;
    if(getenv("PS3_TBLNOVEH")) return 0;
    unsigned a=0,b=0; char opt[8]={0}; sscanf(e,"%x:%x,%7s",&a,&b,opt);
    if(b<=a || b>g_size) return 0;
    a &= ~3u; if(b-a>0x1000) b=a+0x1000;
    g_tblw_lo=a; g_tblw_hi=b;
    AddVectoredExceptionHandler(1,tblw_veh);
    fprintf(stderr,"[TBLW] sampler armed [0x%x,0x%x) veh=%s\n",a,b,opt[0]?"now":"on-first-0x123");
    if(opt[0]) tblw_arm();
    uint8_t snap[0x1000]; memcpy(snap,g_base+a,b-a);
    for(;;){
        Sleep(1);
        char buf[900]; int o=0, hit123=0;
        for(uint32_t off=0; off<b-a; off+=4){
            const uint8_t* c=g_base+a+off; uint8_t* s=snap+off;
            if(memcmp(c,s,4)==0) continue;
            uint32_t ov=(uint32_t)s[0]<<24|s[1]<<16|s[2]<<8|s[3];
            uint32_t nv=(uint32_t)c[0]<<24|c[1]<<16|c[2]<<8|c[3];
            memcpy(s,c,4);
            if(nv==0x123) hit123=1;
            if(o<(int)sizeof buf-32)
                o+=snprintf(buf+o,sizeof buf-o," %x:%08x->%08x",a+off,ov,nv);
        }
        if(o) fprintf(stderr,"[TBLS] %lu%s\n",(unsigned long)GetTickCount(),buf);
        if(hit123 && !g_tblw_armed) tblw_arm();
    }
}
typedef struct { uint32_t lo, hi; uint8_t* orig; const char* what; int repair; volatile long hits, off; } RoRange;
static RoRange g_ro[6]; static int g_nro;
static volatile long g_ro_hits, g_ro_snapped;
static DWORD g_ro_t0;
enum { ROLOG_FULL = 48 };
static __declspec(thread) struct {
    uint8_t* page[2]; int npage; uint32_t ea; int r, pend; long k;
    uint64_t bt[12]; int nbt;
} t_ro;
extern int spu_describe_tid(unsigned long tid, char* out, int cap);

static int ro_range_of(uint32_t ea){
    for(int i=0;i<g_nro;i++) if(ea>=g_ro[i].lo && ea<g_ro[i].hi) return i;
    return -1;
}
static int ro_backtrace(const CONTEXT* c0, uint64_t* out, int max){
    CONTEXT c=*c0; int n=0;
    __try {
        while(n<max && c.Rip){
            out[n++]=c.Rip;
            DWORD64 ib=0; PRUNTIME_FUNCTION rf=RtlLookupFunctionEntry(c.Rip,&ib,NULL);
            if(!rf){ c.Rip=*(const DWORD64*)c.Rsp; c.Rsp+=8; }
            else { PVOID hd; DWORD64 ef;
                   RtlVirtualUnwind(UNW_FLAG_NHANDLER,ib,c.Rip,rf,&c,&hd,&ef,NULL); }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }
    return n;
}
static void ro_ppu_regs(void){
    long nc=g_nctxreg; if(nc>64) nc=64;
    DWORD me=GetCurrentThreadId();
    for(long i=0;i<nc;i++){
        PPUContext* c=g_ctxreg[i].ctx;
        if(!c || g_ctxreg[i].htid!=me) continue;
        for(int r=0;r<32;r+=8)
            fprintf(stderr,"[ROGUARD]   r%-2d %08llx %08llx %08llx %08llx %08llx %08llx %08llx %08llx\n",r,
                (unsigned long long)c->r[r],(unsigned long long)c->r[r+1],(unsigned long long)c->r[r+2],
                (unsigned long long)c->r[r+3],(unsigned long long)c->r[r+4],(unsigned long long)c->r[r+5],
                (unsigned long long)c->r[r+6],(unsigned long long)c->r[r+7]);
        fprintf(stderr,"[ROGUARD]   lr %08llx ctr %08llx\n",(unsigned long long)c->lr,(unsigned long long)c->ctr);
        return;
    }
}
static void ro_report(const RoRange* R, uint32_t ea, const uint8_t* was, const uint8_t* now){
    uint64_t mbase=(uint64_t)GetModuleHandleA(0);
    fprintf(stderr,"[ROGUARD] %lu #%ld WRITE ea=0x%x (%s) t%llu host=%lu curfn=sub_%x sc=%d hle=%s\n",
            (unsigned long)GetTickCount(),t_ro.k,ea,R->what,(unsigned long long)t_gid,
            (unsigned long)GetCurrentThreadId(),g_curfn,g_cursc,g_curhle?g_curhle:"-");
    char b[400]; int o=snprintf(b,sizeof b,"[ROGUARD]   @0x%x was ",ea&~15u);
    for(int i=0;i<16;i++) o+=snprintf(b+o,sizeof b-o,"%02x%s",was[i],(i&3)==3?" ":"");
    o+=snprintf(b+o,sizeof b-o,"now ");
    for(int i=0;i<16;i++) o+=snprintf(b+o,sizeof b-o,"%02x%s",now[i],(i&3)==3?" ":"");
    fprintf(stderr,"%s-> %s\n",b,R->repair?"restored":"kept (report-only range)");
    if(t_ro.k<=ROLOG_FULL) ro_ppu_regs();
    char sd[700];
    if(spu_describe_tid(GetCurrentThreadId(),sd,sizeof sd)) fprintf(stderr,"[ROGUARD]   %s\n",sd);
    if(t_ro.nbt){
        o=snprintf(b,sizeof b,"[ROGUARD]   host stack (g=game.exe+):");
        for(int i=0;i<t_ro.nbt && o<(int)sizeof b-24;i++){
            uint64_t a=t_ro.bt[i];
            o+= (a-mbase<0x10000000ull) ? snprintf(b+o,sizeof b-o," g%llx",(unsigned long long)(a-mbase))
                                        : snprintf(b+o,sizeof b-o," %llx",(unsigned long long)a);
        }
        fprintf(stderr,"%s\n",b);
    }
}
static LONG WINAPI ro_veh(EXCEPTION_POINTERS* ep){
    DWORD code=ep->ExceptionRecord->ExceptionCode;
    if(code==EXCEPTION_ACCESS_VIOLATION){
        if(ep->ExceptionRecord->ExceptionInformation[0]!=1) return EXCEPTION_CONTINUE_SEARCH;
        uint8_t* a=(uint8_t*)ep->ExceptionRecord->ExceptionInformation[1];
        if(a<g_base || a>=g_base+g_size) return EXCEPTION_CONTINUE_SEARCH;
        uint32_t ea=(uint32_t)(a-g_base); int r=ro_range_of(ea);
        if(r<0) return EXCEPTION_CONTINUE_SEARCH;
        uint8_t* pg=g_base+(ea&~0xfffu); DWORD old;
        if(t_ro.pend){
            if(t_ro.npage>=2 || !VirtualProtect(pg,0x1000,PAGE_READWRITE,&old)) return EXCEPTION_CONTINUE_SEARCH;
            t_ro.page[t_ro.npage++]=pg;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if(!VirtualProtect(pg,0x1000,PAGE_READWRITE,&old)) return EXCEPTION_CONTINUE_SEARCH;
        t_ro.page[0]=pg; t_ro.npage=1; t_ro.ea=ea; t_ro.r=r; t_ro.pend=1;
        t_ro.k=InterlockedIncrement(&g_ro_hits);
        InterlockedIncrement(&g_ro[r].hits);
        t_ro.nbt = (t_ro.k<=ROLOG_FULL) ? ro_backtrace(ep->ContextRecord,t_ro.bt,12) : 0;
        if(GetTickCount()-g_ro_t0 >= 30000 && !InterlockedExchange(&g_ro_snapped,1)){
            fprintf(stderr,"[ROGUARD] first guarded write: ea=0x%x (%s) t%llu curfn=sub_%x - snapshot\n",
                    ea,g_ro[r].what,(unsigned long long)t_gid,g_curfn);
            ro_ppu_regs();
            statecap_request("ROGUARD: first write to guarded memory");
            { const char* e=getenv("PS3_ROGUARD_HOLD"); int ms=e?atoi(e):4000;
              if(ms>0) Sleep((DWORD)(ms>60000?60000:ms)); }
        }
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if(code==EXCEPTION_SINGLE_STEP && t_ro.pend){
        t_ro.pend=0;
        ep->ContextRecord->EFlags &= ~0x100u;
        const RoRange* R=&g_ro[t_ro.r];
        uint32_t e16=t_ro.ea&~15u; uint8_t was[16], now[16];
        memcpy(now,g_base+e16,16);
        for(int i=0;i<16;i++){ uint32_t x=e16+i;
            was[i] = (x>=R->lo && x<R->hi) ? R->orig[x-R->lo] : now[i]; }
        for(int p=0;p<t_ro.npage;p++){
            uint32_t pea=(uint32_t)(t_ro.page[p]-g_base);
            int rr=ro_range_of(pea); if(rr<0) rr=ro_range_of(pea+0xfffu);
            DWORD old;
            if(rr>=0 && !g_ro[rr].repair){
                RoRange* Q=&g_ro[rr];
                if(Q->hits>=16 && !InterlockedExchange(&Q->off,1)){
                    VirtualProtect(g_base+Q->lo,Q->hi-Q->lo,PAGE_READWRITE,&old);
                    fprintf(stderr,"[ROGUARD] %s: 16 reports, no longer watched\n",Q->what);
                }
                if(!Q->off) VirtualProtect(t_ro.page[p],0x1000,PAGE_READONLY,&old);
                continue;
            }
            if(rr>=0){ const RoRange* Q=&g_ro[rr];
                uint32_t s=pea<Q->lo?Q->lo:pea, e=pea+0x1000u>Q->hi?Q->hi:pea+0x1000u;
                memcpy(g_base+s,Q->orig+(s-Q->lo),e-s); }
            VirtualProtect(t_ro.page[p],0x1000,PAGE_READONLY,&old);
        }
        if(t_ro.k<=ROLOG_FULL || (t_ro.k%4096)==0 || (!R->repair && R->hits<=16)) ro_report(R,t_ro.ea,was,now);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void ro_add(uint32_t lo, uint32_t hi, const char* what, int repair){
    lo=(lo+0xfffu)&~0xfffu; hi&=~0xfffu;
    if(hi>g_size) hi=(uint32_t)(g_size&~0xfffull);
    if(hi<=lo || g_nro>=(int)(sizeof g_ro/sizeof g_ro[0])) return;
    uint8_t* orig=(uint8_t*)malloc(hi-lo); if(!orig) return;
    memcpy(orig,g_base+lo,hi-lo);
    DWORD old;
    if(!VirtualProtect(g_base+lo,hi-lo,PAGE_READONLY,&old)){
        fprintf(stderr,"[ROGUARD] cannot protect [0x%x,0x%x) %s: error %lu\n",lo,hi,what,GetLastError());
        free(orig); return;
    }
    RoRange* R=&g_ro[g_nro++]; R->lo=lo; R->hi=hi; R->orig=orig; R->what=what; R->repair=repair;
    fprintf(stderr,"[ROGUARD] guarding [0x%x,0x%x) %s (%u pages)\n",lo,hi,what,(hi-lo)>>12);
}
static uint64_t ro_be(const uint8_t* p, int n){ uint64_t v=0; for(int i=0;i<n;i++) v=v<<8|p[i]; return v; }
static void roguard_init(void){
    const char* e=getenv("PS3_ROGUARD");
    if(e && e[0]=='0'){ fprintf(stderr,"[ROGUARD] off (PS3_ROGUARD=0)\n"); return; }
    g_ro_t0=GetTickCount();
    FILE* f=fopen("../Work/EBOOT.ELF","rb");
    if(!f){ fprintf(stderr,"[ROGUARD] no ../Work/EBOOT.ELF: off\n"); return; }
    uint8_t h[64];
    if(fread(h,1,64,f)!=64 || memcmp(h,"\x7f" "ELF",4) || h[4]!=2){ fclose(f); return; }
    uint64_t entry=ro_be(h+0x18,8), phoff=ro_be(h+0x20,8), shoff=ro_be(h+0x28,8);
    unsigned phes=(unsigned)ro_be(h+0x36,2), phn=(unsigned)ro_be(h+0x38,2);
    unsigned shes=(unsigned)ro_be(h+0x3a,2), shn=(unsigned)ro_be(h+0x3c,2);
    AddVectoredExceptionHandler(1,ro_veh);
    for(unsigned i=0;i<phn && i<64;i++){
        uint8_t p[56]; fseek(f,(long)(phoff+(uint64_t)i*phes),SEEK_SET);
        if(fread(p,1,56,f)!=56) break;
        uint32_t type=(uint32_t)ro_be(p,4), flags=(uint32_t)ro_be(p+4,4);
        uint64_t va=ro_be(p+0x10,8), fsz=ro_be(p+0x20,8);
        if(type==1 && fsz && !(flags&2) && va+fsz<=g_size)
            ro_add((uint32_t)va,(uint32_t)(va+fsz),"read-only segment",1);
    }
    for(unsigned i=0;i<shn && i<256;i++){
        uint8_t s[64]; fseek(f,(long)(shoff+(uint64_t)i*shes),SEEK_SET);
        if(fread(s,1,64,f)!=64) break;
        uint64_t addr=ro_be(s+0x10,8), size=ro_be(s+0x20,8);
        if(addr && entry>=addr && entry<addr+size){ ro_add((uint32_t)addr,(uint32_t)(addr+size),".opd",1); break; }
    }
    fclose(f);
    ro_add(0,0x10000,"null page",0);
}

static DWORD WINAPI probe_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_PROBE"); if(!e) return 0;
    uint32_t ms=2000,rep=15; uint32_t ea[32]; int n=0;
    sscanf(e,"%u,%u",&ms,&rep);
    const char* c=strchr(e,':'); if(!c) return 0; c++;
    while(*c && n<32){ char* end; ea[n]=(uint32_t)strtoul(c,&end,16); if(end==c)break; n++; c=end; while(*c==','||*c==' ')c++; }
    for(uint32_t it=0;it<rep;it++){
        Sleep(ms);
        char b[1600]; int o=snprintf(b,sizeof b,"[probe] t=%lu:",(unsigned long)GetTickCount());
        for(int i=0;i<n&&o<(int)sizeof b-24;i++){
            uint32_t v=((uint32_t)g_base[ea[i]]<<24)|((uint32_t)g_base[ea[i]+1]<<16)|((uint32_t)g_base[ea[i]+2]<<8)|g_base[ea[i]+3];
            o+=snprintf(b+o,sizeof b-o," %x=%08x",ea[i],v); }
        fprintf(stderr,"%s\n",b);
    }
    return 0;
}
static DWORD WINAPI scan_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_SCAN"); if(!e) return 0;
    uint32_t val=0,ms=5000,rep=6; sscanf(e,"%i,%u,%u",&val,&ms,&rep);
    uint8_t b0=(uint8_t)(val>>24),b1=(uint8_t)(val>>16),b2=(uint8_t)(val>>8),b3=(uint8_t)val;
    static uint32_t prev[256]; static int nprev;
    for(uint32_t it=0;it<rep;it++){
        Sleep(ms);
        uint32_t hits[256]; int n=0;
        for(uint64_t a=0;a+4<=g_size && n<256;a+=4)
            if(g_base[a]==b0&&g_base[a+1]==b1&&g_base[a+2]==b2&&g_base[a+3]==b3)
                hits[n++]=(uint32_t)a;
        char buf[2048]; int o=snprintf(buf,sizeof buf,"[scan] t=%lums val=0x%x n=%d:",(unsigned long)GetTickCount(),val,n);
        for(int i=0;i<n&&i<48&&o<(int)sizeof buf-16;i++) o+=snprintf(buf+o,sizeof buf-o," %x",hits[i]);
        fprintf(stderr,"%s\n",buf);
        for(int i=0;i<nprev;i++){ int f=0; for(int j=0;j<n;j++) if(prev[i]==hits[j]){f=1;break;}
            if(!f) fprintf(stderr,"[scan] GONE 0x%x\n",prev[i]); }
        memcpy(prev,hits,sizeof(uint32_t)*n); nprev=n;
    }
    return 0;
}
static DWORD WINAPI cri_pump(LPVOID p);
static DWORD WINAPI poke_thread(LPVOID p);
static DWORD WINAPI scanval_thread(LPVOID p);
static DWORD WINAPI kick_thread(LPVOID p);
static DWORD WINAPI evfprof_dump(LPVOID p);
static void ppu_statecap(const char* dir);
void ppu_rt_init(uint8_t* base, uint64_t size){
    g_base=base; g_size=size;
    statecap_init(base,size);
    statecap_register("ppu",ppu_statecap);
    cap_init(base,size);
    ppu_mtrace_register();
    g_heap_hi=(uint32_t)(size-0x200000);
    spu_rt_set_mainmem(base, size);
    spu_set_resolver(spu_resolve);
    spu_set_intr_hook(spu_intr_route);
    if (getenv("PS3_DUMP")) CreateThread(0,0,dump_thread,0,0,0);
    if (getenv("PS3_SCAN")) CreateThread(0,0,scan_thread,0,0,0);
    if (getenv("PS3_PROBE")) CreateThread(0,0,probe_thread,0,0,0);
    if (getenv("PS3_WATCHWR")) CreateThread(0,0,watch_thread,0,0,0);
    if (getenv("PS3_TBLWATCH")) CreateThread(0,0,tblw_thread,0,0,0);
    if (!getenv("PS3_NOCRIPUMP")) CreateThread(0,0,cri_pump,0,0,0);
    if (getenv("PS3_POKE")) CreateThread(0,0,poke_thread,0,0,0);
    if (getenv("PS3_SCANVAL")) CreateThread(0,0,scanval_thread,0,0,0);
    if (getenv("PS3_KICKEVF")) CreateThread(0,0,kick_thread,0,0,0);
    ppumon_register(1);
    if (getenv("PS3_PPUMON"))  CreateThread(0,0,ppu_monitor,0,0,0);
    if (getenv("PS3_PPUPROF")) CreateThread(0,0,ppu_prof,0,0,0);
    if (getenv("PS3_SCPROF")){ g_scprof=1; CreateThread(0,0,scprof_dump,0,0,0); }
    if (getenv("PS3_EVFPROF")){ g_evfprof=1; CreateThread(0,0,evfprof_dump,0,0,0); }
    else g_evfprof=0;
    if (getenv("PS3_CPUPROF")) CreateThread(0,0,cpuprof_dump,0,0,0);
    hprof_init(hprof_label);
    roguard_init();
    t_gid=1; trace_init();
    InitializeCriticalSection(&g_lock);
    atexit(fs_cleanup);
#ifdef _WIN32
    SetUnhandledExceptionFilter(ppu_seh);
#ifdef PPU_TRACE
    CreateThread(0,0,ppu_watchdog,0,0,0);
#endif
#endif
}

static uint32_t guest_alloc(uint32_t size, uint32_t align);
static uint32_t guest_alloc_hi(uint32_t size, uint32_t align);
static DWORD WINAPI cri_pump(LPVOID p){
    (void)p;
    g_cripump_htid=GetCurrentThreadId();
    Sleep(3000);
    PPUContext* ctx=(PPUContext*)calloc(1,sizeof(PPUContext));
    uint32_t stk=guest_alloc_hi(0x20000,0x1000);
    uint32_t blk=guest_alloc_hi(0x10000,0x1000);
    ctx->r[13]=blk+0x7000;
    t_gid=90;
    PPCFunc f=ppu_lookup(0x8bb870u);
    if(!f){ fprintf(stderr,"[CRIPUMP] sub_8bb870 not recompiled\n"); return 0; }
    fprintf(stderr,"[CRIPUMP] running (200Hz)\n");
    for(;;){
        ctx->r[1]=stk+0x20000-0x200;
        ctx->r[2]=0xdd0078u;
        f(ctx,g_base);
        Sleep(5);
    }
}
static DWORD WINAPI dump_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_DUMP"); if(!e) return 0;
    uint32_t ea=0,sz=0x100,ms=10000,rep=1,ptr=0,off=0; int ind=0;
    if(e[0]=='*'){
        ind=1;
        if(!strchr(e,'+') || sscanf(e+1,"%i+%i,%i,%u,%u",&ptr,&off,&sz,&ms,&rep)<2)
            sscanf(e+1,"%i,%i,%u,%u",&ptr,&sz,&ms,&rep);
    } else sscanf(e,"%i,%i,%u,%u",&ea,&sz,&ms,&rep);
    static uint8_t prev[0x2000];
    if(sz>sizeof prev) sz=sizeof prev;
    for(uint32_t it=0;it<rep;it++){
        Sleep(ms);
        if(ind){
            uint32_t nea=((uint32_t)g_base[ptr]<<24)|((uint32_t)g_base[ptr+1]<<16)|
                         ((uint32_t)g_base[ptr+2]<<8)|g_base[ptr+3];
            nea+=off;
            if(nea!=ea){ ea=nea; it=0; }
            if(!ea || (uint64_t)ea+sz>g_size){ fprintf(stderr,"[dump] *%#x -> bad ea %#x\n",ptr,ea); continue; }
        }
        fprintf(stderr,"[dump] --- t=%ums ea=%08x ---\n",(it+1)*ms,ea);
        for(uint32_t o=0;o<sz;o+=16){
            if(it>0 && memcmp(prev+o,g_base+ea+o,16)==0) continue;
            char b[128]; int n=snprintf(b,sizeof b,"[dump] %08x:",ea+o);
            for(int k=0;k<16;k++) n+=snprintf(b+n,sizeof b-n,"%s%02x",(k%4)?"":" ",g_base[ea+o+k]);
            fprintf(stderr,"%s\n",b);
        }
        memcpy(prev,g_base+ea,sz);
    }
    return 0;
}

static DWORD WINAPI poke_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_POKE"); if(!e) return 0;
    char buf[256]; strncpy(buf,e,sizeof buf-1); buf[sizeof buf-1]=0;
    uint32_t ms=10000; char* at=strchr(buf,'@'); if(at){ *at=0; ms=(uint32_t)strtoul(at+1,0,0); }
    Sleep(ms);
    for(char* s=strtok(buf,",");s;s=strtok(0,",")){
        uint32_t ea=0,v=0; if(sscanf(s,"%i:%i",&ea,&v)==2 && ea<g_size){
            g_base[ea]=(uint8_t)v; fprintf(stderr,"[poke] %08x = %02x\n",ea,v); }
    }
    return 0;
}
int ppu_acipatch(uint32_t* n){
    static int on=-1; static uint32_t want;
    if(on<0){ const char* e=getenv("PS3_FUEL");
              want = e ? (uint32_t)strtoul(e,0,0) : 6;
              on = want ? 1 : 0;
              if(on) fprintf(stderr,"[FUEL] ACI patch set armed: sortie tickets = %u (PS3_FUEL=0 disables)\n",want);
              else   fprintf(stderr,"[FUEL] ACI patch set OFF (PS3_FUEL=0): missions need server-granted fuel\n"); }
    if(!on) return 0;
    if(n) *n=want;
    return 1;
}

static DWORD WINAPI scanval_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_SCANVAL"); if(!e) return 0;
    uint32_t val=0, vhi=0; uint32_t period=1000;
    { unsigned v=0,v2=0,pm=0;
      if(strchr(e,'-')){ int n=sscanf(e,"%x-%x:%u",&v,&v2,&pm); val=v; vhi=v2; if(n==3&&pm) period=pm; }
      else { int n=sscanf(e,"%x:%u",&v,&pm); val=v; if(n==2&&pm) period=pm; } }
    uint32_t target=__builtin_bswap32(val);
    if(vhi) fprintf(stderr,"[SV] scanning for ptrs into [0x%x,0x%x) every %ums\n",val,vhi,period);
    else fprintf(stderr,"[SV] scanning for 0x%x every %ums\n",val,period);
    uint32_t known[32]; int nknown=0;
    for(;;){
        const uint32_t* w=(const uint32_t*)g_base;
        uint64_t nw=g_size/4;
        for(uint64_t i=0;i<nw;i++){
            if(vhi){
                uint32_t hv=__builtin_bswap32(w[i]);
                if(hv<val||hv>=vhi) continue;
                uint32_t hea=(uint32_t)(i*4);
                if(hea>=val&&hea<vhi) continue;
            } else if(w[i]!=target) continue;
            uint32_t ea=(uint32_t)(i*4); int seen=0;
            for(int k=0;k<nknown;k++) if(known[k]==ea){ seen=1; break; }
            if(seen) continue;
            if(nknown<32) known[nknown++]=ea;
            fprintf(stderr,"[SV] %lu holder 0x%x:",(unsigned long)GetTickCount(),ea);
            uint32_t lo=ea>=32?ea-32:0;
            for(uint32_t o=lo;o<ea+32&&(uint64_t)o+4<=g_size;o+=4)
                fprintf(stderr," %08x",(uint32_t)PPU_LW(g_base,o));
            fprintf(stderr,"\n"); fflush(stderr);
        }
        for(int k=0;k<nknown;k++){
            uint32_t cur=(uint64_t)known[k]+4<=g_size?__builtin_bswap32(*(const uint32_t*)(g_base+known[k])):0;
            int gone = vhi ? (cur<val||cur>=vhi) : (cur!=val);
            if(gone){
                fprintf(stderr,"[SV] %lu holder 0x%x CLEARED (now %08x)\n",
                        (unsigned long)GetTickCount(),known[k],(uint32_t)PPU_LW(g_base,known[k]));
                known[k]=known[--nknown];
                k--;
            }
        }
        Sleep(period);
    }
}

static uint32_t guest_alloc(uint32_t size, uint32_t align){
    EnterCriticalSection(&g_lock);
    if (align<16) align=16;
    g_heap=(g_heap+align-1)&~(align-1);
    if ((uint64_t)g_heap+((size+15)&~15u) > (uint64_t)g_heap_hi-0x800000){
        LeaveCriticalSection(&g_lock);
        fprintf(stderr,"[alloc] GUEST HEAP EXHAUSTED req=0x%x heap=0x%x hi=0x%x fn=sub_%x t%llu\n",
                size,g_heap,g_heap_hi,g_curfn,(unsigned long long)t_gid);
        return 0;
    }
    uint32_t a=g_heap; g_heap+=(size+15)&~15u;
    LeaveCriticalSection(&g_lock);
    { static int lg=-1; if(lg<0) lg=getenv("PS3_ALLOCLOG")?1:0;
      if(lg) fprintf(stderr,"[alloc] 0x%x +0x%x = [0x%x,0x%x) fn=sub_%x t%llu\n",
                     a,size,a,a+size,g_curfn,(unsigned long long)t_gid); }
    return a;
}
typedef struct { uint32_t addr, size; int free; } MemBlk;
enum { NMEMBLK = 4096 };
static MemBlk g_memblk[NMEMBLK]; static int g_nmemblk;
static uint32_t mem_alloc(uint32_t size, uint32_t align){
    if(align<0x10000) align=0x10000;
    size=(size+0xFFFFu)&~0xFFFFu;
    EnterCriticalSection(&g_lock);
    int best=-1;
    for(int i=0;i<g_nmemblk;i++)
        if(g_memblk[i].free && g_memblk[i].size>=size && !(g_memblk[i].addr&(align-1)) &&
           (best<0 || g_memblk[i].size<g_memblk[best].size)) best=i;
    uint32_t a=0;
    if(best>=0){
        a=g_memblk[best].addr;
        uint32_t rem=g_memblk[best].size-size;
        g_memblk[best].free=0;
        if(rem>=0x10000 && g_nmemblk<NMEMBLK){
            g_memblk[best].size=size;
            g_memblk[g_nmemblk].addr=a+size; g_memblk[g_nmemblk].size=rem;
            g_memblk[g_nmemblk].free=1; g_nmemblk++;
        }
        LeaveCriticalSection(&g_lock);
        { static int z=-1; if(z<0){ const char* e=getenv("PS3_MEMZERO"); z=(e&&e[0]=='0')?0:1; }
          if(z && (uint64_t)a+size<=g_size) memset(g_base+a,0,size); }
    } else {
        LeaveCriticalSection(&g_lock);
        a=guest_alloc(size,align);
        if(a){
            EnterCriticalSection(&g_lock);
            if(g_nmemblk<NMEMBLK){ g_memblk[g_nmemblk].addr=a; g_memblk[g_nmemblk].size=size;
                                   g_memblk[g_nmemblk].free=0; g_nmemblk++; }
            LeaveCriticalSection(&g_lock);
        }
    }
    { static int lg=-1; if(lg<0) lg=getenv("PS3_ALLOCLOG")?1:0;
      if(lg) fprintf(stderr,"[mem] alloc 0x%x +0x%x %s fn=sub_%x t%llu\n",
                     a,size,best>=0?"reuse":"bump",g_curfn,(unsigned long long)t_gid); }
    return a;
}
static void mem_free(uint32_t addr){
    if(!addr) return;
    EnterCriticalSection(&g_lock);
    int i;
    for(i=0;i<g_nmemblk;i++) if(g_memblk[i].addr==addr && !g_memblk[i].free) break;
    if(i<g_nmemblk){
        g_memblk[i].free=1;
        for(int again=1; again; ){
            again=0;
            for(int j=0;j<g_nmemblk;j++){
                if(j==i || !g_memblk[j].free) continue;
                if(g_memblk[j].addr == g_memblk[i].addr+g_memblk[i].size)
                    g_memblk[i].size += g_memblk[j].size;
                else if(g_memblk[j].addr+g_memblk[j].size == g_memblk[i].addr){
                    g_memblk[i].addr = g_memblk[j].addr;
                    g_memblk[i].size += g_memblk[j].size;
                } else continue;
                g_memblk[j]=g_memblk[--g_nmemblk];
                if(i==g_nmemblk) i=j;
                again=1; break;
            }
        }
        { static int lg=-1; if(lg<0) lg=getenv("PS3_ALLOCLOG")?1:0;
          if(lg) fprintf(stderr,"[mem] free 0x%x -> [0x%x,0x%x) t%llu\n",
                         addr,g_memblk[i].addr,g_memblk[i].addr+g_memblk[i].size,(unsigned long long)t_gid); }
    } else {
        static int warn; if(warn++<16)
            fprintf(stderr,"[mem] free of unknown block 0x%x t%llu\n",addr,(unsigned long long)t_gid);
    }
    LeaveCriticalSection(&g_lock);
}
static uint32_t guest_alloc_hi(uint32_t size, uint32_t align){
    EnterCriticalSection(&g_lock);
    if (align<16) align=16;
    uint32_t a=(g_heap_hi-((size+15)&~15u))&~(align-1);
    g_heap_hi=a;
    LeaveCriticalSection(&g_lock);
    { static int lg=-1; if(lg<0) lg=getenv("PS3_ALLOCLOG")?1:0;
      if(lg) fprintf(stderr,"[alloc-hi] 0x%x +0x%x = [0x%x,0x%x) fn=sub_%x t%llu\n",
                     a,size,a,a+size,g_curfn,(unsigned long long)t_gid); }
    return a;
}

typedef struct { uint32_t key; CRITICAL_SECTION cs; CONDITION_VARIABLE cv; int used;
                 DWORD owner; int depth; } SyncObj;
enum { NSYNC = 4096, NSYNCH = 16384 };
static SyncObj g_sync[NSYNC];
static int g_nsync;
static SyncObj* volatile g_sync_h[NSYNCH];

static SyncObj* sync_get(uint32_t key){
    uint32_t h=(key*2654435761u)>>18;
    for(uint32_t i=0;i<NSYNCH;i++){
        SyncObj* s=g_sync_h[(h+i)&(NSYNCH-1)];
        if(!s) break;
        if(s->key==key) return s;
    }
    EnterCriticalSection(&g_lock);
    SyncObj* s=0; uint32_t slot=0; int found=0;
    for(uint32_t i=0;i<NSYNCH;i++){
        slot=(h+i)&(NSYNCH-1);
        s=g_sync_h[slot];
        if(!s) break;
        if(s->key==key){ found=1; break; }
    }
    if(!found){
        s=0;
        if(g_nsync<NSYNC){
            s=&g_sync[g_nsync++];
            s->key=key; s->owner=0; s->depth=0;
            InitializeCriticalSection(&s->cs); InitializeConditionVariable(&s->cv);
            s->used=1;
            InterlockedExchangePointer((PVOID volatile*)&g_sync_h[slot],s);
        }
    }
    LeaveCriticalSection(&g_lock);
    return s;
}

typedef struct { uint32_t code,toc,arg,stacktop; uint64_t id; } ThreadStart;
typedef struct { uint64_t id; HANDLE h; uint64_t retval; } ThreadRec;
enum { NTHREAD = 256 };
static ThreadRec g_threads[NTHREAD];
static int g_nthreads=0;
static uint64_t g_next_tid=2;
static __declspec(thread) jmp_buf t_exit;
static __declspec(thread) uint64_t t_retval;
static __declspec(thread) int t_inthread=0;

static DWORD WINAPI thread_tramp(LPVOID p){
    ThreadStart ts=*(ThreadStart*)p; free(p);
    PPUContext* ctx=(PPUContext*)calloc(1,sizeof(PPUContext));
    ctx->r[1]=ts.stacktop; ctx->r[2]=ts.toc; ctx->r[3]=ts.arg;
    uint32_t blk=guest_alloc_hi(0x10000,0x1000); ctx->r[13]=blk+0x7000;
    t_inthread=1; t_retval=0; t_gid=ts.id;
    { long i=InterlockedIncrement(&g_nctxreg)-1;
      if(i<64){ g_ctxreg[i].tid=ts.id; g_ctxreg[i].ctx=ctx; g_ctxreg[i].htid=GetCurrentThreadId(); } }
    ppumon_register(ts.id);
    if (setjmp(t_exit)==0){
        PPCFunc f=ppu_lookup(ts.code);
        if (f) f(ctx, g_base);
        t_retval=ctx->r[3];
    }
    EnterCriticalSection(&g_lock);
    for (int i=0;i<g_nthreads;i++) if (g_threads[i].id==ts.id) g_threads[i].retval=t_retval;
    LeaveCriticalSection(&g_lock);
    { long nc=g_nctxreg; if(nc>64) nc=64;
      for(long i=0;i<nc;i++) if(g_ctxreg[i].ctx==ctx) g_ctxreg[i].ctx=0; }
    ppumon_unregister();
    free(ctx);
    return 0;
}

#define IS(s) (strcmp(name,(s))==0)
#define R(n)  (ctx->r[n])

static uint64_t join_thread(uint64_t id){
    HANDLE h=0; uint64_t rv=0;
    EnterCriticalSection(&g_lock);
    for(int i=0;i<g_nthreads;i++) if(g_threads[i].id==id){h=g_threads[i].h;break;}
    LeaveCriticalSection(&g_lock);
    if(h){
        DWORD w;
        int warned=0;
        while((w=WaitForSingleObject(h,10000))==WAIT_TIMEOUT){
            if(!warned++) fprintf(stderr,"[join] id=%llu slow (still running) - waiting\n",
                                  (unsigned long long)id);
        }
    }
    EnterCriticalSection(&g_lock);
    for(int i=0;i<g_nthreads;i++) if(g_threads[i].id==id){
        rv=g_threads[i].retval; if(h) CloseHandle(h);
        g_threads[i].h=0; g_threads[i].id=0; break; }
    LeaveCriticalSection(&g_lock);
    return rv;
}

static int thread_create(PPUContext* ctx){
    uint32_t idp=(uint32_t)R(3), opd=(uint32_t)R(4), arg=(uint32_t)R(5), stk=(uint32_t)R(7);
    if (stk<0x10000) stk=0x10000;
    uint32_t code=PPU_LW(g_base,opd), toc=PPU_LW(g_base,opd+4);
    if (code<0x10000 || code>=g_size){
        uint32_t inner=PPU_LW(g_base,opd); code=PPU_LW(g_base,inner); toc=PPU_LW(g_base,inner+4);
    }
    uint32_t stackbase=guest_alloc_hi(stk,0x1000);
    ThreadStart* ts=(ThreadStart*)malloc(sizeof(ThreadStart));
    EnterCriticalSection(&g_lock);
    uint64_t id=g_next_tid++;
    ts->code=code; ts->toc=toc; ts->arg=arg; ts->stacktop=stackbase+stk-0x200; ts->id=id;
    HANDLE h=CreateThread(0,0,thread_tramp,ts,0,0);
    int slot=-1;
    for (int i=0;i<g_nthreads;i++) if (!g_threads[i].id){ slot=i; break; }
    if (slot<0 && g_nthreads<NTHREAD) slot=g_nthreads++;
    if (slot>=0){ g_threads[slot].id=id; g_threads[slot].h=h; g_threads[slot].retval=0; }
    LeaveCriticalSection(&g_lock);
    if (slot<0) fprintf(stderr,"[thread] table FULL (%d): id=%llu is not joinable\n",NTHREAD,(unsigned long long)id);
    if (idp) PPU_STD(g_base, idp, id);
    fprintf(stderr,"[thread] create id=%llu code=0x%x toc=0x%x\n",(unsigned long long)id,code,toc);
    return 0;
}

#define CELL_FS_O_RDONLY 0x0000
#define CELL_FS_O_WRONLY 0x0001
#define CELL_FS_O_RDWR   0x0002
#define CELL_FS_O_ACCMODE 0x0003
#define CELL_FS_O_CREAT  0x0100
#define CELL_FS_O_EXCL   0x0200
#define CELL_FS_O_TRUNC  0x0400
#define CELL_FS_O_APPEND 0x0008
#define CELL_FS_OK     0
#define CELL_FS_ENOENT 0x80010006u
#define CELL_FS_EBADF  0x8001000Au
#define CELL_FS_EINVAL 0x80010002u

#define CELL_FS_TYPE_UNKNOWN   0
#define CELL_FS_TYPE_DIRECTORY 1
#define CELL_FS_TYPE_REGULAR   2
#define CELL_FS_S_IFDIR 0040000
#define CELL_FS_S_IFREG 0100000

typedef struct {
    int    used;
    int    is_dir;
    FILE*  fp;
    HANDLE find;
    WIN32_FIND_DATAA pend;
    int    have_pend;
    char   name[48];
    int    is_pac;
} FsFd;
static FsFd g_fsfd[256];
static char g_fs_root[512] = "";

static const char* fs_root(void){
    if(g_fs_root[0]) return g_fs_root;
    const char* e=getenv("PS3_FS_ROOT");
    if(e&&*e){ snprintf(g_fs_root,sizeof g_fs_root,"%s",e); return g_fs_root; }
    { char dir[MAX_PATH]; DWORD k=GetModuleFileNameA(NULL,dir,MAX_PATH);
      char* s=(k&&k<MAX_PATH)?strrchr(dir,'\\'):NULL;
      if(s){ *s=0; snprintf(g_fs_root,sizeof g_fs_root,"%s\\game\\USRDIR",dir);
             DWORD a=GetFileAttributesA(g_fs_root);
             if(a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_DIRECTORY)) return g_fs_root; } }
    snprintf(g_fs_root,sizeof g_fs_root,"%s","./vfs");
    return g_fs_root;
}
static void fs_guest_str(uint8_t* base, uint32_t ea, char* out, size_t n){
    size_t i=0; for(; i+1<n && ea+i<g_size; i++){ char c=(char)base[ea+i]; if(!c) break; out[i]=c; }
    out[i]=0;
}
static void fs_host_path(uint8_t* base, uint32_t pathea, char* out, size_t n){
    char g[512]; fs_guest_str(base,pathea,g,sizeof g);
    static const char* pre[] = {
        "/dev_hdd0/game/NPUB31347/USRDIR",
        "/dev_hdd0/game/NPUB31347",
        "/dev_bdvd/PS3_GAME/USRDIR",
        "/dev_bdvd/PS3_GAME",
        "/dev_bdvd",
        "/app_home/PS3_GAME/USRDIR",
        "/app_home/PS3_GAME",
        "/app_home",
        "/host_root",
        0
    };
    const char* p=g;
    for(int i=0;pre[i];i++){
        size_t L=strlen(pre[i]);
        if(!strncmp(g,pre[i],L) && (g[L]=='/'||g[L]==0)){ p=g+L; break; }
    }
    if(*p=='/') p++;
    snprintf(out,n,"%s/%s",fs_root(),p);
}
static int fs_alloc_fd(void){
    for(int i=3;i<256;i++) if(!g_fsfd[i].used) return i;
    return -1;
}
static const char* fs_fopen_mode(int flags){
    int acc=flags&CELL_FS_O_ACCMODE;
    if(flags&CELL_FS_O_APPEND) return (acc==CELL_FS_O_RDWR)?"a+b":"ab";
    if(flags&CELL_FS_O_CREAT){
        if(flags&CELL_FS_O_TRUNC) return (acc==CELL_FS_O_RDWR)?"w+b":"wb";
        return (acc==CELL_FS_O_RDONLY)?"rb":"r+b";
    }
    if(acc==CELL_FS_O_RDONLY) return "rb";
    return "r+b";
}
static uint32_t fs_open(uint8_t* base, uint32_t pathea, int flags, uint32_t fd_ea){
    char host[640]; fs_host_path(base,pathea,host,sizeof host);
    const char* mode=fs_fopen_mode(flags);
    if(!mode) return CELL_FS_EINVAL;
    FILE* fp=fopen(host,mode);
    if(!fp && (flags&CELL_FS_O_CREAT) && !(flags&CELL_FS_O_TRUNC))
        fp=fopen(host,(flags&CELL_FS_O_ACCMODE)==CELL_FS_O_RDONLY?"rb":"w+b");
    if(!fp){ fprintf(stderr,"[FS] open FAIL '%s' (flags=0x%x)\n",host,flags); return CELL_FS_ENOENT; }
    int fd=fs_alloc_fd();
    if(fd<0){ fclose(fp); return CELL_FS_EBADF; }
    g_fsfd[fd].fp=fp; g_fsfd[fd].used=1;
    { const char* bn=strrchr(host,'/'); bn=bn?bn+1:host;
      snprintf(g_fsfd[fd].name,sizeof g_fsfd[fd].name,"%s",bn);
      size_t L=strlen(bn);
      g_fsfd[fd].is_pac = (L>4 && (!strcmp(bn+L-4,".PAC")||!strcmp(bn+L-4,".pac"))); }
    if(fd_ea) PPU_STW(base,fd_ea,(uint32_t)fd);
    MTRC(MTRC_FS_OPEN,(uint32_t)fd,(uint32_t)flags,0,0,g_fsfd[fd].name);
    fprintf(stderr,"[FS] open '%s' -> fd %d\n",host,fd);
    return CELL_FS_OK;
}

static void fs_put_stat(uint8_t* base, uint32_t statea, const struct _stat64* st){
    uint32_t mode = ((st->st_mode & _S_IFDIR)?CELL_FS_S_IFDIR:CELL_FS_S_IFREG) | 0777;
    PPU_STW(base,statea+0, mode);
    PPU_STW(base,statea+4, 0);
    PPU_STW(base,statea+8, 0);
    PPU_STD(base,statea+12,(uint64_t)st->st_atime);
    PPU_STD(base,statea+20,(uint64_t)st->st_mtime);
    PPU_STD(base,statea+28,(uint64_t)st->st_ctime);
    PPU_STD(base,statea+36,(uint64_t)st->st_size);
    PPU_STD(base,statea+44,(uint64_t)512);
}
static uint32_t fs_stat(uint8_t* base, uint32_t pathea, uint32_t statea){
    char host[640]; fs_host_path(base,pathea,host,sizeof host);
    struct _stat64 st;
    if(_stat64(host,&st)!=0){ fprintf(stderr,"[FS] stat FAIL '%s'\n",host); return CELL_FS_ENOENT; }
    fprintf(stderr,"[FS] stat '%s' size=%lld\n",host,(long long)st.st_size);
    fs_put_stat(base,statea,&st); return CELL_FS_OK;
}
static uint32_t fs_fstat(uint8_t* base, int fd, uint32_t statea){
    if(fd<0||fd>=256||!g_fsfd[fd].used||!g_fsfd[fd].fp) return CELL_FS_EBADF;
    struct _stat64 st;
    if(_fstat64(_fileno(g_fsfd[fd].fp),&st)!=0) return CELL_FS_EBADF;
    fs_put_stat(base,statea,&st); return CELL_FS_OK;
}
static uint32_t fs_opendir(uint8_t* base, uint32_t pathea, uint32_t fd_ea){
    char host[640]; fs_host_path(base,pathea,host,sizeof host);
    char glob[700]; snprintf(glob,sizeof glob,"%s/*",host);
    WIN32_FIND_DATAA fd_data; HANDLE h=FindFirstFileA(glob,&fd_data);
    if(h==INVALID_HANDLE_VALUE){ fprintf(stderr,"[FS] opendir FAIL '%s'\n",host); return CELL_FS_ENOENT; }
    int fd=fs_alloc_fd();
    if(fd<0){ FindClose(h); return CELL_FS_EBADF; }
    g_fsfd[fd].used=1; g_fsfd[fd].is_dir=1; g_fsfd[fd].find=h;
    g_fsfd[fd].pend=fd_data; g_fsfd[fd].have_pend=1;
    if(fd_ea) PPU_STW(base,fd_ea,(uint32_t)fd);
    fprintf(stderr,"[FS] opendir '%s' -> fd %d\n",host,fd);
    return CELL_FS_OK;
}
static uint32_t fs_readdir(uint8_t* base, int fd, uint32_t dirent_ea, uint32_t nread_ea){
    if(fd<0||fd>=256||!g_fsfd[fd].used||!g_fsfd[fd].is_dir) return CELL_FS_EBADF;
    FsFd* d=&g_fsfd[fd];
    if(!d->have_pend){ if(nread_ea) PPU_STD(base,nread_ea,0); return CELL_FS_OK; }
    const char* nm=d->pend.cFileName;
    uint8_t type=(d->pend.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)?CELL_FS_TYPE_DIRECTORY:CELL_FS_TYPE_REGULAR;
    size_t nl=strlen(nm); if(nl>255) nl=255;
    PPU_STB(base,dirent_ea+0,type);
    PPU_STB(base,dirent_ea+1,(uint8_t)nl);
    for(size_t i=0;i<nl;i++) PPU_STB(base,dirent_ea+2+(uint32_t)i,(uint8_t)nm[i]);
    PPU_STB(base,dirent_ea+2+(uint32_t)nl,0);
    if(nread_ea) PPU_STD(base,nread_ea,258);
    if(!FindNextFileA(d->find,&d->pend)) d->have_pend=0;
    return CELL_FS_OK;
}
static uint32_t fs_closedir(int fd){
    if(fd<0||fd>=256||!g_fsfd[fd].used||!g_fsfd[fd].is_dir) return CELL_FS_EBADF;
    FindClose(g_fsfd[fd].find);
    g_fsfd[fd].used=0; g_fsfd[fd].is_dir=0; g_fsfd[fd].find=0; g_fsfd[fd].have_pend=0;
    return CELL_FS_OK;
}
static void fs_cleanup(void){
    int leaked=0;
    for(int i=3;i<256;i++){
        if(!g_fsfd[i].used) continue;
        if(g_fsfd[i].is_dir){ if(g_fsfd[i].find) FindClose(g_fsfd[i].find); }
        else if(g_fsfd[i].fp){ fclose(g_fsfd[i].fp); }
        g_fsfd[i].used=0; leaked++;
    }
    if(leaked) fprintf(stderr,"[FS] cleanup: closed %d leaked fd(s)\n",leaked);
}

static void (*spu_body_for(uint32_t entry))(SPUContext*){
    for (unsigned i=0;i<g_spu_nbodies;i++)
        if (g_spu_bodies[i].entry==entry) return g_spu_bodies[i].fn;
    return 0;
}
extern void spu_job_4291da02_full(SPUContext*);
extern void spu_job_42a86002_full(SPUContext*);
extern void spu_job_42990002_full(SPUContext*);
extern void spu_job_429d1e02_full(SPUContext*);
extern const uint8_t spu_job_4291da02_img[]; extern const uint32_t spu_job_4291da02_img_len;
extern const uint8_t spu_job_42a86002_img[]; extern const uint32_t spu_job_42a86002_img_len;
extern const uint8_t spu_job_42990002_img[]; extern const uint32_t spu_job_42990002_img_len;
extern const uint8_t spu_job_429d1e02_img[]; extern const uint32_t spu_job_429d1e02_img_len;

typedef struct {
    const char*    name;
    const uint8_t* img;
    uint32_t       img_base;
    uint32_t       lift_base, size;
    SpuBodyFn      fn;
} SpuRelocJob;
static const SpuRelocJob g_reloc_jobs[] = {
    {"4291da02", spu_job_4291da02_img, 0x0a800, 0x3d000, 0x0aa0, spu_job_4291da02_full},
    {"429d1e02", spu_job_429d1e02_img, 0x1fc00, 0x3e000, 0x0fa0, spu_job_429d1e02_full},
};
#define N_RELOC_JOBS (sizeof g_reloc_jobs / sizeof g_reloc_jobs[0])

static uint32_t jobimg_diff(const uint8_t* st, const uint8_t* ref,
                            uint32_t lo, uint32_t hi, uint32_t delta, uint32_t delta2){
    for (uint32_t o = lo; o < hi; ){
        if (st[o] == ref[o]){ o++; continue; }
        uint32_t w = o & ~3u;
        if (w >= lo && w + 4 <= hi){
            uint32_t a = (uint32_t)st[w]<<24|st[w+1]<<16|st[w+2]<<8|st[w+3];
            uint32_t b = (uint32_t)ref[w]<<24|ref[w+1]<<16|ref[w+2]<<8|ref[w+3];
            if (delta && a == b + delta){ o = w + 4; continue; }
            if (delta2 && a == b + delta2){ o = w + 4; continue; }
        }
        return o;
    }
    return 0xffffffffu;
}
static struct { const uint8_t* ls; uint32_t base, moff; } g_reloc_miss[N_RELOC_JOBS];

static int reloc_verify(unsigned ji, const SpuRelocJob* j, uint32_t b, const uint8_t* ls){
    uint32_t n = j->size;
    uint32_t d1 = b - j->img_base, d2 = b;
    if (g_reloc_miss[ji].ls == ls && g_reloc_miss[ji].base == b){
        uint32_t o = g_reloc_miss[ji].moff & ~3u;
        uint32_t e = o + 16 <= n ? o + 16 : n;
        if (jobimg_diff(ls + b, j->img, o, e, d1, d2) != 0xffffffffu) return 0;
    }
    uint32_t bad = n < 0x20 ? jobimg_diff(ls+b, j->img, 0, n, 0, 0)
                            : jobimg_diff(ls+b, j->img, 0, 0x20, 0, 0);
    if (bad == 0xffffffffu && n > 0x70)
        bad = jobimg_diff(ls + b, j->img, 0x60, n - 0x10, d1, d2);
    if (bad != 0xffffffffu){
        g_reloc_miss[ji].ls = ls; g_reloc_miss[ji].base = b; g_reloc_miss[ji].moff = bad;
        return 0;
    }
    if (g_reloc_miss[ji].ls == ls && g_reloc_miss[ji].base == b) g_reloc_miss[ji].ls = 0;
    return 1;
}

static uint32_t reloc_find_base(unsigned ji, const SpuRelocJob* j, uint32_t pc, const uint8_t* ls){
    if (pc >= 0x32000u) return 0;
    for (uint32_t b = pc & ~0x3ffu; pc - b < j->size; b -= 0x400u){
        if (memcmp(ls + b, j->img, 16) == 0 && reloc_verify(ji, j, b, ls)) return b;
        if (b < 0x4c00u) break;
    }
    return 0;
}
int spu_reloc_hit(uint32_t pc, const uint8_t* ls){
    for (unsigned i = 0; i < N_RELOC_JOBS; i++)
        if (reloc_find_base(i, &g_reloc_jobs[i], pc, ls)) return 1;
    return 0;
}
static void reloc_run(int idx, SPUContext* c){
    const SpuRelocJob* j = &g_reloc_jobs[idx];
    uint32_t b = reloc_find_base((unsigned)idx, j, c->pc, (const uint8_t*)c->ls);
    if (!b){ spu_interp(c); return; }
    { static volatile long nrd; long k = InterlockedIncrement(&nrd);
      if (k <= 32 || (k % 4096) == 0)
          fprintf(stderr, "[SPU-RELOC] %lu %s base=0x%x pc=0x%x (n=%ld)\n",
                  (unsigned long)GetTickCount(), j->name, b, c->pc, k); }
    { int32_t d = (int32_t)(b - j->lift_base);
      c->pc      = (uint32_t)((int32_t)c->pc - d);
      c->pc_bias = d;
      j->fn(c);
      c->pc_bias = 0;
      if (c->pc >= j->lift_base && c->pc <= j->lift_base + j->size)
          c->pc = (uint32_t)((int32_t)c->pc + d);
      if (c->pc < 0x400u){
          static volatile long nbad;
          if (InterlockedIncrement(&nbad) <= 16)
              fprintf(stderr,"[SPU-RELOC] %s BAD EXIT pc=0x%x (base=0x%x "
                      "lift=0x%x d=%d r0=0x%x r3=0x%x) - lifted body left pc in "
                      "the reserved area; the SPU is about to stop-0 and the "
                      "machine will hang\n",
                      j->name, c->pc, b, j->lift_base, (int)d,
                      (unsigned)c->r[0].w[0], (unsigned)c->r[3].w[0]);
      } }
}
static void reloc_run_0(SPUContext* c){ reloc_run(0, c); }
static void reloc_run_1(SPUContext* c){ reloc_run(1, c); }
static const SpuBodyFn g_reloc_fns[] = { reloc_run_0, reloc_run_1 };

#define JOBFP_LEN 0x12c
#define JOBFP_N   128
static struct { const uint8_t* ls; uint32_t base, neg_ea; void* fn; uint8_t fp[JOBFP_LEN]; } g_jobfp[JOBFP_N];
static unsigned g_jobfp_next;
static void jobfp_read(const uint8_t* ls, uint32_t base, uint8_t* fp){
    memcpy(fp,        ls + base,        0x20);
    memcpy(fp + 0x20, ls + base + 0x30, 0x0c);
    memcpy(fp + 0x2c, ls + base + 0x60, 0x100);
}
int spu_jobbody_verify(void (*fn)(SPUContext*), const uint8_t* ls, uint32_t base){
    uint32_t ea = 0, code_end = 0;
    for (unsigned i = 0; i < g_spu_njob_guest; i++)
        if (g_spu_job_guest[i].fn == fn){ ea = g_spu_job_guest[i].ea;
                                          code_end = g_spu_job_guest[i].code_end; break; }
    if (!ea) return 1;
    if (base + 0x160 > 0x40000 || memcmp(ls + base + 0x30, "JOBCRT", 6) != 0) return 1;
    {
        uint8_t fp[JOBFP_LEN]; jobfp_read(ls, base, fp);
        int neg = 0;
        for (unsigned i = 0; i < JOBFP_N; i++){
            if (g_jobfp[i].ls != ls || g_jobfp[i].base != base ||
                memcmp(g_jobfp[i].fp, fp, JOBFP_LEN) != 0) continue;
            if (g_jobfp[i].fn) return g_jobfp[i].fn == (void*)fn;
            if (g_jobfp[i].neg_ea == ea) neg = 1;
        }
        if (neg) return 0;
    }
    uint32_t img = (uint32_t)ls[base+0x40]<<24 | ls[base+0x41]<<16 | ls[base+0x42]<<8 | ls[base+0x43];
    uint32_t head = img > base && img - base <= 0x30000 ? img - base
                  : img <= 0x30000 ? img : 0;
    if (head < 0x80 || base + head > 0x40000) return 1;
    {   uint32_t gt = (uint32_t)g_base[ea+0x3c]<<24 | g_base[ea+0x3d]<<16 |
                      g_base[ea+0x3e]<<8 | g_base[ea+0x3f];
        uint32_t gi = (uint32_t)g_base[ea+0x40]<<24 | g_base[ea+0x41]<<16 |
                      g_base[ea+0x42]<<8 | g_base[ea+0x43];
        if (gi >= 0x80 && gi <= gt && gt <= 0x30000 && head > gi) head = gi;
        else if (gt >= 0x80 && gt <= 0x30000 && head > gt) head = gt; }
    if (code_end >= 0x80 && head > code_end + 0x10) head = code_end + 0x10;
    if ((uint64_t)ea + head > g_size) return 0;
    {
        int ok = memcmp(ls + base, g_base + ea, 0x20) == 0 &&
                 jobimg_diff(ls + base, g_base + ea, 0x60, head - 0x10, base, base) == 0xffffffffu;
        uint8_t fp[JOBFP_LEN]; jobfp_read(ls, base, fp);
        int dup = 0;
        for (unsigned i = 0; i < JOBFP_N; i++)
            if (g_jobfp[i].ls == ls && g_jobfp[i].base == base &&
                memcmp(g_jobfp[i].fp, fp, JOBFP_LEN) == 0 &&
                (ok ? g_jobfp[i].fn == (void*)fn : g_jobfp[i].neg_ea == ea)){ dup = 1; break; }
        if (!dup){
            unsigned s = (g_jobfp_next++) % JOBFP_N;
            g_jobfp[s].fn = 0; g_jobfp[s].neg_ea = 0;
            g_jobfp[s].ls = ls; g_jobfp[s].base = base;
            memcpy(g_jobfp[s].fp, fp, JOBFP_LEN);
            if (ok) g_jobfp[s].fn = (void*)fn; else g_jobfp[s].neg_ea = ea;
        }
        return ok;
    }
}

typedef struct { SpuBodyFn fn; uint32_t ea, img_off, ls_addr, len; } SpuElfBody;
extern void spu_task_a(SPUContext*);
extern void spu_auto_d3a180(SPUContext*);
extern void spu_auto_d42600(SPUContext*);
static const SpuElfBody g_elf_bodies[] = {
    { spu_task_a,      0xd3a180u, 0x100+0x4000, 0x7000, 0x100 },
    { spu_auto_d3a180, 0xd3a180u, 0x100+0x4000, 0x7000, 0x100 },
    { spu_auto_d42600, 0xd42600u, 0x100+0x4000, 0x7000, 0x100 },
};
static int spu_elfbody_ok(SpuBodyFn fn, const uint8_t* ls){
    { static int on=-1;
      if(on<0){ const char* e=getenv("PS3_SPUELF"); on=(e&&e[0]=='0')?0:1; }
      if(!on) return 1; }
    for (unsigned i = 0; i < sizeof g_elf_bodies / sizeof g_elf_bodies[0]; i++){
        const SpuElfBody* b = &g_elf_bodies[i];
        if (b->fn != fn) continue;
        if ((uint64_t)b->ea + b->img_off + b->len > g_size) return 1;
        if (PPU_LW(g_base, b->ea) != 0x7f454c46u) return 1;
        if (b->ls_addr + b->len > 0x40000) return 1;
        if (!memcmp(ls + b->ls_addr, g_base + b->ea + b->img_off, b->len)) return 1;
        { static volatile long n; long k = InterlockedIncrement(&n);
          if (k <= 8 || (k % 4096) == 0)
              fprintf(stderr, "[SPU-ELF] rejected lift of 0x%x - resident image "
                      "differs at LS 0x%x (n=%ld)\n", b->ea, b->ls_addr, k); }
        return 0;
    }
    return 1;
}

typedef struct { SpuBodyFn fn; uint32_t ea, ls_addr, len; } SpuRawBody;
extern void spu_run_jq_8000(SPUContext*);
static const SpuRawBody g_raw_bodies[] = {
    { spu_run_jq_8000, 0x1e80e800u, 0x8000, 0x490 },
};
static int spu_rawbody_ok(SpuBodyFn fn, const uint8_t* ls){
    for (unsigned i = 0; i < sizeof g_raw_bodies / sizeof g_raw_bodies[0]; i++){
        const SpuRawBody* b = &g_raw_bodies[i];
        if (b->fn != fn) continue;
        if ((uint64_t)b->ea + b->len > g_size || b->ls_addr + b->len > 0x40000) return 0;
        return memcmp(ls + b->ls_addr, g_base + b->ea, b->len) == 0;
    }
    return 1;
}

static uint32_t g_body_hi[256];
static uint32_t spu_body_hi(unsigned i){
    if (i < 256 && g_body_hi[i]) return g_body_hi[i];
    const SpuBody* b = &g_spu_bodies[i];
    uint32_t lo = b->range[0], hi = b->range[1];
    for (unsigned k = 0; k < g_spu_njob_guest; k++){
        if (g_spu_job_guest[k].fn != b->fn) continue;
        uint32_t ea = g_spu_job_guest[k].ea;
        if ((uint64_t)ea + 0x44 > g_size || memcmp(g_base + ea + 0x30, "JOBCRT", 6)) break;
        uint32_t tot = PPU_LW(g_base, ea + 0x3c), img = PPU_LW(g_base, ea + 0x40);
        if (img >= 0x80 && img <= tot && tot <= 0x40000 && lo + img < hi) hi = lo + img;
        break;
    }
    uint32_t frame = 0x40000;
    for (unsigned r = 0; r < N_RELOC_JOBS; r++)
        if (g_reloc_jobs[r].lift_base < frame) frame = g_reloc_jobs[r].lift_base;
    if (lo < frame && hi > frame) hi = frame;
    if (i < 256) g_body_hi[i] = hi;
    return hi;
}
static uint32_t g_body_ea[256];
static uint32_t spu_body_ea(unsigned i){
    if (i < 256 && g_body_ea[i]) return g_body_ea[i] == 1 ? 0 : g_body_ea[i];
    uint32_t ea = 0;
    for (unsigned k = 0; k < g_spu_njob_guest; k++)
        if (g_spu_job_guest[k].fn == g_spu_bodies[i].fn){ ea = g_spu_job_guest[k].ea; break; }
    if (i < 256) g_body_ea[i] = ea ? ea : 1;
    return ea;
}
static int spu_job_staged_inside(unsigned i, uint32_t base, uint32_t pc, const uint8_t* ls){
    uint32_t ea = spu_body_ea(i);
    if (!ea) return 0;
    for (uint32_t s = base + 0x400; s <= pc && s + 0x36 <= 0x40000; s += 0x400){
        if (memcmp(ls + s + 0x30, "JOBCRT", 6) != 0) continue;
        uint64_t own = (uint64_t)ea + (s - base) + 0x30;
        if (own + 6 <= g_size && memcmp(g_base + own, "JOBCRT", 6) == 0) continue;
        return 1;
    }
    return 0;
}
int spu_body_accept(unsigned i, uint32_t pc, const uint8_t* ls){
    const SpuBody* b = &g_spu_bodies[i];
    if (!b->range || pc < b->range[0] || pc >= spu_body_hi(i)) return 0;
    if (!b->sig || !b->sig_at || memcmp(ls + *b->sig_at, b->sig, 16) != 0) return 0;
    if (b->entry == b->range[0] && spu_job_staged_inside(i, b->range[0], pc, ls)) return 0;
    if (b->entry == b->range[0] && !spu_jobbody_verify(b->fn, ls, b->range[0])) return 0;
    if (!spu_elfbody_ok(b->fn, ls)) return 0;
    if (!spu_rawbody_ok(b->fn, ls)) return 0;
    return 1;
}
extern void spu_job_c8cb80(SPUContext*);
extern void spu_job_c8cb80_s5c00(SPUContext*);
static int is_c8cb80(SpuBodyFn fn){ return fn == spu_job_c8cb80 || fn == spu_job_c8cb80_s5c00; }

static SpuBodyFn spu_resolve(uint32_t pc, const uint8_t* ls){
    for (unsigned ri = 0; ri < N_RELOC_JOBS; ri++)
        if (reloc_find_base(ri, &g_reloc_jobs[ri], pc, ls)) return g_reloc_fns[ri];
    for (unsigned i=0;i<g_spu_nbodies;i++){
        if (!spu_body_accept(i, pc, ls)) continue;
        {
            { static uint32_t seen[64][2]; static int ns; int f=0;
              for(int k=0;k<ns;k++) if(seen[k][0]==i&&seen[k][1]==pc){f=1;break;}
              if(!f&&ns<64){ seen[ns][0]=i; seen[ns][1]=pc; ns++;
                  fprintf(stderr,"[SPU-RES] %lu body#%u entry=0x%x pc=0x%x\n",
                          (unsigned long)GetTickCount(),i,g_spu_bodies[i].entry,pc); } }
            static int fspac=-1;
            if (fspac<0) fspac=getenv("PS3_FSPAC")?1:0;
            if (g_spu_bodies[i].entry==0x4c00 && fspac){
                static volatile long njd; long k=InterlockedIncrement(&njd);
                if (k<=512 || (k%64)==0){
                    const uint8_t* a=ls+0x80;
                    fprintf(stderr,"[PAC1] %lu dispatch #%ld pc=0x%x ls80=%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
                            (unsigned long)GetTickCount(),k,pc,
                            a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
                            a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15],
                            a[16],a[17],a[18],a[19],a[20],a[21],a[22],a[23],
                            a[24],a[25],a[26],a[27],a[28],a[29],a[30],a[31]);
                }
            }
            if (pc==0x3050){
                static volatile long ntd; long k=InterlockedIncrement(&ntd);
                if (k<=24){
                    const uint8_t* a80=ls+0x80;
                    fprintf(stderr,"[TASK] %lu dispatch #%ld ls80=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                            (unsigned long)GetTickCount(),k,
                            a80[0],a80[1],a80[2],a80[3],a80[4],a80[5],a80[6],a80[7],
                            a80[8],a80[9],a80[10],a80[11],a80[12],a80[13],a80[14],a80[15]);
                }
            }
            {
                extern void spu_job_c8cb80(SPUContext*);
                static int gate=-1;
                if (gate<0){ const char* e=getenv("PS3_C8GATE"); gate=(e&&*e=='0')?0:1; }
                if (gate && is_c8cb80(g_spu_bodies[i].fn)){
                    uint32_t need=0;
                    for (int slot=0; slot<2; slot++){
                        const uint8_t* row = ls + 0x3f500 + slot*0x100;
                        uint32_t jea = (uint32_t)row[4]<<24|row[5]<<16|row[6]<<8|row[7];
                        if (jea != 0x00c8cb80u) continue;
                        uint32_t srcA=(uint32_t)row[0x3c]<<24|row[0x3d]<<16|row[0x3e]<<8|row[0x3f];
                        uint32_t szB =(uint32_t)row[0x40]<<24|row[0x41]<<16|row[0x42]<<8|row[0x43];
                        uint32_t srcB=(uint32_t)row[0x44]<<24|row[0x45]<<16|row[0x46]<<8|row[0x47];
                        if (srcA<0x38000000u || srcA>=0x39000000u) continue;
                        if (srcB+szB>need) need=srcB+szB;
                    }
                    if (need && (uint32_t)g_c8_hiwater<need && g_c8_gate_budget>0){
                        static volatile long ng; long gk=InterlockedIncrement(&ng);
                        if (gk<=8 || (gk%1024)==0)
                            fprintf(stderr,"[C8GATE] %lu wait fill: need 0x%x hiwater 0x%x (n=%ld)\n",
                                    (unsigned long)GetTickCount(),need,
                                    (uint32_t)g_c8_hiwater,gk);
                        while ((uint32_t)g_c8_hiwater<need){
                            Sleep(2);
                            if (InterlockedExchangeAdd(&g_c8_gate_budget,-2)<=2){
                                fprintf(stderr,"[C8GATE] budget exhausted, running unfilled\n");
                                break;
                            }
                        }
                    }
                }
            }
            {
                extern void spu_job_c8cb80(SPUContext*);
                static int ci=-1; if(ci<0) ci=getenv("PS3_C8INTERP")?1:0;
                if(ci==1 && is_c8cb80(g_spu_bodies[i].fn)) continue;
            }
            {
                extern void spu_job_c8cb80(SPUContext*);
                static int ct=-1; if(ct<0){ const char* e=getenv("PS3_C8TAB"); ct=e?atoi(e):0; }
                static long ctdone;
                if (ct==2 && g_spu_bodies[i].fn==spu_job_c8cb80){
                    uint8_t* lp=(uint8_t*)(uintptr_t)ls;
                    static const uint8_t mag[16]={0x3f,0x80,0,0, 0,0,0,0,
                                                  0x3f,0x80,0,0, 0x3f,0x80,0,0};
                    static const uint8_t z16[16]={0};
                    unsigned np=0;
                    for (uint32_t o=0x9280;o+16<=0x9560;o+=16)
                        if (!memcmp(lp+o,z16,16)){ memcpy(lp+o,mag,16); np++; }
                    static volatile long nd2; long kd2=InterlockedIncrement(&nd2);
                    if (kd2<=4 || (kd2%1024)==0)
                        fprintf(stderr,"[C8TAB] %lu mode2: %u zero rows filled (n=%ld)\n",
                                (unsigned long)GetTickCount(),np,kd2);
                }
                if (ct==1 && g_spu_bodies[i].fn==spu_job_c8cb80){
                    static const uint8_t lsig[12]={0x3f,0x0f,0x8f,0x90,0x3f,0x1b,0x9b,0x9c,
                                                   0x3f,0x22,0xa2,0xa3};
                    uint8_t* lst=(uint8_t*)(uintptr_t)(ls+0xa400);
                    if (!memcmp(lst+0x10,lsig,12)){
                        static const uint32_t loud2[6][3]={
                            {0x3f800000,0,0},{0,0x3f800000,0},{0,0,0x3f800000},
                            {0x3f800000,0x3f800000,0},{0x3f800000,0,0x3f800000},
                            {0,0x3f800000,0x3f800000}};
                        for (int r=0;r<6;r++){
                            for (int c2=0;c2<3;c2++){
                                uint32_t v=loud2[r][c2];
                                lst[r*16+c2*4]=(uint8_t)(v>>24); lst[r*16+c2*4+1]=(uint8_t)(v>>16);
                                lst[r*16+c2*4+2]=(uint8_t)(v>>8); lst[r*16+c2*4+3]=(uint8_t)v;
                            }
                            lst[r*16+12]=0x3f; lst[r*16+13]=0x80; lst[r*16+14]=0; lst[r*16+15]=0;
                        }
                        static volatile long nls; long kls=InterlockedIncrement(&nls);
                        if (kls<=4 || (kls%1024)==0)
                            fprintf(stderr,"[C8TAB] %lu LS table patched (n=%ld)\n",
                                    (unsigned long)GetTickCount(),kls);
                    }
                }
                if (ct==3 && g_spu_bodies[i].fn==spu_job_c8cb80){
                    uint8_t* lp=(uint8_t*)(uintptr_t)ls;
                    unsigned np=0;
                    for (uint32_t o=0x9280;o+16<=0xa460;o+=16){
                        uint32_t f[4]; int ok=1, nz=0;
                        for (int q=0;q<4;q++)
                            f[q]=(uint32_t)lp[o+q*4]<<24|lp[o+q*4+1]<<16|lp[o+q*4+2]<<8|lp[o+q*4+3];
                        for (int q=0;q<3;q++){
                            if (f[q]==0) continue;
                            if (f[q]>=0x3c000000u && f[q]<=0x40800000u) nz++;
                            else { ok=0; break; }
                        }
                        if (ok && nz && f[3]==0){
                            lp[o+12]=0x3f; lp[o+13]=0x80; lp[o+14]=0; lp[o+15]=0; np++;
                        }
                    }
                    static volatile long nd3; long kd3=InterlockedIncrement(&nd3);
                    if (kd3<=4 || (kd3%1024)==0)
                        fprintf(stderr,"[C8TAB] %lu mode3: %u lane3 repaired (n=%ld)\n",
                                (unsigned long)GetTickCount(),np,kd3);
                }
                if (ct==1 && g_spu_bodies[i].fn==spu_job_c8cb80 &&
                    InterlockedCompareExchange(&ctdone,1,0)==0){
                    static const uint8_t sig[16]={0x3f,0x0f,0x8f,0x90,0x3f,0x1b,0x9b,0x9c,
                                                  0x3f,0x22,0xa2,0xa3,0x00,0x00,0x00,0x00};
                    static const uint32_t loud[6][3]={
                        {0x3f800000,0,0},{0,0x3f800000,0},{0,0,0x3f800000},
                        {0x3f800000,0x3f800000,0},{0x3f800000,0,0x3f800000},
                        {0,0x3f800000,0x3f800000}};
                    unsigned nf=0;
                    for (uint64_t ea=0x36000000ull; ea+0x70<=0x39000000ull && ea+0x70<=g_size; ea+=16){
                        if (memcmp(g_base+ea+0x10, sig, 16)) continue;
                        uint8_t* tb=g_base+ea;
                        for (int r=0;r<6;r++){
                            for (int c2=0;c2<3;c2++){
                                uint32_t v=loud[r][c2];
                                tb[r*16+c2*4]=(uint8_t)(v>>24); tb[r*16+c2*4+1]=(uint8_t)(v>>16);
                                tb[r*16+c2*4+2]=(uint8_t)(v>>8); tb[r*16+c2*4+3]=(uint8_t)v;
                            }
                            tb[r*16+12]=0x3f; tb[r*16+13]=0x80; tb[r*16+14]=0; tb[r*16+15]=0;
                        }
                        fprintf(stderr,"[C8TAB] %lu repainted table at ea=0x%llx\n",
                                (unsigned long)GetTickCount(),(unsigned long long)ea);
                        nf++;
                    }
                    fprintf(stderr,"[C8TAB] %lu scan done: %u tables repainted\n",
                            (unsigned long)GetTickCount(),nf);
                }
            }
            {
                extern void spu_job_c8cb80(SPUContext*);
                static int c8on=-1; static unsigned clo=0x38cb0280u, clen=0x2aab00u;
                if (c8on<0){ const char* e=getenv("PS3_C8LOG");
                    if(e){ c8on=1; unsigned a,b;
                           if(sscanf(e,"%x:%x",&a,&b)==2){ clo=a; clen=b; } }
                    else c8on=0; }
                if (c8on==1 && g_spu_bodies[i].fn==spu_job_c8cb80){
                    static volatile long nc8; long k=InterlockedIncrement(&nc8);
                    if (k<=32 || (k%256)==0){
                        unsigned np=0, zc=0, zm=0, zz=0, off;
                        for(off=0; off+16<=clen; off+=16){
                            const uint8_t* p=g_base+clo+off; np++;
                            int c0 = (*(const uint64_t*)p==0);
                            int m0 = (*(const uint64_t*)(p+8)==0);
                            if(c0&&m0) zz++; else if(c0) zc++; else if(m0) zm++;
                        }
                        const uint8_t* pr=g_base+0xc91200u;
                        fprintf(stderr,"[C8LOG] %lu dispatch #%ld pc=0x%x in[0x%x+0x%x]: "
                                "pairs=%u zerocolor=%u zeromask=%u bothzero=%u params=",
                                (unsigned long)GetTickCount(),k,pc,clo,clen,np,zc,zm,zz);
                        for(int b2=0;b2<0x30;b2++) fprintf(stderr,"%02x",pr[b2]);
                        fprintf(stderr,"\n");
                    }
                }
            }
            return g_spu_bodies[i].fn;
        }
    }
    {
        static volatile long nfb; long k=InterlockedIncrement(&nfb);
        if (k<=16 || (k%4096)==0){
            fprintf(stderr,"[SPU-RES] %lu interp pc=0x%x ls[pc]=%02x%02x%02x%02x (n=%ld)\n",
                    (unsigned long)GetTickCount(), pc,
                    ls[pc&0x3ffff],ls[(pc+1)&0x3ffff],ls[(pc+2)&0x3ffff],ls[(pc+3)&0x3ffff], k);
        }
        { static uint32_t dumped[16]; static volatile long ndump;
          int seen=0; long nd=ndump;
          for(long i=0;i<nd&&i<16;i++) if(dumped[i]==pc) seen=1;
          if(!seen){ long slot=InterlockedIncrement(&ndump)-1;
              if(slot<16){ dumped[slot]=pc;
                  char fn[64]; snprintf(fn,sizeof fn,"logs/ls_%05x.bin",pc);
                  FILE* f=fopen(fn,"wb");
                  if(f){ fwrite(ls,1,0x40000,f); fclose(f);
                         fprintf(stderr,"[SPU-RES] LS dumped to %s\n",fn); } } } }
        if (pc + 0x44 <= 0x40000 && memcmp(ls + pc + 0x30, "JOBCRT", 6) == 0){
            uint32_t pw   = (uint32_t)ls[pc]<<24 | ls[pc+1]<<16 | ls[pc+2]<<8 | ls[pc+3];
            uint32_t htot = (uint32_t)ls[pc+0x3c]<<24 | ls[pc+0x3d]<<16 | ls[pc+0x3e]<<8 | ls[pc+0x3f];
            uint32_t himg = (uint32_t)ls[pc+0x40]<<24 | ls[pc+0x41]<<16 | ls[pc+0x42]<<8 | ls[pc+0x43];
            static uint32_t seenj[16]; static volatile long nj;
            int f2 = 0; long njc = nj;
            for (long i2 = 0; i2 < njc && i2 < 16; i2++) if (seenj[i2] == pw) f2 = 1;
            if (!f2){ long s2 = InterlockedIncrement(&nj) - 1;
                if (s2 < 16){ seenj[s2] = pw;
                    fprintf(stderr,"[SPU-RES] UNLIFTED JOBCRT job prologue=%08x base=0x%x "
                            "img=0x%x total=0x%x - running on interp; lift me\n",
                            pw, pc, himg, htot); } }
        }
    }
    return spu_interp;
}

static uint32_t spu_elf_load_ls(SpuThread* t, uint32_t ea){
    if (ea+0x34>g_size || PPU_LW(g_base,ea)!=0x7f454c46u) return 0;
    uint32_t entry=PPU_LW(g_base,ea+0x18), phoff=PPU_LW(g_base,ea+0x1c);
    uint16_t phentsize=PPU_LH(g_base,ea+0x2a), phnum=PPU_LH(g_base,ea+0x2c);
    for (uint16_t i=0;i<phnum;i++){
        uint32_t ph=ea+phoff+(uint32_t)i*phentsize;
        if (ph+0x20>g_size) break;
        uint32_t type=PPU_LW(g_base,ph), off=PPU_LW(g_base,ph+4), va=PPU_LW(g_base,ph+8);
        uint32_t fsz=PPU_LW(g_base,ph+0x10), msz=PPU_LW(g_base,ph+0x14);
        if (type!=1) continue;
        if (va+msz>0x40000 || ea+off+fsz>g_size) continue;
        spu_thread_write_ls(t, va, g_base+ea+off, fsz);
        if (msz>fsz) spu_thread_write_ls(t, va+fsz, 0, msz-fsz);
    }
    return entry;
}

#define SPU_IMG_RAWELF (-1)

typedef struct {
    uint32_t id; int used;
    SpuThread* t; uint32_t entry; uint64_t arg[4];
    uint32_t group; int started;
} SpuThr;
typedef struct { uint32_t id; int used, nthr, started; uint32_t thr[8]; uint32_t evq;
                 uint32_t spup_q[64]; } SpuGrp;
enum { NSPUTHR=64, NSPUGRP=16 };
static SpuThr g_sputhr[NSPUTHR]; static SpuGrp g_spugrp[NSPUGRP];
static uint32_t g_spu_idseq=0x7000;

static SpuThr* sputhr_find(uint32_t id){ for(int i=0;i<NSPUTHR;i++) if(g_sputhr[i].used&&g_sputhr[i].id==id) return &g_sputhr[i]; return 0; }
static SpuGrp* spugrp_find(uint32_t id){ for(int i=0;i<NSPUGRP;i++) if(g_spugrp[i].used&&g_spugrp[i].id==id) return &g_spugrp[i]; return 0; }

static uint32_t spu_grp_create(uint32_t idp, uint32_t num){
    EnterCriticalSection(&g_lock);
    SpuGrp* g=0; for(int i=0;i<NSPUGRP;i++) if(!g_spugrp[i].used){ g=&g_spugrp[i]; break; }
    if(g){ memset(g,0,sizeof *g); g->used=1; g->id=++g_spu_idseq; g->nthr=0; (void)num; }
    LeaveCriticalSection(&g_lock);
    if(!g) return 0x80010004u;
    if(idp) PPU_STW(g_base,idp,g->id);
    fprintf(stderr,"[SPU] group_create id=0x%x num=%u\n",g->id,num);
    return 0;
}

static uint32_t spu_thr_init(uint32_t thrp, uint32_t gid, uint32_t spu_num,
                             uint32_t img_ea, uint32_t arg_ea){
    SpuGrp* g=spugrp_find(gid); if(!g) return 0x8001000au;
    EnterCriticalSection(&g_lock);
    SpuThr* th=0; for(int i=0;i<NSPUTHR;i++) if(!g_sputhr[i].used){ th=&g_sputhr[i]; break; }
    if(th){ memset(th,0,sizeof *th); th->used=1; th->id=++g_spu_idseq; th->group=gid; }
    LeaveCriticalSection(&g_lock);
    if(!th) return 0x80010004u;
    th->t = spu_thread_alloc();
    uint32_t entry=PPU_LW(g_base,img_ea+4), segs=PPU_LW(g_base,img_ea+8);
    int32_t  nsegs=(int32_t)PPU_LW(g_base,img_ea+12);
    if (nsegs==SPU_IMG_RAWELF){
        uint32_t e=spu_elf_load_ls(th->t, segs);
        if(e) entry=e;
    } else if (nsegs>0 && nsegs<=64){
        for (int32_t i=0;i<nsegs;i++){
            uint32_t s=segs+(uint32_t)i*16;
            int32_t  ty=(int32_t)PPU_LW(g_base,s); uint32_t ls=PPU_LW(g_base,s+4);
            int32_t  sz=(int32_t)PPU_LW(g_base,s+8); uint32_t av=PPU_LW(g_base,s+12);
            if (sz<=0 || ls+(uint32_t)sz>0x40000) continue;
            if (ty==1 && (uint64_t)av+(uint32_t)sz<=g_size)
                spu_thread_write_ls(th->t, ls, g_base+av, (uint32_t)sz);
            else if (ty==2){
                for (int32_t k=0;k+4<=sz;k+=4){ uint8_t w[4]={(uint8_t)(av>>24),(uint8_t)(av>>16),(uint8_t)(av>>8),(uint8_t)av}; spu_thread_write_ls(th->t, ls+(uint32_t)k, w, 4); }
            }
        }
    }
    th->entry=entry;
    if (arg_ea){ for(int i=0;i<4;i++) th->arg[i]=PPU_LD(g_base,arg_ea+8u*(uint32_t)i); }
    if (g->nthr<8) g->thr[g->nthr++]=th->id;
    if (thrp) PPU_STW(g_base,thrp,th->id);
    fprintf(stderr,"[SPU] thread_init id=0x%x grp=0x%x num=%u entry=0x%x nsegs=%d args=%llx,%llx,%llx,%llx\n",
            th->id,gid,spu_num,entry,nsegs,
            (unsigned long long)th->arg[0],(unsigned long long)th->arg[1],
            (unsigned long long)th->arg[2],(unsigned long long)th->arg[3]);
    return 0;
}

static uint32_t spu_grp_start_real(uint32_t gid);
static DWORD WINAPI grp_start_delayed(LPVOID p){
    const char* e=getenv("PS3_SPU_DELAY");
    Sleep(e?(DWORD)strtoul(e,0,0):8000);
    uint32_t gid=(uint32_t)(uintptr_t)p;
    fprintf(stderr,"[SPU] delayed group start 0x%x\n",gid);
    spu_grp_start_real(gid);
    return 0;
}
static uint32_t spu_grp_start(uint32_t gid){
    if (getenv("PS3_SPU_DELAY")){
        static int delayed_once;
        if (!delayed_once){
            delayed_once=1;
            CreateThread(0,0,grp_start_delayed,(LPVOID)(uintptr_t)gid,0,0);
            return 0;
        }
    }
    return spu_grp_start_real(gid);
}
static uint32_t spu_grp_start_real(uint32_t gid){
    SpuGrp* g=spugrp_find(gid); if(!g) return 0x8001000au;
    if (g->started) return 0;
    for (int i=0;i<g->nthr;i++){
        SpuThr* th=sputhr_find(g->thr[i]); if(!th||th->started) continue;
        void (*fn)(SPUContext*) = spu_body_for(th->entry);
        if (!fn){
            fprintf(stderr,"[SPU] no recompiled body for entry 0x%x (thread 0x%x) - interpreting\n",
                    th->entry, th->id);
            fn = spu_interp;
        }
        for(int k=0;k<4;k++) spu_thread_set_arg64(th->t, 3+k, th->arg[k]);
        spu_thread_start_at(th->t, fn, th->entry);
        th->started=1;
        fprintf(stderr,"[SPU] start thread 0x%x entry=0x%x\n",th->id,th->entry);
    }
    g->started=1;
    return 0;
}

#define LV2_ESRCH     0x80010005u
#define LV2_EAGAIN    0x80010001u
#define LV2_EINVAL    0x80010002u
#define LV2_EBUSY     0x8001000Au
#define LV2_ETIMEDOUT 0x8001000Bu
#define LV2_ECANCELED 0x80010013u
#define LV2_EISCONN   0x80010015u
#define LV2_ENOTCONN  0x80010016u
#define LV2_SLOT_RESET(p,T) memset((char*)(p)+offsetof(T,id),0,sizeof(T)-offsetof(T,id))
typedef struct { uint64_t src,d1,d2,d3; } LvEvent;
typedef struct {
    CRITICAL_SECTION cs; CONDITION_VARIABLE cv; int init;
    uint32_t id; int used, n, nwait;
    uint64_t key;
    LvEvent ev[512];
} EvQueue;
typedef struct { uint32_t id; int used; uint32_t queue; uint64_t name; } EvPort;
typedef struct {
    CRITICAL_SECTION cs; CONDITION_VARIABLE cv; int init;
    uint32_t id; int used, nwait; uint64_t bits;
    struct { uint64_t tid, bits; uint32_t mode; } w[6];
    uint64_t last_set_tid;
    uint32_t last_set_tick;
    LONG64 p_set_qpc, p_wl_tk, p_wl_max, p_wt_tk; LONG p_wl_n, p_wt_n;
} EvFlag;
typedef struct {
    CRITICAL_SECTION cs; CONDITION_VARIABLE cv; int init;
    uint32_t id; int used, nwait; int32_t count;
} Sem;
enum { NEVQ=128, NEVP=512, NEVF=1024, NSEM=512 };
static EvQueue g_evq[NEVQ]; static EvPort g_evp[NEVP]; static EvFlag g_evf[NEVF]; static Sem g_sem[NSEM];

static void evf_dump(void){
    DWORD now=GetTickCount();
    for(int i=0;i<NEVF;i++){
        EvFlag* f=&g_evf[i]; if(!f->used) continue;
        int nw=0; for(int j=0;j<6;j++) if(f->w[j].tid) nw++;
        if(!nw) continue;
        char b[512]; int o=snprintf(b,sizeof b,"[EVFW] id=0x%x bits=0x%llx lastset=",f->id,(unsigned long long)f->bits);
        if(f->last_set_tick) o+=snprintf(b+o,sizeof b-o,"%s+%lums",
            f->last_set_tid==~0ull?"SPU":"ppu",(unsigned long)(now-f->last_set_tick));
        else o+=snprintf(b+o,sizeof b-o,"never");
        for(int j=0;j<6 && o<(int)sizeof b-48;j++) if(f->w[j].tid)
            o+=snprintf(b+o,sizeof b-o," t%llu:w0x%llx/m0x%x",
                (unsigned long long)f->w[j].tid,(unsigned long long)f->w[j].bits,f->w[j].mode);
        fprintf(stderr,"%s\n",b);
    }
}
static DWORD WINAPI evfprof_dump(LPVOID p){
    (void)p;
    LARGE_INTEGER fq; QueryPerformanceFrequency(&fq);
    double tk2ms=1000.0/(double)fq.QuadPart, tk2us=1e6/(double)fq.QuadPart;
    for(;;){ Sleep(5000);
        for(int i=0;i<NEVF;i++){
            EvFlag* f=&g_evf[i]; if(!f->used) continue;
            EnterCriticalSection(&f->cs);
            LONG wtn=f->p_wt_n, wln=f->p_wl_n;
            LONG64 wt=f->p_wt_tk, wl=f->p_wl_tk, wm=f->p_wl_max;
            f->p_wt_n=0; f->p_wl_n=0; f->p_wt_tk=0; f->p_wl_tk=0; f->p_wl_max=0;
            LeaveCriticalSection(&f->cs);
            if(!wtn) continue;
            fprintf(stderr,"[EVFPROF] id=0x%x waits=%ld blocked=%.0fms wakes=%ld lat-avg=%.0fus lat-max=%.0fus\n",
                f->id,(long)wtn,wt*tk2ms,(long)wln,
                wln?wl*tk2us/wln:0.0,wm*tk2us);
        }
    }
}
static EvQueue* evq_find(uint32_t id){ for(int i=0;i<NEVQ;i++) if(g_evq[i].used&&g_evq[i].id==id) return &g_evq[i]; return 0; }
static EvQueue* evq_find_by_key(uint64_t key){ if(!key) return 0; for(int i=0;i<NEVQ;i++) if(g_evq[i].used&&g_evq[i].key==key) return &g_evq[i]; return 0; }
static EvPort*  evp_find(uint32_t id){ for(int i=0;i<NEVP;i++) if(g_evp[i].used&&g_evp[i].id==id) return &g_evp[i]; return 0; }
static EvFlag*  evf_find(uint32_t id){ for(int i=0;i<NEVF;i++) if(g_evf[i].used&&g_evf[i].id==id) return &g_evf[i]; return 0; }
static Sem*     sem_find(uint32_t id){ for(int i=0;i<NSEM;i++) if(g_sem[i].used&&g_sem[i].id==id) return &g_sem[i]; return 0; }
#define LV2_LOCK_FN(name,T,findfn) \
    static T* name(uint32_t id){ T* o=findfn(id); if(!o) return 0; \
        EnterCriticalSection(&o->cs); if(o->used && o->id==id) return o; \
        LeaveCriticalSection(&o->cs); return 0; }
LV2_LOCK_FN(evf_lock,EvFlag,evf_find)
LV2_LOCK_FN(sem_lock,Sem,sem_find)
LV2_LOCK_FN(evq_lock,EvQueue,evq_find)
#define LV2_ALLOC_FN(name,T,tab,N) \
    static T* name(void){ \
        for(int i=0;i<(N);i++){ T* o=&tab[i]; if(o->used) continue; \
            if(!o->init){ InitializeCriticalSection(&o->cs); InitializeConditionVariable(&o->cv); o->init=1; } \
            EnterCriticalSection(&o->cs); \
            if(o->used||o->nwait){ LeaveCriticalSection(&o->cs); continue; } \
            LV2_SLOT_RESET(o,T); o->id=++g_spu_idseq; o->used=1; return o; } \
        return 0; }
LV2_ALLOC_FN(evf_alloc,EvFlag,g_evf,NEVF)
LV2_ALLOC_FN(sem_alloc,Sem,g_sem,NSEM)
LV2_ALLOC_FN(evq_alloc,EvQueue,g_evq,NEVQ)
static void lv2_create_failed(const char* what, int cap, PPUContext* ctx){
    static volatile long n; long k=InterlockedIncrement(&n);
    if(k<=16||(k%256)==0)
        fprintf(stderr,"[LV2] %s create FAILED: all %d slots in use (EAGAIN) lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",
                what,cap,ctx?(unsigned long long)ctx->lr:0ull,g_curfn,(unsigned long long)t_gid,k);
}

static DWORD WINAPI kick_thread(LPVOID p){
    (void)p;
    const char* e=getenv("PS3_KICKEVF"); if(!e) return 0;
    uint32_t id=0,bits=1,period=1000,start=20000;
    sscanf(e,"%i:%i:%u:%u",&id,&bits,&period,&start);
    if(!id) return 0;
    fprintf(stderr,"[kick] armed id=0x%x bits=0x%x period=%ums start=%ums\n",id,bits,period,start);
    Sleep(start);
    for(;;){
        EvFlag* f=evf_lock(id);
        if(f){ f->bits|=bits; WakeAllConditionVariable(&f->cv); LeaveCriticalSection(&f->cs);
            static volatile long n; long k=InterlockedIncrement(&n);
            if(k<=8||(k%32)==0) fprintf(stderr,"[kick] %lu set id=0x%x bits=0x%x (k=%ld)\n",(unsigned long)GetTickCount(),id,bits,k); }
        Sleep(period);
    }
}

static uint32_t evq_create(void){
    EnterCriticalSection(&g_lock);
    EvQueue* q=evq_alloc(); uint32_t id=0;
    if(q){ id=q->id; LeaveCriticalSection(&q->cs); }
    LeaveCriticalSection(&g_lock);
    if(!id) lv2_create_failed("event queue",NEVQ,0);
    return id;
}
static int evq_push(EvQueue* q, uint32_t id, uint64_t src, uint64_t d1, uint64_t d2, uint64_t d3){
    EnterCriticalSection(&q->cs);
    if(!q->used || q->id!=id){ LeaveCriticalSection(&q->cs); return 0; }
    if(q->n<512){ q->ev[q->n].src=src; q->ev[q->n].d1=d1; q->ev[q->n].d2=d2; q->ev[q->n].d3=d3; q->n++; }
    else { static volatile long d; long k=InterlockedIncrement(&d);
           if(k<=32||(k%256)==0) fprintf(stderr,"[EVQ] DROP q=0x%x src=0x%llx d1=0x%llx d2=0x%llx (n=%ld)\n",
               q->id,(unsigned long long)src,(unsigned long long)d1,(unsigned long long)d2,k); }
    WakeAllConditionVariable(&q->cv); LeaveCriticalSection(&q->cs);
    return 1;
}
static uint32_t evq_pop(uint32_t id, LvEvent* out, uint64_t timeout_us){
    EvQueue* q=evq_lock(id); if(!q) return LV2_ESRCH;
    uint32_t rc=0;
    q->nwait++;
    while (q->n==0){
        DWORD ms = timeout_us ? (DWORD)(timeout_us/1000+1) : 100;
        BOOL woke = SleepConditionVariableCS(&q->cv,&q->cs,ms);
        if (!q->used || q->id!=id){ rc=LV2_ECANCELED; break; }
        if (!woke && timeout_us){ rc=LV2_ETIMEDOUT; break; }
        if (timeout_us && q->n==0){ rc=LV2_ETIMEDOUT; break; }
    }
    if (!rc){ *out=q->ev[0]; for(int i=1;i<q->n;i++) q->ev[i-1]=q->ev[i]; q->n--; }
    q->nwait--;
    LeaveCriticalSection(&q->cs);
    return rc;
}

static uint32_t gcm_ctx_ea, gcm_ctrl_ea, gcm_label_ea, gcm_cfg_local_ea, gcm_io_ea, gcm_io_size;
static uint32_t gcm_cb_ea, gcm_cb_size;
typedef struct { uint32_t ea, io, size; } GcmIoMap;
static GcmIoMap g_gcmio[64]; static int g_ngcmio=0;
static uint32_t gcm_io_next;
static void gcm_iomap_add(uint32_t ea, uint32_t io, uint32_t size);
static uint32_t gcm_addr2off(uint32_t a){
    if(a>=gcm_cb_ea && a<gcm_cb_ea+gcm_cb_size) return a-gcm_cb_ea;
    if(a>=gcm_cfg_local_ea && a<gcm_cfg_local_ea+0xF900000u) return a-gcm_cfg_local_ea;
    for(int i=0;i<g_ngcmio;i++)
        if(a>=g_gcmio[i].ea && a<g_gcmio[i].ea+g_gcmio[i].size) return g_gcmio[i].io+(a-g_gcmio[i].ea);
    {
        static uint32_t io_auto=0x10000000u;
        uint32_t base=a&~0xfffffu, io=io_auto;
        io_auto+=0x100000;
        fprintf(stderr,"[GCM] addr2off automap ea=0x%x -> window 0x%x io=0x%x\n",a,base,io);
        gcm_iomap_add(base,io,0x100000);
        return io+(a-base);
    }
}
static uint32_t gcm_ioff2ea(uint32_t o){
    if(o<gcm_cb_size) return gcm_cb_ea+o;
    for(int i=0;i<g_ngcmio;i++)
        if(o>=g_gcmio[i].io && o<g_gcmio[i].io+g_gcmio[i].size) return g_gcmio[i].ea+(o-g_gcmio[i].io);
    return 0;
}
static uint32_t gcm_ioff2ea_run(uint32_t o, uint32_t* run){
    if(o<gcm_cb_size){ *run=gcm_cb_size-o; return gcm_cb_ea+o; }
    for(int i=0;i<g_ngcmio;i++)
        if(o>=g_gcmio[i].io && o<g_gcmio[i].io+g_gcmio[i].size){
            *run=g_gcmio[i].io+g_gcmio[i].size-o; return g_gcmio[i].ea+(o-g_gcmio[i].io); }
    *run=0; return 0;
}
static void gcm_iomap_add(uint32_t ea, uint32_t io, uint32_t size){
    for(int i=0;i<g_ngcmio;){
        int ov_ea = g_gcmio[i].ea < ea+size && ea < g_gcmio[i].ea+g_gcmio[i].size;
        int ov_io = g_gcmio[i].io < io+size && io < g_gcmio[i].io+g_gcmio[i].size;
        if(ov_ea || ov_io){
            fprintf(stderr,"[GCM] iomap displace ea=0x%x io=0x%x size=0x%x\n",
                    g_gcmio[i].ea,g_gcmio[i].io,g_gcmio[i].size);
            g_gcmio[i]=g_gcmio[--g_ngcmio];
        } else i++;
    }
    if(g_ngcmio<(int)(sizeof g_gcmio/sizeof g_gcmio[0])){
        g_gcmio[g_ngcmio].ea=ea; g_gcmio[g_ngcmio].io=io; g_gcmio[g_ngcmio].size=size; g_ngcmio++;
    } else fprintf(stderr,"[GCM] iomap TABLE FULL, dropping ea=0x%x\n",ea);
    fprintf(stderr,"[GCM] iomap ea=0x%x io=0x%x size=0x%x\n",ea,io,size);
}
static void gcm_iomap_del(uint32_t ea, uint32_t io, int by_ea){
    for(int i=0;i<g_ngcmio;){
        int hit = by_ea ? (ea>=g_gcmio[i].ea && ea<g_gcmio[i].ea+g_gcmio[i].size)
                        : (io>=g_gcmio[i].io && io<g_gcmio[i].io+g_gcmio[i].size);
        if(hit){
            fprintf(stderr,"[GCM] iounmap ea=0x%x io=0x%x size=0x%x\n",
                    g_gcmio[i].ea,g_gcmio[i].io,g_gcmio[i].size);
            g_gcmio[i]=g_gcmio[--g_ngcmio];
        } else i++;
    }
}
static uint32_t gcm_flip_handler_opd, gcm_vblank_handler_opd;
static uint32_t gcm_user_handler_opd;
static volatile LONG gcm_flip_pending;
static volatile LONG gcm_flip_status = 0;
static volatile LONG gcm_flip_buf = 0;
static volatile LONG gcm_flip_mode = 1;
static volatile DWORD gcm_flip_queued_t;

void   rsxd_bench_reset(void);
double rsxd_bench_line(char* out, size_t cap, int frames);

static uint32_t* g_bench_us;
static int   g_bench_warm, g_bench_want, g_bench_have, g_bench_seen;
static int   g_bench_state;
static uint64_t g_bench_qfreq, g_bench_last, g_bench_t0;

static int bench_cmp(const void* a, const void* b){
    uint32_t x=*(const uint32_t*)a, y=*(const uint32_t*)b;
    return x<y?-1:x>y?1:0;
}
static void bench_tick(void){
    if(g_bench_state==3) return;
    if(!g_bench_state){
        const char* e=getenv("PS3_BENCH");
        if(!e){ g_bench_state=3; return; }
        g_bench_warm=atoi(e);
        const char* c=strchr(e,':');
        g_bench_want=c?atoi(c+1):600;
        if(g_bench_want<1) g_bench_want=1;
        g_bench_us=(uint32_t*)calloc((size_t)g_bench_want,4);
        if(!g_bench_us){ g_bench_state=3; return; }
        LARGE_INTEGER f; QueryPerformanceFrequency(&f);
        g_bench_qfreq=(uint64_t)f.QuadPart;
        g_bench_state=1;
        fprintf(stderr,"[BENCH] armed: warm-up %d flips, then measure %d\n",
                g_bench_warm,g_bench_want);
    }
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    uint64_t now=(uint64_t)q.QuadPart;
    g_bench_seen++;
    if(g_bench_state==1){
        if(g_bench_seen<g_bench_warm){
            if((g_bench_seen%120)==0)
                fprintf(stderr,"[BENCH] warm-up %d/%d\n",g_bench_seen,g_bench_warm);
            g_bench_last=now; return;
        }
        rsxd_bench_reset();
        g_bench_state=2; g_bench_have=0; g_bench_t0=now; g_bench_last=now;
        fprintf(stderr,"[BENCH] measuring %d frames\n",g_bench_want);
        return;
    }
    if(g_bench_last&&g_bench_have<g_bench_want){
        uint64_t d=now-g_bench_last;
        double us=(double)d*1e6/(double)g_bench_qfreq;
        if(us>4e9) us=4e9;
        g_bench_us[g_bench_have++]=(uint32_t)us;
    }
    g_bench_last=now;
    if(g_bench_have<g_bench_want) return;

    int n=g_bench_have;
    double wall=(double)(now-g_bench_t0)/(double)g_bench_qfreq;
    uint32_t* s=(uint32_t*)malloc((size_t)n*4);
    double mean=0;
    for(int i=0;i<n;i++){ mean+=g_bench_us[i]; if(s) s[i]=g_bench_us[i]; }
    mean/=n;
    if(s) qsort(s,(size_t)n,4,bench_cmp);
    double p50=s?s[n/2]/1000.0:0, p95=s?s[(int)(n*0.95)]/1000.0:0,
           p99=s?s[(int)(n*0.99)]/1000.0:0,
           lo=s?s[0]/1000.0:0, hi=s?s[n-1]/1000.0:0;
    char rline[512];
    double rend=rsxd_bench_line(rline,sizeof rline,n);
    fprintf(stderr,
        "\n================ [BENCH] %d frames, %.2fs ================\n"
        "  fps    mean %.2f   (from p50 %.2f)\n"
        "  ms/f   mean %.2f  p50 %.2f  p95 %.2f  p99 %.2f  min %.2f  max %.2f\n"
        "  split  renderer %.2f   everything else (guest PPU/SPU + wait) %.2f\n"
        "  rsx   %s\n"
        "=========================================================\n",
        n,wall,
        mean>0?1e6/mean:0, p50>0?1000.0/p50:0,
        mean/1000.0,p50,p95,p99,lo,hi,
        rend, mean/1000.0-rend,
        rline);
    fprintf(stderr,"[BENCH-CSV] frames=%d mean_ms=%.3f p50_ms=%.3f p95_ms=%.3f "
            "p99_ms=%.3f renderer_ms=%.3f other_ms=%.3f\n",
            n,mean/1000.0,p50,p95,p99,rend,mean/1000.0-rend);
    free(s);
    g_bench_state=3;
    { static int keep=-1; if(keep<0) keep=getenv("PS3_BENCH_KEEPRUNNING")?1:0;
      if(!keep){ fflush(NULL); ExitProcess(0); } }
}
static HANDLE gcm_vblank_thread;
static volatile long g_flipno;

static void gcm_call_guest(uint32_t opd, uint64_t arg){
    if(!opd) return;
    uint32_t code=PPU_LW(g_base,opd), toc=PPU_LW(g_base,opd+4);
    if(!code) return;
    PPUContext* c=(PPUContext*)calloc(1,sizeof(PPUContext));
    static __declspec(thread) uint32_t stk;
    if(!stk) stk=guest_alloc_hi(0x10000,0x1000)+0x10000-0x200;
    c->r[1]=stk; c->r[2]=toc; c->r[3]=arg;
    PPCFunc f=ppu_lookup(code); if(f) f(c,g_base);
    free(c);
}
static DWORD WINAPI gcm_vblank_main(LPVOID p){
    (void)p;
    g_fifo_htid = GetCurrentThreadId();
    { const char* e = getenv("PS3_FIFO_PRIO");
      int pr = e ? atoi(e) : THREAD_PRIORITY_ABOVE_NORMAL;
      if(pr) SetThreadPriority(GetCurrentThread(), pr); }
    DWORD tick_ms = 1;
    { const char* e = getenv("PS3_GCM_TICK"); if(e){ int v=atoi(e); if(v>0&&v<=16) tick_ms=(DWORD)v; } }
    LARGE_INTEGER qpf; QueryPerformanceFrequency(&qpf);
    long long vb_period = qpf.QuadPart / 60;
    { const char* e = getenv("PS3_VBLANK_MS");
      if(e){ int v=atoi(e); if(v>=4&&v<=33) vb_period = qpf.QuadPart*v/1000; } }
    long long last_vb_q; { LARGE_INTEGER q0; QueryPerformanceCounter(&q0); last_vb_q=q0.QuadPart; }
    int hot = 0;
    int hot_win = 512;
    { const char* e = getenv("PS3_GCM_HOT"); if(e){ int v=atoi(e); if(v>=0&&v<=100000) hot_win=v; } }
    uint32_t tick_us = 500, vb_spin_us = 700;
    { const char* e = getenv("PS3_GCM_TICK_US"); if(e){ int v=atoi(e); if(v>=50&&v<=16000) tick_us=(uint32_t)v; }
      e = getenv("PS3_GCM_VBSPIN_US"); if(e){ int v=atoi(e); if(v>=0&&v<=4000) vb_spin_us=(uint32_t)v; } }
    HANDLE wait_tmr = getenv("PS3_GCM_TICK") ? NULL
        : CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                 TIMER_ALL_ACCESS);
    HANDLE wait_evt = CreateEventW(NULL, FALSE, FALSE, NULL);
    spu_fifo_watch_event(wait_evt);
    int acq_spin = 256, stall_hot = 8;
    { const char* e = getenv("PS3_GCM_ACQSPIN"); if(e){ int v=atoi(e); if(v>=0&&v<=1000000) acq_spin=v; }
      e = getenv("PS3_GCM_STALLHOT"); if(e){ int v=atoi(e); if(v>=0&&v<=100000) stall_hot=v; } }
    uint32_t park_ea = 0, park_val = 0; int park_acq = 0;
    enum { FW_GAME, FW_ACQ, FW_JTS };
    int fw_kind = FW_GAME;
    uint64_t fa_busy=0, fa_acq=0, fa_jts=0, fa_game=0, fa_vsync=0;
    uint64_t fs_busy=0, fs_acq=0, fs_jts=0, fs_game=0, fs_vsync=0;
    long long last_flip_q=0; int fl_n=0, fl_late3=0, fl_late4=0; double fl_worst=0;
    uint64_t ls_busy=0, ls_spu=0, ls_game=0;
    for(;;){
        { LARGE_INTEGER qa,qb; QueryPerformanceCounter(&qa);
          if(hot > 0){ hot--; SwitchToThread(); }
          else if(!wait_tmr) Sleep(tick_ms);
          else {
              long long left_us = (last_vb_q + vb_period - qa.QuadPart) * 1000000 / qpf.QuadPart;
              if(left_us <= (long long)vb_spin_us) SwitchToThread();
              else {
                  long long w = left_us - vb_spin_us;
                  if(w > (long long)tick_us) w = tick_us;
                  LARGE_INTEGER due; due.QuadPart = -w * 10;
                  SetWaitableTimer(wait_tmr, &due, 0, NULL, NULL, FALSE);
                  HANDLE hs[2] = { wait_evt, wait_tmr };
                  WaitForMultipleObjects(2, hs, FALSE, INFINITE);
              }
          }
          QueryPerformanceCounter(&qb);
          uint64_t dw=(uint64_t)(qb.QuadPart-qa.QuadPart);
          if(gcm_flip_pending) fa_vsync+=dw;
          else if(fw_kind==FW_ACQ) fa_acq+=dw;
          else if(fw_kind==FW_JTS) fa_jts+=dw;
          else fa_game+=dw; }
        if(gcm_ctrl_ea){
            uint32_t put=PPU_LW(g_base,gcm_ctrl_ea+0);
            uint32_t get=PPU_LW(g_base,gcm_ctrl_ea+4);
            static int gcm_log=-1;
            if(gcm_log<0) gcm_log=getenv("PS3_GCM_LOG")?1:0;
            if(gcm_log && put!=get){
                static uint32_t lastput; if(put!=lastput){ lastput=put;
                    fprintf(stderr,"[GCM-TICK] %lu put=0x%x get=0x%x\n",(unsigned long)GetTickCount(),put,get); }
            }
            if(put==get) fw_kind=FW_GAME;
            if(put!=get && gcm_cb_ea){
                LARGE_INTEGER qd0; QueryPerformanceCounter(&qd0);
                int stall_kind=FW_JTS;
                DWORD drain_t0=GetTickCount(); uint32_t drain_o0=get;
                uint32_t o=get, callret=0; int guard=0, stalled=0;
                uint64_t acq_spin_q=0;
                park_ea=0;
                static uint32_t sem_off;
                static uint32_t stall_hdr; static DWORD stall_since;
                static uint32_t jts_off; static DWORD jts_since;
                while(o!=put && guard++<1000000){
                    uint32_t cea=gcm_ioff2ea(o);
                    if(!cea){
                        static int n; if(n++<8) fprintf(stderr,"[GCM] parse: untranslatable get=0x%x\n",o);
                        DWORD nowu=GetTickCount();
                        if(jts_off!=o){ jts_off=o; jts_since=nowu; }
                        if(nowu-jts_since<1000){ stalled=1; break; }
                        jts_off=0; o+=4; continue;
                    }
                    uint32_t w=PPU_LW(g_base,cea);
                    if(w&0x20000000u){
                        uint32_t tgt=w&0x1fffffffu;
                        if(tgt!=o && jts_off==o && jts_off){
                            DWORD durj=GetTickCount()-jts_since;
                            MTRC(MTRC_FIFO_STALL,1,o,tgt,durj,"JTS");
                            static long njr; if(durj>20 && njr++<80)
                                fprintf(stderr,"[GCM] %lu JTS patched io=0x%x took=%lums\n",
                                        (unsigned long)GetTickCount(),o,(unsigned long)durj);
                            jts_off=0;
                        }
                        if(tgt==o){
                            DWORD nowj=GetTickCount();
                            if(jts_off!=o){ jts_off=o; jts_since=nowj; }
                            if(nowj-jts_since<1000){ stalled=1; park_ea=cea; park_val=w; park_acq=0; break; }
                            MTRC(MTRC_FIFO_STALL,1,o,0,nowj-jts_since,"JTS TIMEOUT");
                            static int njts; if(njts++<16)
                                fprintf(stderr,"[GCM] JTS TIMEOUT at io=0x%x - skipping word\n",o);
                            jts_off=0; o+=4; continue;
                        }
                        o=tgt; continue;
                    }
                    if((w&3)==2){ callret=o+4; o=w&0x1ffffffcu; continue; }
                    if(w==0x00020000u){ if(!callret) break; o=callret; callret=0; continue; }
                    o+=4;
                    uint32_t cnt=(w>>18)&0x7ff, mth=w&0x3fffc, ni=(w>>30)&1;
                    static int gcm_stats=-1;
                    if(gcm_stats<0) gcm_stats=getenv("PS3_GCM_STATS")?1:0;
                    if(gcm_stats){
                        static uint32_t sm[256]; static uint32_t sc[256]; static int sn; static DWORD slast;
                        int si=-1; for(int j2=0;j2<sn;j2++) if(sm[j2]==mth){ si=j2; break; }
                        if(si<0 && sn<256){ si=sn; sm[sn]=mth; sc[sn]=0; sn++; }
                        if(si>=0) sc[si]++;
                        DWORD now=GetTickCount();
                        if(now-slast>5000){ slast=now;
                            fprintf(stderr,"[GCM-STATS]");
                            for(int j2=0;j2<sn;j2++) if(sc[j2]>0){ fprintf(stderr," %04x=%u",sm[j2],sc[j2]); sc[j2]=0; }
                            fprintf(stderr,"\n");
                        }
                    }
                    uint32_t aea=0, arun=0;
                    for(uint32_t i=0;i<cnt && o!=put;i++,o+=4,aea+=4,arun-=4){
                        if(arun<4){ aea=gcm_ioff2ea_run(o,&arun); if(!aea) break; }
                        uint32_t arg=PPU_LW(g_base,aea), m=mth+(ni?0:i*4);
                        if(m==0x050){ PPU_STW(g_base,gcm_ctrl_ea+8,arg); }
                        else if(m==0x064||m==0x1d6c) sem_off=arg;
                        else if(m==0x068){
                            if(gcm_label_ea && sem_off<0x4000 &&
                               PPU_LW(g_base,gcm_label_ea+sem_off)!=arg){
                                int ok=0;
                                LARGE_INTEGER sq0, sq1; QueryPerformanceCounter(&sq0);
                                for(int sp=0; sp<acq_spin; sp++){
                                    YieldProcessor();
                                    if(PPU_LW(g_base,gcm_label_ea+sem_off)==arg){ ok=1; break; }
                                }
                                QueryPerformanceCounter(&sq1); acq_spin_q+=(uint64_t)(sq1.QuadPart-sq0.QuadPart);
                                if(ok) stall_hdr=0;
                                if(!ok){
                                    uint32_t hdr=o-4u*(i+1u);
                                    DWORD now2=GetTickCount();
                                    if(stall_hdr!=hdr){ stall_hdr=hdr; stall_since=now2; }
                                    if(now2-stall_since<250){ o=hdr; stalled=1; stall_kind=FW_ACQ;
                                        park_ea=gcm_label_ea+sem_off; park_val=arg; park_acq=1; break; }
                                    MTRC(MTRC_FIFO_STALL,0,sem_off,arg,
                                         GetTickCount()-stall_since,"acquire TIMEOUT");
                                    static int nsk; if(nsk++<40)
                                        fprintf(stderr,"[GCM] acquire TIMEOUT off=0x%x want=0x%x have=0x%x\n",
                                                sem_off,arg,PPU_LW(g_base,gcm_label_ea+sem_off));
                                }
                            }
                            else if(stall_hdr && stall_hdr==o-4u*(i+1u)){
                                DWORD durok=GetTickCount()-stall_since;
                                MTRC(MTRC_FIFO_STALL,0,sem_off,arg,durok,"acquire");
                                static long nsl; if(durok>20 && nsl++<80)
                                    fprintf(stderr,"[GCM] %lu acquire SLOW off=0x%x want=0x%x took=%lums\n",
                                            (unsigned long)GetTickCount(),sem_off,arg,(unsigned long)durok);
                                stall_hdr=0;
                            }
                        }
                        else if(m==0x06c||m==0x1d70||m==0x1d74){
                            uint32_t v=(m==0x1d70)? ((arg&0xff00ff00u)|((arg>>16)&0xff)|((arg&0xff)<<16)) : arg;
                            if(gcm_label_ea && sem_off<0x4000){
                                PPU_STW(g_base,gcm_label_ea+sem_off,v);
                                static int n; if(n++<16 || gcm_log) fprintf(stderr,"[GCM] %lu label[0x%x]=0x%x\n",(unsigned long)GetTickCount(),sem_off,v);
                            } else if(gcm_log){
                                static int n2; if(n2++<64) fprintf(stderr,"[GCM] %lu semrel OOR sem_off=0x%x v=0x%x m=0x%x\n",(unsigned long)GetTickCount(),sem_off,v,m);
                            }
                        }
                        else if(m==0xeb00){
                            MTRC(MTRC_FIFO_INTR,arg,gcm_user_handler_opd,0,0,0);
                            static int n3; if(n3++<16 || gcm_log)
                                fprintf(stderr,"[GCM] %lu user-interrupt cause=0x%x handler=0x%x\n",
                                        (unsigned long)GetTickCount(),arg,gcm_user_handler_opd);
                            { static int nocb=-1;
                              if(nocb<0) nocb=getenv("PS3_GCM_NOUSERCB")?1:0;
                              if(!nocb) gcm_call_guest(gcm_user_handler_opd,arg); }
                            { static int forceblit=-1;
                              if(forceblit<0) forceblit=getenv("PS3_GCM_BLITDONE")?1:0;
                              if(forceblit && (uint64_t)arg+4808+48<=g_size && arg)
                                PPU_STW(g_base,arg+4808+44,1); }
                        }
                        else if(m==0xe924||m==0xe944){
                            gcm_flip_status=1; InterlockedExchange(&gcm_flip_buf,(LONG)arg);
                            gcm_flip_queued_t=GetTickCount();
                            InterlockedExchange(&gcm_flip_pending,1);
                            static long nf; long kf=++nf; if(kf<=8||(kf%512)==0)
                                fprintf(stderr,"[GCM] fifo flip buf=%u (k=%ld)\n",arg,kf);
                        }
                        else rsx_method(m,arg);
                    }
                    if(stalled) break;
                }
                uint32_t newget = stalled ? o : put;
                PPU_STW(g_base,gcm_ctrl_ea+4, newget);
                MTRC(MTRC_FIFO_DRAIN,drain_o0,newget,put,
                     ((uint32_t)stalled<<16)|((uint32_t)guard&0xffffu),0);
                { DWORD ddt=GetTickCount()-drain_t0;
                  static long ndp; if(ddt>30 && ndp++<80)
                    fprintf(stderr,"[GCM] %lu drain %lums get 0x%x->0x%x put=0x%x stalled=%d guard=%d\n",
                            (unsigned long)GetTickCount(),(unsigned long)ddt,
                            drain_o0,newget,put,stalled,guard); }
                if(newget != get) hot = hot_win;
                if(stalled && park_ea && wait_tmr){
                    spu_fifo_watch(park_ea);
                    if(hot > stall_hot) hot = stall_hot;
                    MemoryBarrier();
                    uint32_t pv = PPU_LW(g_base,park_ea);
                    if((park_acq ? pv == park_val : pv != park_val) && hot < 1) hot = 1;
                } else spu_fifo_watch(0);
                { LARGE_INTEGER qd1; QueryPerformanceCounter(&qd1);
                  uint64_t dd=(uint64_t)(qd1.QuadPart-qd0.QuadPart);
                  uint64_t sp=acq_spin_q<dd?acq_spin_q:dd;
                  dd-=sp; fa_acq+=sp;
                  fw_kind = stalled ? stall_kind : FW_GAME;
                  if(newget!=get) fa_busy+=dd;
                  else if(stall_kind==FW_ACQ) fa_acq+=dd; else fa_jts+=dd; }
            }
            else if(put!=get){ PPU_STW(g_base,gcm_ctrl_ea+4,put); hot = hot_win; }
        }
        DWORD now = GetTickCount();
        LARGE_INTEGER qnow; QueryPerformanceCounter(&qnow);
        int vb_now = (qnow.QuadPart - last_vb_q >= vb_period);
        int vsync = (gcm_flip_mode == 2);
        if((!vsync || vb_now) && InterlockedExchange(&gcm_flip_pending,0)){
            gcm_flip_status=0;
            DWORD tq = gcm_flip_queued_t;
            DWORD tf0 = GetTickCount();
            MTRC(MTRC_FIFO_FLIP,(uint32_t)gcm_flip_buf,
                 (uint32_t)(tf0>=tq?tf0-tq:0),0,0,0);
            rsx_flip((uint32_t)gcm_flip_buf);
            g_flipno++;
            gcm_call_guest(gcm_flip_handler_opd,1);
            hot = hot_win;
            { static long lim=-1;
              if(lim<0){ const char* e=getenv("PS3_EXIT_AFTER_FLIPS"); lim=e?atol(e):0; }
              if(lim>0 && g_flipno>=lim){
                  fprintf(stderr,"[GCM] PS3_EXIT_AFTER_FLIPS: exit at flip %ld\n",g_flipno);
                  fflush(NULL); ExitProcess(0); } }
            bench_tick();
            { static DWORD w0; static int fc; static DWORD lastdone;
              static uint64_t sprod, swait, sflip;
              DWORD tf1 = GetTickCount();
              if(lastdone && tq>=lastdone){ sprod += tq-lastdone; swait += (tf0>tq)?tf0-tq:0; }
              sflip += tf1-tf0; lastdone = tf1; fc++;
              fs_busy+=fa_busy; fs_acq+=fa_acq; fs_jts+=fa_jts; fs_game+=fa_game; fs_vsync+=fa_vsync;
              if(last_flip_q){
                  double fms=(double)(qnow.QuadPart-last_flip_q)*1000.0/(double)qpf.QuadPart;
                  long vbn=(long)((double)(qnow.QuadPart-last_flip_q)/(double)vb_period+0.5);
                  fl_n++; if(vbn==3) fl_late3++; else if(vbn>=4) fl_late4++;
                  hprof_frame((int)vbn);
                  if(fms>fl_worst) fl_worst=fms;
                  if(vbn>=3){ ls_busy+=fa_busy; ls_spu+=fa_acq+fa_jts; ls_game+=fa_game; } }
              fa_busy=fa_acq=fa_jts=fa_game=fa_vsync=0;
              last_flip_q=qnow.QuadPart;
              if(now - w0 >= 5000){
                  double k = fc ? 1000.0/((double)qpf.QuadPart*fc) : 0;
                  int nl = fl_late3+fl_late4;
                  double kl = nl ? 1000.0/((double)qpf.QuadPart*nl) : 0;
                  if(w0) fprintf(stderr,"[GCM] %.1f flips/s prod=%.1f wait=%.1f flip=%.1f ms/f"
                                 " | fifo: render=%.1f spu-wait=%.1f (acquire %.1f, jts %.1f) game=%.1f vsync=%.1f"
                                 " | late %d/%d (3vb %d, 4+vb %d) worst %.0fms"
                                 " late-avg: render=%.1f spu-wait=%.1f game=%.1f\n",
                                 fc*1000.0/(now-w0),
                                 fc?(double)sprod/fc:0, fc?(double)swait/fc:0, fc?(double)sflip/fc:0,
                                 fs_busy*k, (fs_acq+fs_jts)*k, fs_acq*k, fs_jts*k, fs_game*k, fs_vsync*k,
                                 fl_late3+fl_late4, fl_n, fl_late3, fl_late4, fl_worst,
                                 ls_busy*kl, ls_spu*kl, ls_game*kl);
                  w0 = now; fc = 0; sprod=swait=sflip=0;
                  fs_busy=fs_acq=fs_jts=fs_game=fs_vsync=0; fl_n=fl_late3=fl_late4=0; fl_worst=0;
                  ls_busy=ls_spu=ls_game=0; } }
        }
        if(vb_now){
            long long miss = (qnow.QuadPart - last_vb_q) / vb_period;
            last_vb_q += miss * vb_period;
            { static DWORD vw0; static int vbc; vbc++;
              if(now - vw0 >= 5000){
                  if(vw0) fprintf(stderr,"[GCM] %.1f vblanks/s\n", vbc*1000.0/(now-vw0));
                  vw0 = now; vbc = 0; } }
            gcm_call_guest(gcm_vblank_handler_opd,1); }
    }
    return 0;
}
static void gcm_init(PPUContext* ctx){
    uint32_t ctxp=(uint32_t)R(3); gcm_cb_size=(uint32_t)R(4);
    gcm_io_size=(uint32_t)R(5); gcm_io_ea=(uint32_t)R(6);
    if(gcm_cb_size<0x100000) gcm_cb_size=0x100000;
    gcm_cb_ea      = guest_alloc(gcm_cb_size,0x1000);
    gcm_ctx_ea     = guest_alloc(0x40,16);
    gcm_ctrl_ea    = guest_alloc(0x1000,0x1000);
    gcm_label_ea   = guest_alloc(0x4000,0x1000);
    gcm_cfg_local_ea = guest_alloc(0xF900000u,0x100000);
    PPU_STW(g_base,gcm_ctx_ea+0, gcm_cb_ea);
    PPU_STW(g_base,gcm_ctx_ea+4, gcm_cb_ea+gcm_cb_size-4);
    PPU_STW(g_base,gcm_ctx_ea+8, gcm_cb_ea);
    PPU_STW(g_base,gcm_ctx_ea+12,0);
    if(ctxp) PPU_STW(g_base,ctxp,gcm_ctx_ea);
    PPU_STW(g_base,gcm_ctrl_ea+0,0);
    PPU_STW(g_base,gcm_ctrl_ea+4,0);
    PPU_STW(g_base,gcm_ctrl_ea+8,0);
    gcm_io_next=(gcm_cb_size+0xfffffu)&~0xfffffu;
    if(gcm_io_ea && gcm_io_size){
        uint32_t io=gcm_io_next; gcm_io_next+=(gcm_io_size+0xfffffu)&~0xfffffu;
        gcm_iomap_add(gcm_io_ea,io,gcm_io_size);
    }
    rsx_init(g_base, gcm_cfg_local_ea, 0xF900000u, gcm_ioff2ea, g_size);
    spu_set_dma_read_hook(rsx_sync_read, gcm_cfg_local_ea,
                          gcm_cfg_local_ea + 0xF900000u);
    if(!gcm_vblank_thread) gcm_vblank_thread=CreateThread(0,0,gcm_vblank_main,0,0,0);
    fprintf(stderr,"[GCM] init cb=0x%x(%u) ctrl=0x%x labels=0x%x local=0x%x io=0x%x(%u)\n",
            gcm_cb_ea,gcm_cb_size,gcm_ctrl_ea,gcm_label_ea,gcm_cfg_local_ea,gcm_io_ea,gcm_io_size);
    R(3)=0;
}
static int gcm_hle(const char* name, PPUContext* ctx){
    if (IS("_cellGcmInitBody")){ gcm_init(ctx); return 1; }
    if (IS("cellGcmGetControlRegister")){ R(3)=gcm_ctrl_ea; return 1; }
    if (IS("cellGcmGetLabelAddress")){ R(3)=gcm_label_ea+(((uint32_t)R(3))&0x3ff)*16; return 1; }
    if (IS("cellGcmGetConfiguration")){
        uint32_t p=(uint32_t)R(3);
        if(p){ PPU_STW(g_base,p+0,gcm_cfg_local_ea); PPU_STW(g_base,p+4,gcm_io_ea);
               PPU_STW(g_base,p+8,0xF900000u);   PPU_STW(g_base,p+12,gcm_io_size?gcm_io_size:0x1000000);
               PPU_STW(g_base,p+16,650000000);      PPU_STW(g_base,p+20,500000000); }
        R(3)=0; return 1; }
    if (IS("cellGcmIoOffsetToAddress")){
        uint32_t io=(uint32_t)R(3),pa=(uint32_t)R(4);
        uint32_t ea=gcm_ioff2ea(io);
        if(pa) PPU_STW(g_base,pa,ea);
        R(3)=ea?0:0x802100ff; return 1; }
    if (IS("cellGcmAddressToOffset")){
        uint32_t a=(uint32_t)R(3),po=(uint32_t)R(4);
        uint32_t off = gcm_addr2off(a);
        if(po) PPU_STW(g_base,po,off); R(3)=0; return 1; }
    if (IS("cellGcmMapMainMemory")){
        uint32_t a=(uint32_t)R(3),sz=(uint32_t)R(4),po=(uint32_t)R(5);
        uint32_t io=gcm_io_next; gcm_io_next+=(sz+0xfffffu)&~0xfffffu;
        gcm_iomap_add(a,io,sz);
        if(po) PPU_STW(g_base,po,io); R(3)=0; return 1; }
    if (IS("cellGcmMapEaIoAddress")||IS("cellGcmMapEaIoAddressWithFlags")){
        uint32_t a=(uint32_t)R(3),io=(uint32_t)R(4),sz=(uint32_t)R(5);
        gcm_iomap_add(a,io,sz);
        if(io+sz>gcm_io_next) gcm_io_next=(io+sz+0xfffffu)&~0xfffffu;
        R(3)=0; return 1; }
    if (IS("cellGcmUnmapEaIoAddress")){ gcm_iomap_del((uint32_t)R(3),0,1); R(3)=0; return 1; }
    if (IS("cellGcmUnmapIoAddress")){ gcm_iomap_del(0,(uint32_t)R(3),0); R(3)=0; return 1; }
    if (IS("cellGcmGetTiledPitchSize")){ R(3)=R(3); return 1; }
    if (IS("cellGcmSetUserHandler")){ gcm_user_handler_opd=(uint32_t)R(3); R(3)=0; return 1; }
    if (IS("cellGcmSetFlipHandler")){ gcm_flip_handler_opd=(uint32_t)R(3); R(3)=0; return 1; }
    if (IS("cellGcmSetVBlankHandler")){ gcm_vblank_handler_opd=(uint32_t)R(3); R(3)=0; return 1; }
    if (IS("cellGcmSetFlip")||IS("_cellGcmSetFlipCommand")||IS("cellGcmSetFlipWithWaitLabel")||
        IS("_cellGcmSetFlipCommandWithWaitLabel")){
        gcm_flip_status=1; InterlockedExchange(&gcm_flip_buf,(LONG)(uint32_t)R(4));
        gcm_flip_queued_t=GetTickCount();
        InterlockedExchange(&gcm_flip_pending,1);
        { static long n; long k=++n; if(k<=8||(k%512)==0) fprintf(stderr,"[GCM] flip queued id=%u (k=%ld)\n",(uint32_t)R(4),k); }
        R(3)=0; return 1; }
    if (IS("cellGcmGetFlipStatus")){ R(3)=(uint32_t)gcm_flip_status; return 1; }
    if (IS("cellGcmResetFlipStatus")){ gcm_flip_status=1; R(3)=0; return 1; }
    if (IS("cellGcmSetFlipMode")){
        InterlockedExchange(&gcm_flip_mode,(LONG)(uint32_t)R(3));
        fprintf(stderr,"[GCM] flip mode = %u\n",(uint32_t)R(3));
        R(3)=0; return 1; }
    if (IS("cellGcmSetWaitFlip")||IS("cellGcmSetSecondVFrequency")){ R(3)=0; return 1; }
    if (IS("cellGcmSetDisplayBuffer")){
        rsx_set_display_buffer((uint32_t)R(3),(uint32_t)R(4),(uint32_t)R(5),
                               (uint32_t)R(6),(uint32_t)R(7));
        R(3)=0; return 1; }
    if (IS("cellGcmGetLastFlipTime")||IS("cellGcmGetVBlankCount")){
        LARGE_INTEGER c,f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
        R(3)=(uint64_t)(c.QuadPart*60/f.QuadPart); return 1; }
    return 0;
}

#define CELL_AUDIO_BLOCK_SAMPLES 256
#define CELL_AUDIO_PORTATTR_INITLEVEL 0x1000ull
typedef struct { int open, running; uint32_t nch, nblk, ridx_ea, port_ea, portsize;
                 uint64_t attr; uint32_t ridx;
                 int consumed;
                 float level, level_cur;
                 volatile uint64_t tag; } AudioPort;

static int aud_writer_next(const AudioPort* ap){
    uint32_t obj=PPU_LW(g_base,0xddb800u);
    if(obj<0x10000u || (uint64_t)obj+0x2040u>g_size) return -1;
    if(PPU_LW(g_base,obj+0x2010u)!=ap->ridx_ea || PPU_LW(g_base,obj+0x202cu)!=ap->port_ea) return -1;
    uint32_t w=PPU_LW(g_base,obj+0x2034u);
    return w<ap->nblk ? (int)w : -1;
}
static inline uint32_t aud_lead(uint32_t nblk, uint32_t r, uint32_t w){
    return (w + 2u*nblk - r - 1u) % nblk;
}
static AudioPort g_aport[8];
static uint64_t g_anotify_key[8]; static volatile int g_nanotify;
static HANDLE g_audio_thread;

static const uint8_t g_aud_map8[8] = { 0, 1, 2, 3, 6, 7, 4, 5 };

static float aud_mix_block(float* mix, const uint8_t* blk, uint32_t nch, float* cur, float target){
    float lv=*cur, peak=0.0f;
    const float k = 1.0f/624.0f;
    for(int s=0;s<CELL_AUDIO_BLOCK_SAMPLES;s++){
        lv += (target-lv)*k;
        for(uint32_t c=0;c<nch;c++){
            uint32_t u; memcpy(&u,blk+((size_t)s*nch+c)*4,4);
            u=__builtin_bswap32(u);
            float v; memcpy(&v,&u,4);
            if(!(v>-16.0f && v<16.0f)) v=0.0f;
            if(v>peak) peak=v; else if(-v>peak) peak=-v;
            int slot = nch==8 ? g_aud_map8[c] : (c<2 ? (int)c : -1);
            if(slot>=0) mix[s*8+slot]+=v*lv;
        }
    }
    *cur=lv;
    return peak;
}

static FILE* g_aud_wav; static uint64_t g_aud_wav_frames;
static void aud_wav_header(FILE* f, uint64_t frames){
    uint32_t data=(uint32_t)(frames*8*4), riff=data+60;
    uint8_t h[68]; memset(h,0,sizeof h);
    #define W32(o,v) do{ uint32_t _v=(v); memcpy(h+(o),&_v,4); }while(0)
    #define W16(o,v) do{ uint16_t _v=(uint16_t)(v); memcpy(h+(o),&_v,2); }while(0)
    memcpy(h,"RIFF",4); W32(4,riff); memcpy(h+8,"WAVEfmt ",8); W32(16,40);
    W16(20,0xFFFE); W16(22,8); W32(24,48000); W32(28,48000*8*4); W16(32,8*4); W16(34,32);
    W16(36,22); W16(38,32); W32(40,0x63F);
    static const uint8_t ieee_guid[16]={0x03,0,0,0,0,0,0x10,0,0x80,0,0,0xAA,0,0x38,0x9B,0x71};
    memcpy(h+44,ieee_guid,16); memcpy(h+60,"data",4); W32(64,data);
    #undef W32
    #undef W16
    fseek(f,0,SEEK_SET); fwrite(h,1,sizeof h,f); fseek(f,0,SEEK_END);
}

static DWORD WINAPI audio_pump(LPVOID p){
    (void)p;
    g_audio_htid=GetCurrentThreadId();
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_TIME_CRITICAL);
    float master=1.0f;
    { const char* e=getenv("PS3_AUDIO_VOL"); if(e){ master=(float)atof(e); if(master<0) master=0; } }
    { const char* e=getenv("PS3_AUDIO_WAV");
      if(e&&*e){ g_aud_wav=fopen(e,"wb");
          if(g_aud_wav){ aud_wav_header(g_aud_wav,0); fprintf(stderr,"[AUDIO] writing the mix to %s\n",e); } } }
    LARGE_INTEGER f,t0; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&t0);
    uint64_t blocks=0;
    static float mix[CELL_AUDIO_BLOCK_SAMPLES*8];
    const double target=2048.0;
    double qavg=target; float ratio=1.0f; int pushing=0;
    uint64_t n_out=0, n_under=0, n_drop=0; float peak_win=0.0f; DWORD last_log=GetTickCount();
    int hold_ms=120;
    { const char* e=getenv("PS3_AUDIO_HOLD_MS"); if(e){ hold_ms=atoi(e); if(hold_ms<0) hold_ms=0; if(hold_ms>1000) hold_ms=1000; } }
    const int debt_max = hold_ms*48/CELL_AUDIO_BLOCK_SAMPLES + 8;
    int debt=0; LONGLONG held_since=0;
    uint64_t n_hold=0, n_giveup=0, n_lost=0, n_cut=0; double held_ms_sum=0, held_ms_max=0;
    uint32_t lead_min=~0u; float prev_pk=0.0f;
    for(;;){
        Sleep(1);
        LARGE_INTEGER t; QueryPerformanceCounter(&t);
        uint64_t want=(uint64_t)((t.QuadPart-t0.QuadPart)*48000.0/(f.QuadPart*CELL_AUDIO_BLOCK_SAMPLES));
        if(want>blocks+8) blocks=want-1;
        while(blocks<want){ blocks++; debt++; }
        if(debt>debt_max){ n_lost+=(uint64_t)(debt-debt_max); debt=debt_max; }
        while(debt>0){
            int hold=0;
            for(int i=0;i<8 && hold_ms;i++) if(g_aport[i].running && g_aport[i].consumed){
                const AudioPort* ap=&g_aport[i];
                int w=aud_writer_next(ap); if(w<0) continue;
                uint32_t lead=aud_lead(ap->nblk,ap->ridx,(uint32_t)w);
                if(lead<lead_min) lead_min=lead;
                if(lead==0) hold=1;
            }
            if(hold){
                if(!held_since){ held_since=t.QuadPart; n_hold++; }
                if((t.QuadPart-held_since)*1000 < (LONGLONG)hold_ms*f.QuadPart) break;
                n_giveup++;
            }
            if(held_since){
                double ms=(double)(t.QuadPart-held_since)*1000.0/(double)f.QuadPart;
                held_ms_sum+=ms; if(ms>held_ms_max) held_ms_max=ms; held_since=0;
            }
            debt--;
            memset(mix,0,sizeof mix);
            int nrun=0; float pk_step=0.0f;
            for(int i=0;i<8;i++) if(g_aport[i].running){
                AudioPort* ap=&g_aport[i];
                if(ap->consumed){
                    ap->ridx=(ap->ridx+1)%ap->nblk;
                    PPU_STD(g_base,ap->ridx_ea,ap->ridx);
                    ap->tag++;
                }
                uint32_t idx=ap->ridx%ap->nblk;
                uint32_t bsz=ap->nch*CELL_AUDIO_BLOCK_SAMPLES*4;
                uint64_t ea=(uint64_t)ap->port_ea+(uint64_t)idx*bsz;
                if(ea+bsz<=g_size){
                    float pk=aud_mix_block(mix,g_base+ea,ap->nch,&ap->level_cur,ap->level);
                    if(pk>pk_step) pk_step=pk;
                    memset(g_base+ea,0,bsz);
                }
                ap->consumed=1;
                nrun++;
            }
            if(pk_step>peak_win) peak_win=pk_step;
            if(nrun && pk_step==0.0f && prev_pk>0.02f) n_cut++;
            prev_pk=pk_step;
            if(nrun){
                for(int s=0;s<CELL_AUDIO_BLOCK_SAMPLES*8;s++){
                    float v=mix[s]*master;
                    mix[s]= v>1.0f?1.0f:(v<-1.0f?-1.0f:v);
                }
                if(g_aud_wav){ fwrite(mix,4,CELL_AUDIO_BLOCK_SAMPLES*8,g_aud_wav);
                    g_aud_wav_frames+=CELL_AUDIO_BLOCK_SAMPLES;
                    if((g_aud_wav_frames&0x7fff)==0){ aud_wav_header(g_aud_wav,g_aud_wav_frames); fflush(g_aud_wav); } }
                int q=rsxvk_audio_push(mix,CELL_AUDIO_BLOCK_SAMPLES);
                if(q>=0){
                    n_out++;
                    if(!pushing){ pushing=1; qavg=target; }
                    if(q==0 && n_out>32) n_under++;
                    if(q>(int)(target*6)){
                        rsxvk_audio_clear(); n_drop++; qavg=target; }
                    else {
                        qavg += ((double)q-qavg)*0.02;
                        double err=(qavg-target)/target;
                        double r=1.0+0.01*err;
                        if(r>1.01) r=1.01; if(r<0.99) r=0.99;
                        if(fabs(r-ratio)>0.0002){ ratio=(float)r; rsxvk_audio_ratio(ratio); }
                    }
                }
            } else pushing=0;
            for(int k=0;k<g_nanotify;k++){
                EvQueue* q=evq_find_by_key(g_anotify_key[k]);
                if(q) evq_push(q,q->id,0,0 ,0,0);
            }
        }
        DWORD now=GetTickCount();
        if(now-last_log>=10000){
            if(n_out||n_under||n_drop){
                fprintf(stderr,"[AUDIO] %llu blocks out, queue %.0f frames (%.1f ms), ratio %.4f, "
                        "underruns %llu, drops %llu, peak %.3f\n",
                        (unsigned long long)n_out,qavg,qavg/48.0,ratio,
                        (unsigned long long)n_under,(unsigned long long)n_drop,peak_win);
                if(lead_min!=~0u || n_hold || n_cut)
                    fprintf(stderr,"[AUDIO] game writer: lead min %d blocks, held %llu x (max %.0f ms, sum %.0f ms), "
                            "gave up %llu, lost %llu blocks, cuts %llu\n",
                            lead_min==~0u?-1:(int)lead_min,(unsigned long long)n_hold,held_ms_max,held_ms_sum,
                            (unsigned long long)n_giveup,(unsigned long long)n_lost,(unsigned long long)n_cut);
            }
            if(g_aud_wav){ aud_wav_header(g_aud_wav,g_aud_wav_frames); fflush(g_aud_wav); }
            last_log=now; peak_win=0.0f;
            lead_min=~0u; n_hold=n_giveup=n_lost=n_cut=0; held_ms_sum=held_ms_max=0;
        }
    }
}
static void audio_start_pump(void){ if(!g_audio_thread) g_audio_thread=CreateThread(0,0,audio_pump,0,0,0); }

static void pad_stick(int sx, int sy, int dz, float sens, float curve,
                      int* ox, int* oy){
    float x=(float)sx, y=(float)sy, m=sqrtf(x*x+y*y);
    *ox=0x80; *oy=0x80;
    if(m<=(float)dz) return;
    if(m>32767.0f) m=32767.0f;
    float n=(m-(float)dz)/(32767.0f-(float)dz);
    if(curve!=1.0f) n=powf(n,curve);
    n*=sens; if(n>1.0f) n=1.0f; if(n<0.0f) n=0.0f;
    float ux=x/m*n, uy=y/m*n;
    int px=(int)(ux*(ux<0.0f?128.0f:127.0f)+(ux<0.0f?-0.5f:0.5f));
    int py=(int)(uy*(uy<0.0f?128.0f:127.0f)+(uy<0.0f?-0.5f:0.5f));
    *ox=0x80+px;
    *oy=0x80-py;
    if(*ox<0)*ox=0; if(*ox>255)*ox=255;
    if(*oy<0)*oy=0; if(*oy>255)*oy=255;
}
static float pad_envf(const char* n, float d){
    const char* v=getenv(n); if(!v||!*v) return d;
    float f=(float)atof(v); return f>0.0f?f:d;
}
static uint32_t g_pad_setting[7];
static int pad_host_read(uint16_t w[24], uint8_t trig[2]){
    uint16_t d1=0, d2=0;
    int rx=0x80, ry=0x80, lx=0x80, ly=0x80;
    trig[0]=trig[1]=0;
    static float ldz=-1.0f, rdz, lsn, rsn, lcv, rcv;
    if(ldz<0.0f){
        ldz=pad_envf("PS3_PAD_LDZ",7849.0f);
        rdz=pad_envf("PS3_PAD_RDZ",8689.0f);
        lsn=pad_envf("PS3_PAD_LSENS",1.0f);
        rsn=pad_envf("PS3_PAD_RSENS",1.0f);
        lcv=pad_envf("PS3_PAD_LCURVE",1.0f);
        rcv=pad_envf("PS3_PAD_RCURVE",1.0f);
        fprintf(stderr,"[PAD] sticks: L dz=%.0f sens=%.2f curve=%.2f | "
                "R dz=%.0f sens=%.2f curve=%.2f\n",
                ldz,lsn,lcv,rdz,rsn,rcv);
    }
    int xi_ok = 0;
    static DWORD xi_down_until;
    if(GetTickCount() >= xi_down_until){
        XINPUT_STATE st;
        DWORD r = XInputGetState(0, &st);
        if(r == ERROR_SUCCESS){
            xi_ok = 1;
            WORD b = st.Gamepad.wButtons;
            if(b & XINPUT_GAMEPAD_DPAD_UP)        d1 |= 1u<<4;
            if(b & XINPUT_GAMEPAD_DPAD_RIGHT)     d1 |= 1u<<5;
            if(b & XINPUT_GAMEPAD_DPAD_DOWN)      d1 |= 1u<<6;
            if(b & XINPUT_GAMEPAD_DPAD_LEFT)      d1 |= 1u<<7;
            if(b & XINPUT_GAMEPAD_START)          d1 |= 1u<<3;
            if(b & XINPUT_GAMEPAD_BACK)           d1 |= 1u<<0;
            if(b & XINPUT_GAMEPAD_LEFT_THUMB)     d1 |= 1u<<1;
            if(b & XINPUT_GAMEPAD_RIGHT_THUMB)    d1 |= 1u<<2;
            if(b & XINPUT_GAMEPAD_X)              d2 |= 1u<<7;
            if(b & XINPUT_GAMEPAD_A)              d2 |= 1u<<6;
            if(b & XINPUT_GAMEPAD_B)              d2 |= 1u<<5;
            if(b & XINPUT_GAMEPAD_Y)              d2 |= 1u<<4;
            if(b & XINPUT_GAMEPAD_RIGHT_SHOULDER) d2 |= 1u<<3;
            if(b & XINPUT_GAMEPAD_LEFT_SHOULDER)  d2 |= 1u<<2;
            if(st.Gamepad.bRightTrigger > 30)     d2 |= 1u<<1;
            if(st.Gamepad.bLeftTrigger  > 30)     d2 |= 1u<<0;
            trig[0]=st.Gamepad.bLeftTrigger; trig[1]=st.Gamepad.bRightTrigger;
            pad_stick(st.Gamepad.sThumbLX,st.Gamepad.sThumbLY,(int)ldz,lsn,lcv,&lx,&ly);
            pad_stick(st.Gamepad.sThumbRX,st.Gamepad.sThumbRY,(int)rdz,rsn,rcv,&rx,&ry);
        } else {
            xi_down_until = GetTickCount() + 2000;
        }
    }
    if(!xi_ok){
        RsxvkPad sp;
        if(rsxvk_pad_read(&sp)){
            d1 |= sp.d1; d2 |= sp.d2;
            trig[0]=sp.l2; trig[1]=sp.r2;
            pad_stick(sp.lx,sp.ly,(int)ldz,lsn,lcv,&lx,&ly);
            pad_stick(sp.rx,sp.ry,(int)rdz,rsn,rcv,&rx,&ry);
        }
    }
    #define KD(vk) (GetAsyncKeyState(vk) & 0x8000)
    if(KD(VK_RETURN)) d1 |= 1u<<3;
    if(KD(VK_BACK))   d1 |= 1u<<0;
    if(KD(VK_UP))     d1 |= 1u<<4;  if(KD(VK_RIGHT)) d1 |= 1u<<5;
    if(KD(VK_DOWN))   d1 |= 1u<<6;  if(KD(VK_LEFT))  d1 |= 1u<<7;
    if(KD('X') || KD(VK_SPACE)) d2 |= 1u<<6;
    if(KD('C'))       d2 |= 1u<<5;
    if(KD('V'))       d2 |= 1u<<7;
    if(KD('T'))       d2 |= 1u<<4;
    if(KD('Q'))       d2 |= 1u<<2;  if(KD('E')) d2 |= 1u<<3;
    if(KD('1'))       d2 |= 1u<<0;  if(KD('3')) d2 |= 1u<<1;
    if(KD('W')) ly = 0;   if(KD('S')) ly = 255;
    if(KD('A')) lx = 0;   if(KD('D')) lx = 255;
    if(KD('I')) ry = 0;   if(KD('K')) ry = 255;
    if(KD('J')) rx = 0;   if(KD('L')) rx = 255;
    #undef KD
    w[0]=0; w[1]=0; w[2]=d1; w[3]=d2;
    w[4]=(uint16_t)rx; w[5]=(uint16_t)ry; w[6]=(uint16_t)lx; w[7]=(uint16_t)ly;
    for(int i=8;i<24;i++) w[i]=0;
    return d1 || d2 || rx!=0x80 || ry!=0x80 || lx!=0x80 || ly!=0x80;
}

static uint32_t g_sucb[4], g_suarg[4];
static uint64_t g_suevt[16][2]; static int g_suevt_n;
static int g_netstart_phase;
static DWORD g_netstart_t0;
static uint32_t g_np_cb, g_np_arg;
static int g_np_status = -1;
static int g_np_cb_fire;
static uint32_t g_m2_cb, g_m2_arg;
static int g_m2_fire;

typedef struct {
    uint32_t cb, arg;
    uint32_t req;
    uint16_t evt;
    uint32_t key;
    uint32_t data, size;
    uint32_t ptrofs;
    int      pending;
} M2Req;
static M2Req g_m2req[24]; static int g_m2req_n;
static uint32_t g_m2_arena; static uint32_t g_m2_arena_off;
static uint32_t g_m2_next_req = 1, g_m2_next_key = 0x1000;
static uint32_t m2_arena_alloc(uint32_t sz){
    if(!g_m2_arena){ g_m2_arena=guest_alloc_hi(0x20000,0x1000); g_m2_arena_off=0; }
    if(g_m2_arena_off+sz>0x20000) g_m2_arena_off=0;
    uint32_t a=g_m2_arena+g_m2_arena_off;
    g_m2_arena_off += (sz+15)&~15u;
    memset(g_base+a,0,sz);
    return a;
}
static void m2_queue(const char* name, uint32_t optp, uint32_t reqid_out,
                     uint16_t evt, uint32_t data, uint32_t size, uint32_t ptrofs){
    uint32_t cb=0, arg=0;
    if(optp){ cb=(uint32_t)PPU_LW(g_base,optp); arg=(uint32_t)PPU_LW(g_base,optp+4); }
    EnterCriticalSection(&g_lock);
    uint32_t req=g_m2_next_req++, key=g_m2_next_key++;
    if(g_m2req_n<24){
        M2Req* q=&g_m2req[g_m2req_n++];
        q->cb=cb; q->arg=arg; q->req=req; q->evt=evt; q->key=key;
        q->data=data; q->size=size; q->ptrofs=ptrofs; q->pending=1;
    }
    LeaveCriticalSection(&g_lock);
    if(reqid_out) PPU_STW(g_base,reqid_out,req);
    fprintf(stderr,"[NP2] %s queued req=%u evt=0x%04x size=%u\n",name,req,evt,size);
}
static int g_np_ticket_fire;
enum { NP_TICKET_SZ = 256 };

static char g_http_path[160];
static char g_http_resp[8192];
static uint32_t g_http_resp_len, g_http_resp_off;
static void wind_build_response(const char* path){
    const char* body = "{\"result\":\"OK\",\"uid\":12345678,\"data\":{}}";
    snprintf(g_http_resp,sizeof g_http_resp,"%s",body);
    g_http_resp_len=(uint32_t)strlen(g_http_resp);
    g_http_resp_off=0;
    fprintf(stderr,"[HTTP-RESP] %s -> %s\n",path,g_http_resp);
}
static void sysutil_push(uint64_t status, uint64_t param){
    EnterCriticalSection(&g_lock);
    if(g_suevt_n<16){ g_suevt[g_suevt_n][0]=status; g_suevt[g_suevt_n][1]=param; g_suevt_n++; }
    LeaveCriticalSection(&g_lock);
}
static uint64_t sysutil_call_guest7(uint32_t opd, uint64_t a, uint64_t b, uint64_t c3,
                                    uint64_t d, uint64_t e, uint64_t f6, uint64_t g7){
    if(!opd) return 0;
    uint32_t code=PPU_LW(g_base,opd), toc=PPU_LW(g_base,opd+4);
    if(!code) return 0;
    PPUContext* c=(PPUContext*)calloc(1,sizeof(PPUContext));
    static __declspec(thread) uint32_t stk;
    if(!stk) stk=guest_alloc_hi(0x10000,0x1000)+0x10000-0x200;
    c->r[1]=stk; c->r[2]=toc; c->r[3]=a; c->r[4]=b; c->r[5]=c3; c->r[6]=d; c->r[7]=e;
    c->r[8]=f6; c->r[9]=g7;
    PPCFunc f=ppu_lookup(code); if(f) f(c,g_base);
    uint64_t rv=c->r[3]; free(c); return rv;
}
static uint64_t sysutil_call_guest5(uint32_t opd, uint64_t a, uint64_t b, uint64_t c3,
                                    uint64_t d, uint64_t e){
    return sysutil_call_guest7(opd,a,b,c3,d,e,0,0);
}
static void sysutil_call_guest(uint32_t opd, uint64_t a, uint64_t b, uint64_t c3){
    sysutil_call_guest5(opd,a,b,c3,0,0);
}

static int misc_hle(const char* name, PPUContext* ctx){
    if (IS("cellAudioInit")||IS("cellAudioQuit")){ R(3)=0; return 1; }
    if (IS("cellAudioPortOpen")){
        uint32_t prm=(uint32_t)R(3), outp=(uint32_t)R(4);
        uint32_t nch=(uint32_t)PPU_LD(g_base,prm), nblk=(uint32_t)PPU_LD(g_base,prm+8);
        if(!nch||nch>8) nch=2; if(!nblk||nblk>32) nblk=8;
        int pi=-1; for(int i=0;i<8;i++) if(!g_aport[i].open){ pi=i; break; }
        if(pi<0){ R(3)=0x80310705u; return 1; }
        AudioPort* ap=&g_aport[pi];
        ap->nch=nch; ap->nblk=nblk; ap->tag=0; ap->ridx=0; ap->consumed=0;
        ap->attr=PPU_LD(g_base,prm+16);
        ap->level=1.0f;
        if(ap->attr&CELL_AUDIO_PORTATTR_INITLEVEL){
            uint32_t u=PPU_LW(g_base,prm+24); float lv; memcpy(&lv,&u,4);
            ap->level = lv<0 ? -lv : lv; }
        ap->level_cur=ap->level;
        ap->portsize=nch*nblk*CELL_AUDIO_BLOCK_SAMPLES*4;
        ap->ridx_ea=guest_alloc_hi(16,16);
        ap->port_ea=guest_alloc_hi(ap->portsize,64);
        PPU_STD(g_base,ap->ridx_ea,0);
        ap->open=1; ap->running=0;
        if(outp) PPU_STW(g_base,outp,(uint32_t)pi);
        fprintf(stderr,"[AUDIO] port %d open nch=%u nblk=%u attr=0x%llx level=%.3f buf=0x%x ridx=0x%x\n",
                pi,nch,nblk,(unsigned long long)ap->attr,ap->level,ap->port_ea,ap->ridx_ea);
        R(3)=0; return 1;
    }
    if (IS("cellAudioGetPortConfig")){
        uint32_t pi=(uint32_t)R(3), cfg=(uint32_t)R(4);
        if(pi>=8||!g_aport[pi].open){ R(3)=0x80310707u; return 1; }
        AudioPort* ap=&g_aport[pi];
        PPU_STW(g_base,cfg+0, ap->ridx_ea);
        PPU_STW(g_base,cfg+4, ap->running?2u:1u);
        PPU_STD(g_base,cfg+8, ap->nch);
        PPU_STD(g_base,cfg+16,ap->nblk);
        PPU_STW(g_base,cfg+24,ap->portsize);
        PPU_STW(g_base,cfg+28,ap->port_ea);
        R(3)=0; return 1;
    }
    if (IS("cellAudioPortStart")){ uint32_t pi=(uint32_t)R(3); if(pi<8&&g_aport[pi].open){ g_aport[pi].running=1; audio_start_pump(); } R(3)=0; return 1; }
    if (IS("cellAudioPortStop")){  uint32_t pi=(uint32_t)R(3); if(pi<8) g_aport[pi].running=0; R(3)=0; return 1; }
    if (IS("cellAudioPortClose")){ uint32_t pi=(uint32_t)R(3); if(pi<8){ g_aport[pi].running=0; g_aport[pi].open=0; } R(3)=0; return 1; }
    if (IS("cellAudioSetNotifyEventQueue")||IS("cellAudioSetNotifyEventQueueEx")){
        uint64_t key=R(3); int i=g_nanotify;
        if(i<8){ g_anotify_key[i]=key; g_nanotify=i+1; }
        fprintf(stderr,"[AUDIO] notify key=0x%llx (queue %s)\n",(unsigned long long)key,evq_find_by_key(key)?"found":"NOT FOUND");
        audio_start_pump(); R(3)=0; return 1;
    }
    if (IS("cellAudioRemoveNotifyEventQueue")||IS("cellAudioRemoveNotifyEventQueueEx")){ R(3)=0; return 1; }
    if (IS("cellAudioCreateNotifyEventQueue")||IS("cellAudioCreateNotifyEventQueueEx")){
        uint32_t idp=(uint32_t)R(3), keyp=(uint32_t)R(4);
        uint32_t id=evq_create(); EvQueue* q=evq_find(id);
        static uint64_t seq=0x80004d494e490000ull;
        uint64_t key=++seq; if(q) q->key=key;
        if(idp) PPU_STW(g_base,idp,id);
        if(keyp) PPU_STD(g_base,keyp,key);
        R(3)=0; return 1;
    }
    if (IS("cellAudioGetPortBlockTag")){
        uint32_t pi=(uint32_t)R(3); uint32_t outp=(uint32_t)R(5);
        if(outp) PPU_STD(g_base,outp,pi<8?g_aport[pi].tag:0);
        R(3)=0; return 1;
    }
    if (IS("cellAudioGetPortTimestamp")){
        uint32_t outp=(uint32_t)R(5);
        LARGE_INTEGER c,f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
        if(outp) PPU_STD(g_base,outp,(uint64_t)(c.QuadPart*1000000ull/f.QuadPart));
        R(3)=0; return 1;
    }
    if (IS("cellAudioSetPortLevel")){
        uint32_t pi=(uint32_t)R(3); float lv=(float)ctx->f[1];
        if(pi>=8||!g_aport[pi].open){ R(3)=0x80310707u; return 1; }
        g_aport[pi].level = lv<0 ? -lv : lv;
        { static int n; if(n++<8) fprintf(stderr,"[AUDIO] port %u level %.3f\n",pi,lv); }
        R(3)=0; return 1; }
    if (IS("cellAudioAddData")||IS("cellAudioAdd2chData")||IS("cellAudioAdd6chData")){
        { static int n; if(n++<4) fprintf(stderr,"[AUDIO] %s ignored (not implemented)\n",name); }
        R(3)=0; return 1; }

    if (IS("cellAudioOutGetState")){
        uint32_t o=(uint32_t)R(5);
        PPU_STB(g_base,o+0,0);
        PPU_STB(g_base,o+1,0);
        PPU_STW(g_base,o+8,0);
        PPU_STB(g_base,o+12,0);
        PPU_STB(g_base,o+13,2);
        PPU_STB(g_base,o+14,0x04);
        PPU_STW(g_base,o+16,1);
        R(3)=0; return 1;
    }
    if (IS("cellAudioOutGetConfiguration")){
        uint32_t o=(uint32_t)R(4);
        PPU_STB(g_base,o+0,2);
        PPU_STB(g_base,o+1,0);
        PPU_STW(g_base,o+12,0);
        R(3)=0; return 1;
    }
    if (IS("cellAudioOutConfigure")){ R(3)=0; return 1; }
    if (IS("cellAudioOutGetSoundAvailability")||IS("cellAudioOutGetSoundAvailability2")){ R(3)=2; return 1; }
    if (IS("cellAudioOutGetNumberOfDevice")){ R(3)=1; return 1; }

    if (IS("cellVideoOutGetNumberOfDevice")){ R(3)=1; return 1; }
    if (IS("cellVideoOutGetState")){
        uint32_t o=(uint32_t)R(5);
        PPU_STB(g_base,o+0,0);
        PPU_STB(g_base,o+1,0x01);
        PPU_STB(g_base,o+8,2);
        PPU_STB(g_base,o+9,1);
        PPU_STB(g_base,o+10,0);
        PPU_STB(g_base,o+11,2);
        PPU_STH(g_base,o+14,0x0001);
        R(3)=0; return 1;
    }
    if (IS("cellVideoOutGetResolution")){
        uint32_t id=(uint32_t)R(3), o=(uint32_t)R(4); uint16_t w=1280,h=720;
        switch(id){ case 1: w=1920;h=1080; break; case 2: w=1280;h=720; break;
                    case 4: w=720;h=480; break; case 5: w=720;h=576; break; }
        PPU_STH(g_base,o,w); PPU_STH(g_base,o+2,h); R(3)=0; return 1;
    }
    if (IS("cellVideoOutGetResolutionAvailability")){ R(3)=1; return 1; }
    if (IS("cellVideoOutConfigure")){ R(3)=0; return 1; }
    if (IS("cellVideoOutGetConfiguration")){
        uint32_t o=(uint32_t)R(4);
        PPU_STB(g_base,o+0,2);
        PPU_STB(g_base,o+1,0);
        PPU_STB(g_base,o+2,2);
        PPU_STW(g_base,o+12,1280*4);
        R(3)=0; return 1;
    }

    if (IS("cellGameBootCheck")){
        if(R(3)) PPU_STW(g_base,(uint32_t)R(3),2);
        if(R(4)) PPU_STW(g_base,(uint32_t)R(4),0);
        if(R(5)){ uint32_t s=(uint32_t)R(5);
            PPU_STW(g_base,s+0,10u*1024*1024);
            PPU_STW(g_base,s+4,4u*1024*1024);
            PPU_STW(g_base,s+8,4096); }
        if(R(6)){ const char* d="NPUB31347"; uint32_t o=(uint32_t)R(6);
            for(int i=0;;i++){ g_base[o+i]=d[i]; if(!d[i]) break; } }
        R(3)=0; return 1;
    }
    if (IS("cellGameContentPermit")){
        static const char ci[]="/dev_hdd0/game/NPUB31347";
        static const char ud[]="/dev_hdd0/game/NPUB31347/USRDIR";
        if(R(3)){ uint32_t o=(uint32_t)R(3); memcpy(g_base+o,ci,sizeof ci); }
        if(R(4)){ uint32_t o=(uint32_t)R(4); memcpy(g_base+o,ud,sizeof ud); }
        R(3)=0; return 1;
    }
    if (IS("cellGameDataCheck")){ R(3)=0; return 1; }
    if (IS("cellGamePatchCheck")){ R(3)=0; return 1; }
    if (IS("cellGameGetParamString")){
        uint32_t buf=(uint32_t)R(4), n=(uint32_t)R(5);
        if(buf&&n) g_base[buf]=0;
        R(3)=0; return 1;
    }
    if (IS("cellGameGetParamInt")){ if(R(4)) PPU_STW(g_base,(uint32_t)R(4),0); R(3)=0; return 1; }
    if (IS("cellGameContentErrorDialog")){ R(3)=0; return 1; }

    if (IS("cellPadInit")||IS("cellPadEnd")||IS("cellPadClearBuf")||IS("cellPadSetActDirect")){ R(3)=0; return 1; }
    if (IS("cellPadSetPortSetting")){
        uint32_t p=(uint32_t)R(3), s=(uint32_t)R(4);
        if(p<7) g_pad_setting[p]=s;
        fprintf(stderr,"[PAD] port %u setting=0x%x (press=%u sensor=%u)\n",
                p,s,(s>>1)&1u,(s>>2)&1u);
        R(3)=0; return 1; }
    if (IS("cellPadGetInfo2")){
        uint32_t o=(uint32_t)R(3);
        for(uint32_t i=0;i<124;i+=4) PPU_STW(g_base,o+i,0);
        PPU_STW(g_base,o+0,7);
        PPU_STW(g_base,o+4,1);
        PPU_STW(g_base,o+12,1);
        PPU_STW(g_base,o+40,g_pad_setting[0]);
        PPU_STW(g_base,o+68,1u|2u|4u|0x10u);
        PPU_STW(g_base,o+96,0);
        R(3)=0; return 1;
    }
    if (IS("cellPadGetData")){
        uint32_t o=(uint32_t)R(4);
        if(o){
            PPU_STW(g_base,o,0);
            if((uint32_t)R(3)==0){
                uint16_t w[24]; uint8_t trig[2];
                pad_host_read(w,trig);
                static int auto_pad=-1, auto_tf=0;
                if(auto_pad<0){ const char* av=getenv("PS3_PAD_AUTO"); auto_pad=0;
                    if(av){
                        if(!_stricmp(av,"testflight")||!_stricmp(av,"test flight")||
                           !_stricmp(av,"test_flight")||!_stricmp(av,"test-flight")||
                           !_stricmp(av,"tf")||!strcmp(av,"3")) auto_tf=1;
                        else { auto_pad=atoi(av); if(!auto_pad) auto_pad=1; } } }
                if(auto_pad){
                    uint64_t ms=GetTickCount64();
                    if(ms%3000<100){
                        int cross=(auto_pad>=2)||((ms/3000)&1);
                        if(cross) w[3]|=0x0040; else w[2]|=0x0008;
                        static long n; if(++n<=20) fprintf(stderr,"[PAD] auto %s pulse\n",cross?"CROSS":"START");
                    }
                    if(auto_pad==1 && ms%3000>=100 && ms%3000<200){}
                }
                { static int hold=-1; static unsigned hd1,hd2;
                  if(hold<0){ const char* hv=getenv("PS3_PAD_HOLD");
                      hold = hv?1:0;
                      if(hv) sscanf(hv,"%x:%x",&hd1,&hd2); }
                  if(hold){ w[2]|=(uint16_t)hd1; w[3]|=(uint16_t)hd2; } }
                { static const char* pp=NULL; static int pp_init=0;
                  static struct { uint16_t d1,d2; uint8_t st,lx,ly,minp; uint32_t ms; } q[512];
                  static int qn=0,qi=0,step_p=0; static uint64_t poll_ms=0, step_t0=0;
                  if(!pp_init){ pp_init=1; const char* v=getenv("PS3_PAD_PIPE");
                      if(v) pp = (v[0]=='1'&&!v[1]) ? "pad_pipe.txt" : v;
                      if(auto_tf){
                        static const struct { uint16_t d1,d2; uint32_t gap; } tf[]={
                          {0,0,12000},
                          {0,0x40,1000},{0,0x40,1000},{0,0x40,2000},
                          {0,0x40,3000},{0,0x40,2000},{0,0x40,9000},
                          {0,0x40,1000},{0,0x40,1000},{0,0x40,1000},
                          {0,0x40,2500},{0,0x40,1000},
                          {0x40,0,500},
                          {0,0x40,6000},{0,0x40,1000},{0,0x40,1000},
                          {0,0x40,1000},{0,0x40,3000},{0,0x40,1500},
                          {0x10,0,1000},
                          {0,0x40,23000},
                        };
                        unsigned skiplast=0;
                        { const char* sl=getenv("PS3_PAD_SKIPLAST");
                          if(sl) skiplast=(unsigned)atoi(sl); }
                        unsigned slack=0;
                        { const char* sk=getenv("PS3_PAD_SLACK");
                          if(sk) slack=(unsigned)atoi(sk); }
                        unsigned tftotal=0;
                        for(unsigned i=0;i<sizeof tf/sizeof tf[0];i++)
                          if(tf[i].d1||tf[i].d2) tftotal++;
                        unsigned tfpressed=0;
                        for(unsigned i=0;i<sizeof tf/sizeof tf[0] && qn<510;i++){
                          if(tf[i].d1||tf[i].d2){
                            if(tfpressed>=tftotal-skiplast) break;
                            tfpressed++;
                            q[qn].d1=tf[i].d1; q[qn].d2=tf[i].d2;
                            q[qn].st=0; q[qn].lx=q[qn].ly=0;
                            q[qn].ms=250; q[qn].minp=4; qn++; }
                          q[qn].d1=0; q[qn].d2=0; q[qn].st=0;
                          q[qn].lx=q[qn].ly=0; q[qn].minp=2;
                          q[qn].ms=tf[i].gap+slack; qn++;
                        }
                        fprintf(stderr,"[PAD] auto testflight: %d step(s) queued\n",qn);
                      } }
                  uint64_t now=GetTickCount64();
                  if(pp){
                    if(now-poll_ms>250){ poll_ms=now;
                      FILE* f=fopen(pp,"rb");
                      if(f){ char ln[256]; int added=0;
                        while(fgets(ln,sizeof ln,f) && qn<512){
                          char btns[128]; unsigned ms=0,sx,sy;
                          uint16_t d1=0,d2=0; uint8_t st=0,lx=0,ly=0;
                          if(sscanf(ln,"wait %u",&ms)==1){ }
                          else if(sscanf(ln,"stick %u %u %u",&sx,&sy,&ms)==3){
                            st=1; lx=(uint8_t)sx; ly=(uint8_t)sy; }
                          else if(sscanf(ln,"press %127s %u",btns,&ms)==2){
                            for(char* t=strtok(btns,"+");t;t=strtok(NULL,"+")){
                              if(!strcmp(t,"select"))d1|=0x01; else if(!strcmp(t,"l3"))d1|=0x02;
                              else if(!strcmp(t,"r3"))d1|=0x04; else if(!strcmp(t,"start"))d1|=0x08;
                              else if(!strcmp(t,"up"))d1|=0x10; else if(!strcmp(t,"right"))d1|=0x20;
                              else if(!strcmp(t,"down"))d1|=0x40; else if(!strcmp(t,"left"))d1|=0x80;
                              else if(!strcmp(t,"l2"))d2|=0x01; else if(!strcmp(t,"r2"))d2|=0x02;
                              else if(!strcmp(t,"l1"))d2|=0x04; else if(!strcmp(t,"r1"))d2|=0x08;
                              else if(!strcmp(t,"triangle"))d2|=0x10; else if(!strcmp(t,"circle"))d2|=0x20;
                              else if(!strcmp(t,"cross"))d2|=0x40; else if(!strcmp(t,"square"))d2|=0x80;
                              else fprintf(stderr,"[PAD] pipe: unknown button '%s'\n",t);
                            }
                          } else continue;
                          q[qn].d1=d1; q[qn].d2=d2; q[qn].st=st;
                          q[qn].lx=lx; q[qn].ly=ly; q[qn].ms=ms;
                          q[qn].minp=2; qn++; added++;
                        }
                        fclose(f); remove(pp);
                        fprintf(stderr,"[PAD] pipe: loaded %d step(s), queue %d/%d\n",added,qi,qn);
                      }
                    }
                  }
                  if(auto_tf && !g_flipno){
                    static int said; if(!said){ said=1;
                      fprintf(stderr,"[PAD] auto testflight: waiting for first flip\n"); }
                  } else
                  if(qi<qn){
                    if(!step_t0){ step_t0=now; step_p=0;
                      fprintf(stderr,"[PAD] pipe step %d/%d: d1=%04x d2=%04x %ums/%up\n",
                              qi+1,qn,q[qi].d1,q[qi].d2,q[qi].ms,q[qi].minp); }
                    step_p++;
                    if(now-step_t0 < q[qi].ms || step_p < q[qi].minp){
                      w[2]|=q[qi].d1; w[3]|=q[qi].d2;
                      if(q[qi].st){ w[6]=q[qi].lx; w[7]=q[qi].ly; } }
                    else { qi++; step_t0=0; if(qi==qn){ qi=qn=0; fprintf(stderr,"[PAD] pipe: queue done\n"); } }
                  }
                  static int tf_hold=-1;
                  if(tf_hold<0) tf_hold=getenv("PS3_PAD_SKIPLAST")?1:0;
                  if(auto_tf && !tf_hold && qn==0 && g_flipno){
                    q[qn].d1=0; q[qn].d2=0; q[qn].st=0;
                    q[qn].lx=q[qn].ly=0; q[qn].ms=220000; q[qn].minp=2; qn++;
                    for(int k=0;k<40 && qn<510;k++){
                      q[qn].d1=0; q[qn].d2=0x40; q[qn].st=0;
                      q[qn].lx=q[qn].ly=0; q[qn].ms=250; q[qn].minp=4; qn++;
                      q[qn].d1=0; q[qn].d2=0; q[qn].st=0;
                      q[qn].lx=q[qn].ly=0; q[qn].ms=4000; q[qn].minp=2; qn++; }
                    qi=0; step_t0=0;
                    fprintf(stderr,"[PAD] auto testflight: retry cycle queued "
                                   "(%ums quiet, then CROSS x%d)\n",q[0].ms,(qn-1)/2);
                  }
                }
                w[8]  = (w[2]&0x20)?255:0;
                w[9]  = (w[2]&0x80)?255:0;
                w[10] = (w[2]&0x10)?255:0;
                w[11] = (w[2]&0x40)?255:0;
                w[12] = (w[3]&0x10)?255:0;
                w[13] = (w[3]&0x20)?255:0;
                w[14] = (w[3]&0x40)?255:0;
                w[15] = (w[3]&0x80)?255:0;
                w[16] = (w[3]&0x04)?255:0;
                w[17] = (w[3]&0x08)?255:0;
                w[18] = trig[0]?trig[0]:((w[3]&0x01)?255:0);
                w[19] = trig[1]?trig[1]:((w[3]&0x02)?255:0);
                w[20]=w[21]=w[22]=w[23]=512;
                uint32_t nw = (g_pad_setting[0]&4u) ? 24u
                            : (g_pad_setting[0]&2u) ? 20u : 8u;
                PPU_STW(g_base,o,nw);
                for(int i=0;i<24;i++) PPU_STH(g_base,o+4+i*2,w[i]);
                { static uint16_t lastd1, lastd2; static long pn;
                  if((w[2]!=lastd1||w[3]!=lastd2) && (w[2]||w[3]) && pn<40){ pn++;
                      fprintf(stderr,"[PAD] d1=%04x d2=%04x lx=%u ly=%u rx=%u ry=%u "
                              "l2=%u r2=%u len=%u\n",
                              w[2],w[3],w[6],w[7],w[4],w[5],w[18],w[19],nw); }
                  lastd1=w[2]; lastd2=w[3]; }
            }
        }
        R(3)=0; return 1;
    }

    if (IS("cellSysutilGetSystemParamInt")){
        uint32_t id=(uint32_t)R(3), o=(uint32_t)R(4); uint32_t v=0;
        if(id==0x0111) v=1;
        else if(id==0x0112) v=1;
        if(o) PPU_STW(g_base,o,v);
        R(3)=0; return 1;
    }
    if (IS("cellSysutilGetSystemParamString")){
        uint32_t buf=(uint32_t)R(4), n=(uint32_t)R(5);
        if(buf&&n){ const char* s="recomp"; uint32_t i=0; for(;s[i]&&i+1<n;i++) g_base[buf+i]=s[i]; g_base[buf+i]=0; }
        R(3)=0; return 1;
    }

    if (IS("cellRtcGetCurrentTick")){
        uint32_t o=(uint32_t)R(3);
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        uint64_t t1601=((uint64_t)ft.dwHighDateTime<<32)|ft.dwLowDateTime;
        uint64_t tick=t1601/10ull + 50491123200000000ull;
        if(o) PPU_STD(g_base,o,tick);
        R(3)=0; return 1;
    }
    if (IS("cellRtcGetCurrentClock")||IS("cellRtcGetCurrentClockLocalTime")){
        uint32_t dt=(uint32_t)R(3);
        if(dt){
            SYSTEMTIME st; GetSystemTime(&st);
            PPU_STH(g_base,dt+0,st.wYear); PPU_STH(g_base,dt+2,st.wMonth); PPU_STH(g_base,dt+4,st.wDay);
            PPU_STH(g_base,dt+6,st.wHour); PPU_STH(g_base,dt+8,st.wMinute); PPU_STH(g_base,dt+10,st.wSecond);
            PPU_STW(g_base,dt+12,(uint32_t)st.wMilliseconds*1000u);
        }
        R(3)=0; return 1; }
    if (IS("cellRtcConvertUtcToLocalTime")||IS("cellRtcConvertLocalTimeToUtc")){
        uint32_t in=(uint32_t)R(3), out=(uint32_t)R(4);
        if(in&&out) PPU_STD(g_base,out,PPU_LD(g_base,in));
        R(3)=0; return 1;
    }
    if (IS("cellRtcGetTick")){
        uint32_t dt=(uint32_t)R(3), tk=(uint32_t)R(4);
        if(dt&&tk){
            int64_t y=PPU_LH(g_base,dt+0), m=PPU_LH(g_base,dt+2), d=PPU_LH(g_base,dt+4);
            y-= m<=2; int64_t era=(y>=0?y:y-399)/400; uint64_t yoe=(uint64_t)(y-era*400);
            uint64_t doy=(153*(uint64_t)(m>2?m-3:m+9)+2)/5+(uint64_t)d-1;
            uint64_t doe=yoe*365+yoe/4-yoe/100+doy;
            int64_t days=era*146097+(int64_t)doe-306;
            uint64_t us=(uint64_t)days*86400000000ull
                + (uint64_t)PPU_LH(g_base,dt+6)*3600000000ull
                + (uint64_t)PPU_LH(g_base,dt+8)*60000000ull
                + (uint64_t)PPU_LH(g_base,dt+10)*1000000ull
                + PPU_LW(g_base,dt+12);
            PPU_STD(g_base,tk,us);
        }
        R(3)=0; return 1;
    }
    if (IS("cellRtcSetTick")){
        uint32_t dt=(uint32_t)R(3), tk=(uint32_t)R(4);
        uint64_t us=tk?PPU_LD(g_base,tk):0;
        uint64_t days=us/86400000000ull, rem=us%86400000000ull;
        int64_t z=(int64_t)days; z+=306;
        int64_t era=(z>=0?z:z-146096)/146097; uint64_t doe=(uint64_t)(z-era*146097);
        uint64_t yoe=(doe-doe/1460+doe/36524-doe/146096)/365;
        int64_t y=(int64_t)yoe+era*400;
        uint64_t doy=doe-(365*yoe+yoe/4-yoe/100);
        uint64_t mp=(5*doy+2)/153, d=doy-(153*mp+2)/5+1, m=mp<10?mp+3:mp-9;
        if(m<=2) y++;
        if(dt){
            PPU_STH(g_base,dt+0,(uint16_t)y); PPU_STH(g_base,dt+2,(uint16_t)m); PPU_STH(g_base,dt+4,(uint16_t)d);
            PPU_STH(g_base,dt+6,(uint16_t)(rem/3600000000ull));
            PPU_STH(g_base,dt+8,(uint16_t)(rem/60000000ull%60));
            PPU_STH(g_base,dt+10,(uint16_t)(rem/1000000ull%60));
            PPU_STW(g_base,dt+12,(uint32_t)(rem%1000000ull));
        }
        R(3)=0; return 1;
    }

    if (IS("cellSysutilRegisterCallback")){
        uint32_t s=(uint32_t)R(3)&3; g_sucb[s]=(uint32_t)R(4); g_suarg[s]=(uint32_t)R(5);
        fprintf(stderr,"[SYSUTIL] cb slot %u = opd 0x%x arg 0x%x\n",s,g_sucb[s],g_suarg[s]);
        R(3)=0; return 1; }
    if (IS("cellSysutilUnregisterCallback")){ g_sucb[(uint32_t)R(3)&3]=0; R(3)=0; return 1; }
    if (IS("cellSysutilCheckCallback")){
        if(g_netstart_phase==1){ sysutil_push(0x0801,0); g_netstart_phase=2; g_netstart_t0=GetTickCount(); }
        else if(g_netstart_phase==2 && GetTickCount()-g_netstart_t0>400){
            g_netstart_phase=0;
            g_np_status=3; g_np_cb_fire=1;
            sysutil_push(0x0802,0);
            fprintf(stderr,"[NETCTL] netstart finished -> NP online\n");
        }
        for(;;){
            uint64_t st=0,pa=0; int have=0;
            EnterCriticalSection(&g_lock);
            if(g_suevt_n){ st=g_suevt[0][0]; pa=g_suevt[0][1];
                g_suevt_n--; memmove(g_suevt,g_suevt+1,(size_t)g_suevt_n*sizeof g_suevt[0]); have=1; }
            LeaveCriticalSection(&g_lock);
            if(!have) break;
            for(int s=0;s<4;s++) if(g_sucb[s]) sysutil_call_guest(g_sucb[s],st,pa,g_suarg[s]);
        }
        if(g_np_cb_fire){ g_np_cb_fire=0;
            if(g_np_cb) sysutil_call_guest(g_np_cb,(uint64_t)(uint32_t)g_np_status,0,g_np_arg); }
        if(g_m2_fire){ g_m2_fire=0;
            if(g_m2_cb){ fprintf(stderr,"[NP2] matching2 context started\n");
                sysutil_call_guest5(g_m2_cb,1,0x6f02,11,0,g_m2_arg); } }
        if(g_np_ticket_fire){ g_np_ticket_fire=0;
            if(g_np_cb){ fprintf(stderr,"[NP] ticket ready (%d bytes)\n",NP_TICKET_SZ);
                sysutil_call_guest(g_np_cb,255,NP_TICKET_SZ,g_np_arg); } }
        for(;;){
            M2Req r; int have=0;
            EnterCriticalSection(&g_lock);
            for(int i=0;i<g_m2req_n;i++) if(g_m2req[i].pending){ g_m2req[i].pending=0; r=g_m2req[i]; have=1; break; }
            LeaveCriticalSection(&g_lock);
            if(!have) break;
            fprintf(stderr,"[NP2] deliver req=%u evt=0x%04x key=0x%x size=%u\n",r.req,r.evt,r.key,r.size);
            if(r.cb) sysutil_call_guest7(r.cb,1,r.req,r.evt,r.key,0,r.size,r.arg);
        }
        R(3)=0; return 1; }

    if (IS("sceNpManagerGetStatus")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),(uint32_t)g_np_status); R(3)=0; return 1; }
    if (IS("sceNpManagerRegisterCallback")){
        g_np_cb=(uint32_t)R(3); g_np_arg=(uint32_t)R(4);
        if(g_np_status==3) g_np_cb_fire=1;
        R(3)=0; return 1; }
    if (IS("sceNpManagerUnregisterCallback")){ g_np_cb=0; R(3)=0; return 1; }
    if (IS("sceNpManagerGetNpId")){
        uint32_t o=(uint32_t)R(3);
        if(o){ memset(g_base+o,0,36); memcpy(g_base+o,"recomp",6); }
        R(3)=0; return 1; }
    if (IS("sceNpManagerGetOnlineName")){
        uint32_t o=(uint32_t)R(3);
        if(o){ memset(g_base+o,0,48); memcpy(g_base+o,"recomp",6); }
        R(3)=0; return 1; }
    if (IS("sceNpManagerGetAvatarUrl")){ uint32_t o=(uint32_t)R(3); if(o) g_base[o]=0; R(3)=0; return 1; }
    if (IS("sceNpManagerGetAccountAge")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),25); R(3)=0; return 1; }
    if (IS("sceNpManagerGetAccountRegion")){
        uint32_t cc=(uint32_t)R(3), lg=(uint32_t)R(4);
        if(cc){ g_base[cc]='u'; g_base[cc+1]='s'; g_base[cc+2]=0; g_base[cc+3]=0; }
        if(lg) PPU_STW(g_base,lg,1);
        R(3)=0; return 1; }
    if (IS("sceNpManagerGetContentRatingFlag")){
        if(R(3)) PPU_STW(g_base,(uint32_t)R(3),0);
        if(R(4)) PPU_STW(g_base,(uint32_t)R(4),25);
        R(3)=0; return 1; }
    if (IS("sceNpManagerGetChatRestrictionFlag")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),0); R(3)=0; return 1; }
    if (IS("sceNpManagerGetMyLanguages")){
        uint32_t o=(uint32_t)R(3);
        if(o){ PPU_STW(g_base,o,1); PPU_STW(g_base,o+4,(uint32_t)-1); PPU_STW(g_base,o+8,(uint32_t)-1); PPU_STW(g_base,o+12,0); }
        R(3)=0; return 1; }
    if (IS("sceNpManagerGetNetworkTime")){
        if(g_np_status!=3){ R(3)=0x8002aa0cu; return 1; }
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        uint64_t t1601=((uint64_t)ft.dwHighDateTime<<32)|ft.dwLowDateTime;
        if(R(3)) PPU_STD(g_base,(uint32_t)R(3),t1601/10ull+50491123200000000ull);
        R(3)=0; return 1; }
    if (IS("sceNpTrophyCreateContext")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),1); R(3)=0; return 1; }
    if (IS("sceNpTrophyCreateHandle")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),1); R(3)=0; return 1; }
    if (IS("sceNpTrophyRegisterContext")){
        uint32_t cb=(uint32_t)R(5); uint64_t ctxid=R(3), arg=R(6);
        if(cb){
            sysutil_call_guest5(cb,ctxid,6,0,0,arg);
            sysutil_call_guest5(cb,ctxid,7,100,100,arg);
            sysutil_call_guest5(cb,ctxid,8,0,0,arg);
            sysutil_call_guest5(cb,ctxid,9,0,0,arg);
        }
        R(3)=0; return 1; }
    if (IS("sceNpTrophyGetRequiredDiskSpace")){ if(R(5)) PPU_STD(g_base,(uint32_t)R(5),0); R(3)=0; return 1; }

    if (IS("cellSaveDataAutoLoad2")){ R(3)=0x8002b304u; return 1; }

    if (IS("sceNpManagerRequestTicket")||IS("sceNpManagerRequestTicket2")){
        g_np_ticket_fire=1; R(3)=0; return 1; }
    if (IS("sceNpManagerGetTicket")){
        uint32_t buf=(uint32_t)R(3), szp=(uint32_t)R(4);
        if(!buf){ if(szp) PPU_STW(g_base,szp,NP_TICKET_SZ); R(3)=0; return 1; }
        uint32_t want=szp?(uint32_t)PPU_LW(g_base,szp):NP_TICKET_SZ;
        if(want>NP_TICKET_SZ) want=NP_TICKET_SZ;
        memset(g_base+buf,0,want);
        PPU_STW(g_base,buf+0,0x00020001u);
        PPU_STW(g_base,buf+4,NP_TICKET_SZ-8);
        memcpy(g_base+buf+8,"recomp-ticket",13);
        if(szp) PPU_STW(g_base,szp,want);
        R(3)=0; return 1; }

    if (IS("sceNpMatching2CreateContext")){
        if(R(6)) PPU_STH(g_base,(uint32_t)R(6),1);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2RegisterContextCallback")){
        g_m2_cb=(uint32_t)R(4); g_m2_arg=(uint32_t)R(5); R(3)=0; return 1; }
    if (IS("sceNpMatching2ContextStartAsync")){ g_m2_fire=1; R(3)=0; return 1; }
    if (IS("sceNpMatching2ContextStop")){
        if(g_m2_cb) sysutil_call_guest5(g_m2_cb,1,0x6f03,11,0,g_m2_arg);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2GetServerIdListLocal")){
        uint32_t ids=(uint32_t)R(4), num=(uint32_t)R(5);
        if(ids&&num>=1) PPU_STH(g_base,ids,1);
        R(3)=1; return 1; }
    if (IS("sceNpMatching2GetServerInfo")){
        uint32_t rq=(uint32_t)R(4);
        uint16_t sid = rq? (uint16_t)PPU_LH(g_base,rq) : 1;
        uint32_t d=m2_arena_alloc(4);
        PPU_STH(g_base,d,sid);
        g_base[d+2]=1;
        m2_queue(name,(uint32_t)R(5),(uint32_t)R(6),0x0001,d,4,~0u);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2GetWorldInfoList")){
        uint32_t d=m2_arena_alloc(8+60);
        PPU_STW(g_base,d,d+8); PPU_STW(g_base,d+4,1);
        PPU_STW(g_base,d+8,1);
        m2_queue(name,(uint32_t)R(5),(uint32_t)R(6),0x0002,d,8+60,0);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2SetUserInfo")){
        m2_queue(name,(uint32_t)R(5),(uint32_t)R(6),0x0007,0,0,~0u);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2SearchRoom")){
        uint32_t d=m2_arena_alloc(16);
        m2_queue(name,(uint32_t)R(5),(uint32_t)R(6),0x0106,d,16,~0u);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2GetRoomDataExternalList")){
        uint32_t d=m2_arena_alloc(16);
        m2_queue(name,(uint32_t)R(5),(uint32_t)R(6),0x0005,d,16,~0u);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2GetEventData")){
        uint32_t key=(uint32_t)R(4), buf=(uint32_t)R(5), bl=(uint32_t)R(6);
        uint32_t copied=0;
        EnterCriticalSection(&g_lock);
        for(int i=0;i<g_m2req_n;i++){
            M2Req* q=&g_m2req[i];
            if(q->key==key && !q->pending){
                copied = q->size<bl? q->size : bl;
                if(buf&&copied) memcpy(g_base+buf,g_base+q->data,copied);
                if(buf && q->ptrofs!=~0u && q->ptrofs+4<=copied){
                    uint32_t v=(uint32_t)PPU_LW(g_base,buf+q->ptrofs);
                    if(v) PPU_STW(g_base,buf+q->ptrofs, buf + (v - q->data));
                }
                memmove(q,q+1,(g_m2req_n-i-1)*sizeof(M2Req)); g_m2req_n--;
                break;
            }
        }
        LeaveCriticalSection(&g_lock);
        R(3)=copied; return 1; }
    if (IS("sceNpMatching2ClearEventData")){
        uint32_t key=(uint32_t)R(4);
        EnterCriticalSection(&g_lock);
        for(int i=0;i<g_m2req_n;i++) if(g_m2req[i].key==key && !g_m2req[i].pending){
            memmove(&g_m2req[i],&g_m2req[i+1],(g_m2req_n-i-1)*sizeof(M2Req)); g_m2req_n--; break; }
        LeaveCriticalSection(&g_lock);
        R(3)=0; return 1; }
    if (IS("sceNpMatching2AbortRequest")){ R(3)=0; return 1; }

    if (IS("sceNpTusInit")||IS("sceNpTusTerm")||IS("sceNpTusDestroyTitleCtx")||
        IS("sceNpTusDestroyTransactionCtx")||IS("sceNpTusAbortTransaction")){ R(3)=0; return 1; }
    if (IS("sceNpTusCreateTitleCtx")){ R(3)=1; return 1; }
    if (IS("sceNpTusCreateTransactionCtx")){ R(3)=2; return 1; }
    if (IS("sceNpTssGetData")){
        uint32_t st=(uint32_t)R(5), stsz=(uint32_t)R(6);
        if(st && stsz && (uint64_t)st+stsz<=g_size) memset(g_base+st,0,stsz);
        R(3)=0; return 1; }
    if (IS("sceNpTusPollAsync")||IS("sceNpTusWaitAsync")){
        if(R(4)) PPU_STW(g_base,(uint32_t)R(4),0);
        R(3)=0; return 1; }

    if (IS("cellSslInit")||IS("cellSslEnd")||IS("cellHttpsInit")||IS("cellHttpsEnd")||
        IS("cellHttpInit")||IS("cellHttpEnd")||IS("cellHttpInitCookie")||IS("cellHttpEndCookie")){ R(3)=0; return 1; }
    if (IS("cellSslCertificateLoader")){
        static const char pem[] =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBrecompDummyCertificateBodyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----END CERTIFICATE-----\n";
        uint32_t buf=(uint32_t)R(4), sz=(uint32_t)R(5), req=(uint32_t)R(6);
        if(req) PPU_STW(g_base,req,(uint32_t)sizeof(pem)-1);
        if(buf&&sz){ uint32_t n=(uint32_t)sizeof(pem)-1; if(n>sz) n=sz; memcpy(g_base+buf,pem,n); }
        R(3)=0; return 1; }
    if (IS("cellHttpCreateClient")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),1); R(3)=0; return 1; }
    if (IS("cellHttpDestroyClient")||!strncmp(name,"cellHttpClientSet",17)){ R(3)=0; return 1; }
    if (IS("cellHttpCreateTransaction")){
        uint32_t mp=(uint32_t)R(5), up=(uint32_t)R(6);
        const char* mth = (mp && mp<g_size)? (const char*)(g_base+mp) : "?";
        const char *host="?", *path="?";
        if(up && (uint64_t)up+24<=g_size){
            uint32_t hp=(uint32_t)PPU_LW(g_base,up+4), pp=(uint32_t)PPU_LW(g_base,up+16);
            if(hp&&hp<g_size) host=(const char*)(g_base+hp);
            if(pp&&pp<g_size) path=(const char*)(g_base+pp);
        }
        fprintf(stderr,"[HTTP] %s %s %s\n",mth,host,path);
        snprintf(g_http_path,sizeof g_http_path,"%s",path);
        if(R(3)) PPU_STW(g_base,(uint32_t)R(3),1);
        R(3)=0; return 1; }
    if (IS("cellHttpDestroyTransaction")||IS("cellHttpTransactionCloseConnection")||
        IS("cellHttpTransactionAbortConnection")||!strncmp(name,"cellHttpRequest",15)){ R(3)=0; return 1; }
    if (IS("cellHttpUtilEscapeUri")||IS("cellHttpUtilFormUrlEncode")){
        uint32_t out=(uint32_t)R(3), osz=(uint32_t)R(4), in=(uint32_t)R(5), isz=(uint32_t)R(6), req=(uint32_t)R(7);
        if(!in||!isz){ R(3)=0x80711004u; return 1; }
        uint32_t need=1;
        for(uint32_t i=0;i<isz;i++){
            uint8_t c=g_base[in+i];
            int plain=(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='.'||c=='_'||c=='~';
            need += plain?1:3;
        }
        if(req) PPU_STW(g_base,req,need);
        if(out){
            if(osz<need){ R(3)=0x80711005u; return 1; }
            static const char hx[]="0123456789ABCDEF";
            uint32_t o=out;
            for(uint32_t i=0;i<isz;i++){
                uint8_t c=g_base[in+i];
                int plain=(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='.'||c=='_'||c=='~';
                if(plain) g_base[o++]=c;
                else { g_base[o++]='%'; g_base[o++]=hx[c>>4]; g_base[o++]=hx[c&0xf]; }
            }
            g_base[o]=0;
        }
        R(3)=0; return 1; }
    if (IS("cellHttpUtilBase64Encoder")){
        uint32_t out=(uint32_t)R(3), in=(uint32_t)R(4), len=(uint32_t)R(5);
        if(!in||!len){ R(3)=0x80711004u; return 1; }
        if(!out){ R(3)=0x80711002u; return 1; }
        static const char b64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint32_t o=out;
        for(uint32_t i=0;i<len;i+=3){
            uint32_t r=len-i;
            uint32_t v=(uint32_t)g_base[in+i]<<16;
            if(r>1) v|=(uint32_t)g_base[in+i+1]<<8;
            if(r>2) v|=(uint32_t)g_base[in+i+2];
            g_base[o++]=b64[(v>>18)&63];
            g_base[o++]=b64[(v>>12)&63];
            g_base[o++]=(r>1)?b64[(v>>6)&63]:'=';
            g_base[o++]=(r>2)?b64[v&63]:'=';
        }
        g_base[o]=0;
        R(3)=0; return 1; }
    if (IS("cellHttpUtilBase64Decoder")){
        uint32_t out=(uint32_t)R(3), in=(uint32_t)R(4), len=(uint32_t)R(5);
        if(!in){ R(3)=0x80711004u; return 1; }
        if(len&3){ R(3)=0x80711006u; return 1; }
        if(!out){ R(3)=0x80711002u; return 1; }
        uint32_t o=out;
        for(uint32_t i=0;i<len;i+=4){
            uint32_t v=0; int nb=3;
            for(int k=0;k<4;k++){
                uint8_t c=g_base[in+i+k]; uint32_t d=0;
                if(c>='A'&&c<='Z') d=c-'A';
                else if(c>='a'&&c<='z') d=c-'a'+26;
                else if(c>='0'&&c<='9') d=c-'0'+52;
                else if(c=='+') d=62;
                else if(c=='/') d=63;
                else if(c=='='){ d=0; nb--; }
                v=(v<<6)|d;
            }
            g_base[o++]=(uint8_t)(v>>16);
            if(nb>1) g_base[o++]=(uint8_t)(v>>8);
            if(nb>2) g_base[o++]=(uint8_t)v;
        }
        R(3)=0; return 1; }
    if (IS("cellHttpSendRequest")){
        uint32_t bp=(uint32_t)R(4), bl=(uint32_t)R(5);
        if(bp && bl && (uint64_t)bp+bl<=g_size)
            fprintf(stderr,"[HTTP-REQ] %s <- %.*s\n",g_http_path,(int)(bl>1024?1024:bl),(const char*)(g_base+bp));
        wind_build_response(g_http_path);
        if(R(6)) PPU_STW(g_base,(uint32_t)R(6),bl);
        R(3)=0; return 1; }
    if (IS("cellHttpRecvResponse")){
        uint32_t buf=(uint32_t)R(4), sz=(uint32_t)R(5), rp=(uint32_t)R(6);
        uint32_t left = g_http_resp_len - g_http_resp_off;
        uint32_t n = left<sz? left : sz;
        if(n && buf && (uint64_t)buf+n<=g_size) memcpy(g_base+buf,g_http_resp+g_http_resp_off,n);
        g_http_resp_off += n;
        if(rp) PPU_STW(g_base,rp,n);
        R(3)=0; return 1; }
    if (IS("cellHttpResponseGetStatusCode")){ if(R(4)) PPU_STW(g_base,(uint32_t)R(4),200); R(3)=0; return 1; }
    if (IS("cellHttpResponseGetContentLength")){ if(R(4)) PPU_STD(g_base,(uint32_t)R(4),(uint64_t)g_http_resp_len); R(3)=0; return 1; }
    if (IS("cellHttpResponseGetAllHeaders")){
        static const char* const hdr[][2] = {
            { "oauth_token",        "recomp-oauth-token" },
            { "oauth_token_secret", "recomp-oauth-secret" },
            { "Content-Type",       "application/json;charset=utf-8" },
        };
        enum { NH = 3 };
        uint32_t need = NH*8;
        for (int i=0;i<NH;i++) need += (uint32_t)strlen(hdr[i][0])+1+(uint32_t)strlen(hdr[i][1])+1;
        uint32_t pool=(uint32_t)R(6), poolsz=(uint32_t)R(7);
        if(R(8)) PPU_STW(g_base,(uint32_t)R(8),need);
        if(pool && poolsz>=need && (uint64_t)pool+need<=g_size){
            uint32_t sp = pool + NH*8;
            for (int i=0;i<NH;i++){
                uint32_t nl=(uint32_t)strlen(hdr[i][0])+1, vl=(uint32_t)strlen(hdr[i][1])+1;
                memcpy(g_base+sp,hdr[i][0],nl);
                memcpy(g_base+sp+nl,hdr[i][1],vl);
                PPU_STW(g_base,pool+i*8,  sp);
                PPU_STW(g_base,pool+i*8+4,sp+nl);
                sp += nl+vl;
            }
            if(R(4)) PPU_STW(g_base,(uint32_t)R(4),pool);
            if(R(5)) PPU_STW(g_base,(uint32_t)R(5),NH);
        }
        R(3)=0; return 1; }

    if (IS("cellNetCtlGetState")){ if(R(3)) PPU_STW(g_base,(uint32_t)R(3),3); R(3)=0; return 1; }
    if (IS("cellNetCtlAddHandler")){ if(R(5)) PPU_STW(g_base,(uint32_t)R(5),1); R(3)=0; return 1; }
    if (IS("cellNetCtlDelHandler")){ R(3)=0; return 1; }
    if (IS("cellNetCtlNetStartDialogLoadAsync")){ g_netstart_phase=1; R(3)=0; return 1; }
    if (IS("cellNetCtlNetStartDialogAbortAsync")){ if(g_netstart_phase){ g_netstart_phase=2; g_netstart_t0=0; } R(3)=0; return 1; }
    if (IS("cellNetCtlNetStartDialogUnloadAsync")){
        if(R(3)) PPU_STW(g_base,(uint32_t)R(3)+4,0);
        sysutil_push(0x0803,0);
        R(3)=0; return 1; }
    if (IS("cellNetCtlGetInfo")){
        uint32_t code=(uint32_t)R(3), o=(uint32_t)R(4);
        if(o){
            memset(g_base+o,0,16);
            const char* s=0;
            switch(code){
            case 4:  PPU_STW(g_base,o,1);    break;
            case 3:  PPU_STW(g_base,o,1500); break;
            case 16: s="192.168.1.2";   break;
            case 17: s="255.255.255.0"; break;
            case 18: s="192.168.1.1";   break;
            case 19: case 20: s="8.8.8.8"; break;
            default: break;
            }
            if(s) memcpy(g_base+o,s,strlen(s)+1);
        }
        R(3)=0; return 1; }
    if (IS("cellNetCtlGetNatInfo")){
        uint32_t o=(uint32_t)R(3);
        if(o){ PPU_STW(g_base,o+4,1); PPU_STW(g_base,o+8,1); PPU_STW(g_base,o+12,2); PPU_STW(g_base,o+16,0); }
        R(3)=0; return 1; }

    if (IS("cellFiberPpuSelf")){ R(3)=0; return 1; }
    if (IS("cellFiberPpuWaitSignal")){
        static int warned=0; if(!warned++) fprintf(stderr,"[FIBER] WaitSignal called outside fiber context!\n");
        R(3)=0x80760004u; return 1;
    }
    if (IS("_cellFiberPpuInitialize")||IS("cellFiberPpuInitialize")){ R(3)=0; return 1; }
    return 0;
}

typedef struct GFiber {
    uint32_t ea, entry_opd, stack_ea, stack_size; uint64_t arg;
    void* hf;
    int started, done;
    uint32_t incoming_from_ea;
    uint32_t resume_from_out;
} GFiber;
enum { NGFIB = 512 };
static GFiber* g_fibers[NGFIB];
static __declspec(thread) void*   t_thread_hf;
static __declspec(thread) GFiber* t_cur_fib;
static __declspec(thread) int     t_ret_cause;
static __declspec(thread) uint32_t t_ret_fiber_ea;

static GFiber* fib_find(uint32_t ea){
    for(int i=0;i<NGFIB;i++) if(g_fibers[i]&&g_fibers[i]->ea==ea) return g_fibers[i];
    return 0;
}
static void CALLBACK fib_main(void* p){
    GFiber* f=(GFiber*)p;
    for(;;){
        PPUContext* c=(PPUContext*)calloc(1,sizeof(PPUContext));
        c->r[1]=f->stack_ea+f->stack_size-0x200;
        c->r[2]=PPU_LW(g_base,f->entry_opd+4);
        c->r[3]=f->arg;
        c->r[4]=f->incoming_from_ea;
        uint32_t code=PPU_LW(g_base,f->entry_opd);
        PPCFunc fn=ppu_lookup(code);
        if(fn) fn(c,g_base);
        free(c);
        f->done=1; t_ret_cause=0; t_ret_fiber_ea=f->ea;
        SwitchToFiber(t_thread_hf);
    }
}
static void fib_resume_outputs(GFiber* f){
    if(f->resume_from_out){
        PPU_STW(g_base,f->resume_from_out,f->incoming_from_ea);
        f->resume_from_out=0;
    }
}
static int fiber_hle(const char* name, PPUContext* ctx){
    { static long n; if(++n<=24) fprintf(stderr,"[FIBER] %s r3=0x%llx r4=0x%llx lr=0x%llx\n",name,
        (unsigned long long)R(3),(unsigned long long)R(4),(unsigned long long)ctx->lr); }
    if (IS("cellFiberPpuContextInitialize")){
        uint32_t ea=(uint32_t)R(3);
        GFiber* f=fib_find(ea);
        if(!f){ f=(GFiber*)calloc(1,sizeof *f);
            EnterCriticalSection(&g_lock);
            for(int i=0;i<NGFIB;i++) if(!g_fibers[i]){ g_fibers[i]=f; break; }
            LeaveCriticalSection(&g_lock); }
        f->ea=ea; f->entry_opd=(uint32_t)R(4); f->arg=R(5);
        f->stack_ea=(uint32_t)R(6); f->stack_size=(uint32_t)R(7);
        f->started=f->done=0; f->incoming_from_ea=0; f->resume_from_out=0;
        if(!f->hf) f->hf=CreateFiberEx(0x40000,0x100000,0,fib_main,f);
        R(3)=0; return 1;
    }
    if (IS("cellFiberPpuContextFinalize")){
        uint32_t ea=(uint32_t)R(3); GFiber* f=fib_find(ea);
        if(f && f!=t_cur_fib){
            EnterCriticalSection(&g_lock);
            for(int i=0;i<NGFIB;i++) if(g_fibers[i]==f) g_fibers[i]=0;
            LeaveCriticalSection(&g_lock);
            if(f->hf) DeleteFiber(f->hf);
            free(f);
        }
        R(3)=0; return 1;
    }
    if (IS("cellFiberPpuContextRun")){
        uint32_t to=(uint32_t)R(3), cause_out=(uint32_t)R(4), from_out=(uint32_t)R(5);
        GFiber* f=fib_find(to);
        if(!f){ R(3)=0x80410a01u; return 1; }
        if(!t_thread_hf) t_thread_hf=ConvertThreadToFiberEx(0,0);
        f->incoming_from_ea=0;
        t_cur_fib=f;
        SwitchToFiber(f->hf);
        t_cur_fib=0;
        if(cause_out) PPU_STW(g_base,cause_out,(uint32_t)t_ret_cause);
        if(from_out)  PPU_STW(g_base,from_out,t_ret_fiber_ea);
        R(3)=0; return 1;
    }
    if (IS("cellFiberPpuContextSwitch")){
        uint32_t to=(uint32_t)R(3), from_out=(uint32_t)R(4);
        GFiber* me=t_cur_fib, *f=fib_find(to);
        if(!f || !me){ R(3)=0x80410a02u; return 1; }
        me->resume_from_out=from_out;
        f->incoming_from_ea=me->ea;
        t_cur_fib=f;
        SwitchToFiber(f->hf);
        t_cur_fib=me;
        fib_resume_outputs(me);
        R(3)=0; return 1;
    }
    if (IS("cellFiberPpuContextReturnToThread")){
        GFiber* me=t_cur_fib;
        if(!me){ R(3)=0x80410a02u; return 1; }
        t_ret_cause=(int)(int32_t)R(3); t_ret_fiber_ea=me->ea;
        SwitchToFiber(t_thread_hf);
        t_cur_fib=me;
        fib_resume_outputs(me);
        R(3)=0; return 1;
    }
    if (IS("cellFiberPpuContextSelf")){ R(3)=t_cur_fib?t_cur_fib->ea:0; return 1; }
    if (IS("cellFiberPpuContextCheckStackLimit")){ R(3)=0; return 1; }
    if (IS("_cellFiberPpuContextAttributeInitialize")||IS("cellFiberPpuContextAttributeInitialize")){ R(3)=0; return 1; }
    return 0;
}

#define SYS_SPU_THREAD_EVENT_USER_KEY 0xFFFFFFFF53505501ull
static int spu_intr_route(SpuThread* st, uint32_t intr, uint32_t data1){
    uint32_t code = intr>>24, data0 = intr&0xffffff;
    if (code==128 || code==192){
        uint32_t bit = data0 & 63;
        { static uint32_t dbg=0xffffffffu;
          if(dbg==0xffffffffu){ const char* e=getenv("PS3_EVFID");
                                dbg=e?(uint32_t)strtoul(e,0,16):0; }
          if(dbg && data1==dbg)
              fprintf(stderr,"[EVF-SPU] %lu set id=0x%x bit=%u spu=%p pc=0x%x\n",
                      (unsigned long)GetTickCount(),data1,bit,(void*)st,
                      spu_thread_pc(st)); }
        EvFlag* f = evf_lock(data1);
        static volatile long n; long k=InterlockedIncrement(&n);
        if (f){
            f->bits |= 1ull<<bit;
            f->last_set_tid=~0ull; f->last_set_tick=GetTickCount();
            if(g_evfprof>0){ int hw=0; for(int i=0;i<6;i++) if(f->w[i].tid){hw=1;break;}
                if(hw){ LARGE_INTEGER q; QueryPerformanceCounter(&q); f->p_set_qpc=q.QuadPart; } }
            WakeAllConditionVariable(&f->cv); LeaveCriticalSection(&f->cs);
            if(k<=32||(k%32)==0) fprintf(stderr,"[SPU-EVF] %lu set id=0x%x bit=%u (n=%ld)\n",
                                  (unsigned long)GetTickCount(),data1,bit,k);
        } else if (k<=32)
            fprintf(stderr,"[SPU-EVF] set id=0x%x bit=%u: no such flag\n",data1,bit);
        return 1;
    }
    if (code>=128) return 0;
    uint32_t spup = code & 0x3f;
    const int want_ack = (code < 64);
    for (int i=0;i<NSPUTHR;i++){
        SpuThr* t=&g_sputhr[i];
        if (!t->used || t->t!=st) continue;
        SpuGrp* g=spugrp_find(t->group);
        EvQueue* q = (g && g->spup_q[spup]) ? evq_find(g->spup_q[spup]) : 0;
        if (!q){
            if (want_ack){ spu_push_inmbox(st, 0x80010005u  ); return 1; }
            return 0;
        }
        if (!evq_push(q, g->spup_q[spup], SYS_SPU_THREAD_EVENT_USER_KEY,
                      t->id, ((uint64_t)spup<<32)|data0, data1)){
            if (want_ack){ spu_push_inmbox(st, LV2_ESRCH); return 1; }
            return 0;
        }
        static volatile long nlog=0;
        long k=InterlockedIncrement(&nlog);
        if(k<=12||(k%64)==0) fprintf(stderr,"[SPU-EV] %lu spup=%u data0=0x%x data1=0x%x -> q=0x%x (n=%ld)\n",
                              (unsigned long)GetTickCount(),spup,data0,data1,g->spup_q[spup],k);
        if (want_ack) spu_push_inmbox(st, 0);
        return 1;
    }
    if (want_ack){ spu_push_inmbox(st, 0x80010005u); return 1; }
    return 0;
}

static uint32_t guest_strlen(uint32_t s){ uint32_t n=0; while(s+n<g_size && g_base[s+n]) n++; return n; }

static void guest_fmt(char* out, size_t cap, uint32_t fmt_ea, const uint64_t* a, int na){
    const char* f=(const char*)g_base+fmt_ea; size_t o=0; int ai=0;
    while(*f && o+40<cap){
        if(*f!='%'){ out[o++]=*f++; continue; }
        f++;
        if(*f=='%'){ out[o++]='%'; f++; continue; }
        char spec[24]; size_t sl=0; spec[sl++]='%';
        while(*f && strchr("-+ #0123456789.",*f) && sl<16) spec[sl++]=*f++;
        int ll=0; while(*f=='l'||*f=='h'||*f=='z'){ if(*f=='l') ll++; f++; }
        char cv=*f ? *f++ : 0;
        uint64_t v = (ai<na)?a[ai]:0;
        if (cv=='d'||cv=='i'){ spec[sl++]='l';spec[sl++]='l';spec[sl++]='d';spec[sl]=0;
            o+=(size_t)snprintf(out+o,cap-o,spec,(long long)(ll>=2?(int64_t)v:(int64_t)(int32_t)v)); ai++; }
        else if (cv=='u'||cv=='x'||cv=='X'||cv=='p'){ spec[sl++]='l';spec[sl++]='l';spec[sl++]=(cv=='u')?'u':(cv=='p'?'x':cv);spec[sl]=0;
            o+=(size_t)snprintf(out+o,cap-o,spec,(unsigned long long)(ll>=2?v:(uint64_t)(uint32_t)v)); ai++; }
        else if (cv=='c'){ out[o++]=(char)v; ai++; }
        else if (cv=='s'){ uint32_t s=(uint32_t)v;
            while(s<g_size && g_base[s] && o+2<cap) out[o++]=(char)g_base[s++]; ai++; }
        else if (cv) out[o++]=cv;
    }
    out[o<cap?o:cap-1]=0;
}

static void hle_mutex_lock(const char* name, PPUContext* ctx){
    uint32_t ea=(uint32_t)R(3); SyncObj* s=sync_get(ea);
    if(s){
        if(s->owner==GetCurrentThreadId() && s->depth>0){
            uint32_t attr = name[4]=='l' ? PPU_LW(g_base,ea+8) : 0x10;
            if(!(attr&0x10)){
                static long dl_n=0; long dk=InterlockedIncrement(&dl_n);
                if(dk<=16) fprintf(stderr,"[LOCK] EDEADLK ea=0x%x lr=0x%llx fn=sub_%x depth=%d\n",
                    ea,(unsigned long long)ctx->lr,g_curfn,s->depth);
                R(3)=0x80010008u; return;
            }
        }
        if(!TryEnterCriticalSection(&s->cs)){
            int got=0;
            for(int i=0;i<64;i++){ SwitchToThread();
                if(TryEnterCriticalSection(&s->cs)){ got=1; break; } }
            if(!got) EnterCriticalSection(&s->cs);
        }
        if(s->owner==GetCurrentThreadId()) s->depth++;
        else { s->owner=GetCurrentThreadId(); s->depth=1; }
    }
    R(3)=0;
}
static void hle_mutex_unlock(PPUContext* ctx){
    SyncObj* s=sync_get((uint32_t)R(3));
    if(s){ if(s->depth>0 && --s->depth==0) s->owner=0; LeaveCriticalSection(&s->cs); }
    R(3)=0;
}
static void hle_mutex_trylock(const char* name, PPUContext* ctx){
    uint32_t ea=(uint32_t)R(3); SyncObj* s=sync_get(ea);
    if(!s){ R(3)=0x80010005u; return; }
    if(s->owner==GetCurrentThreadId() && s->depth>0){
        uint32_t attr = name[4]=='l' ? PPU_LW(g_base,ea+8) : 0x10;
        if(!(attr&0x10)){ R(3)=0x80010008u; return; }
    }
    if(TryEnterCriticalSection(&s->cs)){
        if(s->owner==GetCurrentThreadId()) s->depth++;
        else { s->owner=GetCurrentThreadId(); s->depth=1; }
        R(3)=0;
    }
    else R(3)=0x80010005u;
}

static void ppu_hle_body(uint32_t nid, const char* lib, const char* name, PPUContext* ctx, uint8_t* base){
    (void)nid;(void)base;
    PPU_STD(base,(uint32_t)ctx->r[1]+40,ctx->r[2]);
    g_curhle = name;

    {
        static int mon=-1; if(mon<0) mon=getenv("PS3_HLEMON")?1:0;
        if(mon){
            enum{MCAP=512}; static const char* mn[MCAP]; static uint32_t mc[MCAP]; static int mcnt=0;
            int i=0; for(;i<mcnt;i++) if(mn[i]==name) break;
            if(i==mcnt && mcnt<MCAP){ mn[mcnt]=name; mc[mcnt]=0; mcnt++; }
            if(i<mcnt){ uint32_t k=++mc[i];
                if(k<=3||(k&4095)==0)
                    fprintf(stderr,"[HLEMON] %s n=%u r3=0x%llx r4=0x%llx r5=0x%llx lr=0x%llx\n",
                        name,k,(unsigned long long)R(3),(unsigned long long)R(4),
                        (unsigned long long)R(5),(unsigned long long)ctx->lr);
            }
        }
    }

    if(name[0]=='s' && !strncmp(name,"sys_lwmutex_",12)){
        int which = name[12]=='l' && !strcmp(name+12,"lock")    ? 0
                  : name[12]=='u' && !strcmp(name+12,"unlock")  ? 1
                  : name[12]=='t' && !strcmp(name+12,"trylock") ? 2 : -1;
        if(which>=0){
            static __declspec(thread) uint32_t lwn[3];
            uint32_t k=++lwn[which];
            if((k&0xfffff)==0)
                fprintf(stderr,"[loop] %s x%u r3=0x%llx lr=0x%llx t%llu\n",name,k,
                        (unsigned long long)R(3),(unsigned long long)ctx->lr,
                        (unsigned long long)t_gid);
            if(which==0) hle_mutex_lock(name,ctx);
            else if(which==1) hle_mutex_unlock(ctx);
            else hle_mutex_trylock(name,ctx);
            return;
        }
    }

    if ((name[0]=='c'||name[0]=='_') && strstr(name,"ellGcm") && gcm_hle(name,ctx)) return;
    if ((name[0]=='c'||name[0]=='_') && strstr(name,"ellFiber") && fiber_hle(name,ctx)) return;
    if (misc_hle(name,ctx)) return;

    {
        enum{TCAP=256}; static const char* tn[TCAP]; static uint32_t tc[TCAP]; static int tcnt=0;
        int i=0; for(;i<tcnt;i++) if(tn[i]==name) break;
        if(i==tcnt && tcnt<TCAP){ tn[tcnt]=name; tc[tcnt]=0; tcnt++; }
        if(i<tcnt && (++tc[i] & 0xfffff)==0)
            fprintf(stderr,"[loop] %s x%u r3=0x%llx lr=0x%llx\n",name,tc[i],
                    (unsigned long long)R(3),(unsigned long long)ctx->lr);
    }

    if (IS("sys_initialize_tls")){
        uint32_t taddr=(uint32_t)R(4), fsz=(uint32_t)R(5);
        uint32_t blk=guest_alloc_hi(0x10000,0x1000);
        if (taddr&&fsz&&taddr+fsz<=g_size) memcpy(g_base+blk,g_base+taddr,fsz);
        ctx->r[13]=blk+0x7000; R(3)=0; return;
    }
    if (IS("sys_process_getpid")){ R(3)=0x1000; return; }
    if (IS("sys_process_getppid")){ R(3)=0x1001; return; }
    if (IS("sys_process_exit")||IS("_sys_process_exit")){
        tty_flush();
        fprintf(stderr,"\n[boot] sys_process_exit code=%lld lr=0x%llx\n",
                (long long)R(3),(unsigned long long)ctx->lr);
        printf("\n[boot] sys_process_exit code=%lld\n",(long long)R(3)); exit(0); }

    if (IS("sys_tty_write")){
        uint32_t buf=(uint32_t)R(4),len=(uint32_t)R(5),pw=(uint32_t)R(6);
        tty_out(g_base,buf,len);
        if(pw) PPU_STW(g_base,pw,len); R(3)=0; return;
    }

    if (IS("sys_time_get_system_time")){
        LARGE_INTEGER c,f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
        R(3)=(uint64_t)(c.QuadPart*1000000ull/f.QuadPart); return;
    }

    if (IS("sys_memory_allocate")){ uint32_t a=mem_alloc((uint32_t)R(3),0x10000); if(R(5)) PPU_STW(g_base,(uint32_t)R(5),a); R(3)=a?0:0x80010004u; return; }
    if (IS("sys_memory_allocate_from_container")){ uint32_t a=mem_alloc((uint32_t)R(3),0x10000); if(R(6)) PPU_STW(g_base,(uint32_t)R(6),a); R(3)=a?0:0x80010004u; return; }
    if (IS("sys_memory_free")){ mem_free((uint32_t)R(3)); R(3)=0; return; }
    if (IS("sys_mmapper_free_address")||IS("sys_mmapper_free_shared_memory")){ mem_free((uint32_t)R(3)); R(3)=0; return; }
    if (IS("sys_memory_get_user_memory_size")){ uint32_t p=(uint32_t)R(3); if(p){PPU_STW(g_base,p,256u*1024*1024);PPU_STW(g_base,p+4,200u*1024*1024);} R(3)=0; return; }
    if (IS("_sys_heap_create_heap")){ R(3)=0x4000; return; }
    if (IS("_sys_heap_malloc")){ R(3)=guest_alloc((uint32_t)R(4),16); return; }
    if (IS("_sys_heap_memalign")){ R(3)=guest_alloc((uint32_t)R(5),(uint32_t)R(4)); return; }
    if (IS("malloc")){ R(3)=guest_alloc((uint32_t)R(3),16); return; }
    if (IS("memalign")){ R(3)=guest_alloc((uint32_t)R(4),(uint32_t)R(3)); return; }
    if (IS("_sys_heap_free")||IS("free")){ R(3)=0; return; }

    if (IS("cellFsOpen")){ R(3)=fs_open(g_base,(uint32_t)R(3),(int)(int32_t)R(4),(uint32_t)R(5)); return; }
    if (IS("cellFsRead")){
        int fd=(int)(int32_t)R(3); uint32_t buf=(uint32_t)R(4),nb=(uint32_t)R(5),pn=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ R(3)=CELL_FS_EBADF; return; }
        if((uint64_t)buf+nb<=g_size){
            fswatch_check("cellFsRead",buf,nb,fd,ctx);
            int64_t off = -1;
            static int fspac=-1; if(fspac<0) fspac=getenv("PS3_FSPAC")?1:0;
            if(fspac && g_fsfd[fd].is_pac) off=_ftelli64(g_fsfd[fd].fp);
            int64_t mtoff = g_mtrc_on ? (off>=0?off:_ftelli64(g_fsfd[fd].fp)) : 0;
            size_t r=fread(g_base+buf,1,nb,g_fsfd[fd].fp);
            MTRC(MTRC_FS_READ,(uint32_t)fd,(uint32_t)mtoff,nb,(uint32_t)r,g_fsfd[fd].name);
            if(fspac && g_fsfd[fd].is_pac){
                static volatile long np; long k=InterlockedIncrement(&np);
                if(k<=8192||(k%256)==0)
                    fprintf(stderr,"[PAC] %lu read fd=%d %s off=0x%llx nb=0x%x got=0x%zx buf=0x%x lr=0x%llx (n=%ld)\n",
                            (unsigned long)GetTickCount(),fd,g_fsfd[fd].name,
                            (unsigned long long)off,nb,r,buf,(unsigned long long)ctx->lr,k);
                if(!strncmp(g_fsfd[fd].name,"DATA1",5) && off>0x10000){
                    extern volatile DWORD spu_trace_until;
                    DWORD until=GetTickCount()+30000;
                    if(spu_trace_until!=until){ spu_trace_until=until;
                        static volatile long armed; if(InterlockedIncrement(&armed)==1)
                            fprintf(stderr,"[JQT] window first armed\n"); }
                }
            }
            { static volatile long n; long k=++n; if(k<=32||(k%2048)==0)
              fprintf(stderr,"[FS] cread fd=%d nb=0x%x got=0x%zx (n=%ld)\n",fd,nb,r,k); }
            if(pn) PPU_STD(g_base,pn,(uint64_t)r);
        }
        R(3)=CELL_FS_OK; return; }
    if (IS("cellFsWrite")){
        int fd=(int)(int32_t)R(3); uint32_t buf=(uint32_t)R(4),nb=(uint32_t)R(5),pn=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ R(3)=CELL_FS_EBADF; return; }
        if((uint64_t)buf+nb<=g_size){ size_t w=fwrite(g_base+buf,1,nb,g_fsfd[fd].fp); if(pn) PPU_STD(g_base,pn,(uint64_t)w); }
        R(3)=CELL_FS_OK; return; }
    if (IS("cellFsClose")){
        int fd=(int)(int32_t)R(3);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ R(3)=CELL_FS_EBADF; return; }
        fclose(g_fsfd[fd].fp); g_fsfd[fd].fp=0; g_fsfd[fd].used=0; R(3)=CELL_FS_OK; return; }
    if (IS("cellFsLseek")){
        int fd=(int)(int32_t)R(3); int64_t off=(int64_t)R(4); int wh=(int)(int32_t)R(5); uint32_t pp=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ R(3)=CELL_FS_EBADF; return; }
        int o = wh==1?SEEK_CUR : wh==2?SEEK_END : SEEK_SET;
        { static int fspac=-1; if(fspac<0) fspac=getenv("PS3_FSPAC")?1:0;
          if(fspac && g_fsfd[fd].is_pac){
              static volatile long np; long k=InterlockedIncrement(&np);
              if(k<=8192||(k%256)==0)
                  fprintf(stderr,"[PAC] %lu seek fd=%d %s off=0x%llx wh=%d lr=0x%llx (n=%ld)\n",
                          (unsigned long)GetTickCount(),fd,g_fsfd[fd].name,
                          (unsigned long long)off,wh,(unsigned long long)ctx->lr,k); } }
        if(_fseeki64(g_fsfd[fd].fp,off,o)==0){ if(pp) PPU_STD(g_base,pp,(uint64_t)_ftelli64(g_fsfd[fd].fp)); R(3)=CELL_FS_OK; } else R(3)=CELL_FS_EINVAL;
        return; }
    if (IS("cellFsStat")){ R(3)=fs_stat(g_base,(uint32_t)R(3),(uint32_t)R(4)); return; }
    if (IS("cellFsFstat")){ R(3)=fs_fstat(g_base,(int)(int32_t)R(3),(uint32_t)R(4)); return; }
    if (IS("cellFsOpendir")){ R(3)=fs_opendir(g_base,(uint32_t)R(3),(uint32_t)R(4)); return; }
    if (IS("cellFsReaddir")){ R(3)=fs_readdir(g_base,(int)(int32_t)R(3),(uint32_t)R(4),(uint32_t)R(5)); return; }
    if (IS("cellFsClosedir")){ R(3)=fs_closedir((int)(int32_t)R(3)); return; }

    if (IS("sys_mempool_create")){ uint32_t bs=(uint32_t)R(6); if(bs>g_mempool_block) g_mempool_block=bs; R(3)=0; return; }
    if (IS("sys_mempool_allocate_block")||IS("sys_mempool_try_allocate_block")){ R(3)=guest_alloc_hi(g_mempool_block,16); return; }
    if (IS("sys_mempool_free_block")){ R(3)=0; return; }
    if (IS("sys_mempool_destroy")){ R(3)=0; return; }
    if (IS("sys_mempool_get_count")){ R(3)=0x10000; return; }

    if (IS("_sys_memset")){ uint32_t d=(uint32_t)R(3); uint64_t n=R(5); if((uint64_t)d+n<=g_size) memset(g_base+d,(int)R(4),(size_t)n); R(3)=d; return; }
    if (IS("_sys_memcpy")||IS("_sys_memmove")){ uint32_t d=(uint32_t)R(3),s=(uint32_t)R(4); uint64_t n=R(5); if((uint64_t)d+n<=g_size&&(uint64_t)s+n<=g_size) memmove(g_base+d,g_base+s,(size_t)n); R(3)=d; return; }
    if (IS("_sys_memcmp")){ R(3)=(uint64_t)(int64_t)memcmp(g_base+(uint32_t)R(3),g_base+(uint32_t)R(4),(size_t)R(5)); return; }
    if (IS("_sys_strlen")){ R(3)=guest_strlen((uint32_t)R(3)); return; }
    if (IS("_sys_strcpy")){ uint32_t d=(uint32_t)R(3),s=(uint32_t)R(4),n=guest_strlen(s); memmove(g_base+d,g_base+s,n+1); R(3)=d; return; }
    if (IS("_sys_strncpy")){ uint32_t d=(uint32_t)R(3),s=(uint32_t)R(4); uint64_t n=R(5),l=guest_strlen(s); if(l>n)l=n; memmove(g_base+d,g_base+s,(size_t)l); if(l<n) memset(g_base+d+l,0,(size_t)(n-l)); R(3)=d; return; }
    if (IS("_sys_strcat")){ uint32_t d=(uint32_t)R(3),s=(uint32_t)R(4); uint32_t dl=guest_strlen(d),sl=guest_strlen(s); memmove(g_base+d+dl,g_base+s,sl+1); R(3)=d; return; }
    if (IS("_sys_strncat")){ uint32_t d=(uint32_t)R(3),s=(uint32_t)R(4); uint64_t n=R(5); uint32_t dl=guest_strlen(d),sl=guest_strlen(s); if(sl>n)sl=(uint32_t)n; memmove(g_base+d+dl,g_base+s,sl); g_base[d+dl+sl]=0; R(3)=d; return; }
    if (IS("_sys_strncmp")){ R(3)=(uint64_t)(int64_t)strncmp((char*)g_base+(uint32_t)R(3),(char*)g_base+(uint32_t)R(4),(size_t)R(5)); return; }
    if (IS("_sys_printf")){ uint64_t a[7]={R(4),R(5),R(6),R(7),R(8),R(9),R(10)};
        char b[1024]; guest_fmt(b,sizeof b,(uint32_t)R(3),a,7);
        fprintf(stderr,"[prx] %s",b); R(3)=0; return; }
    if (IS("_sys_vprintf")){ uint64_t a[8]; uint32_t va=(uint32_t)R(4);
        for(int i=0;i<8;i++) a[i]=(uint64_t)va+8u*(uint32_t)i<g_size?PPU_LD(g_base,va+8u*(uint32_t)i):0;
        char b[1024]; guest_fmt(b,sizeof b,(uint32_t)R(3),a,8);
        fprintf(stderr,"[prx] %s",b); R(3)=0; return; }
    if (IS("_sys_snprintf")){ uint64_t a[5]={R(6),R(7),R(8),R(9),R(10)};
        uint32_t d=(uint32_t)R(3); uint64_t n=R(4);
        char b[1024]; guest_fmt(b,sizeof b,(uint32_t)R(5),a,5);
        size_t l=strlen(b); if(n && l+1>n) l=(size_t)n-1;
        memcpy(g_base+d,b,l); g_base[d+l]=0; R(3)=l; return; }
    if (IS("_sys_vsnprintf")){ uint64_t a[8]; uint32_t va=(uint32_t)R(6);
        for(int i=0;i<8;i++) a[i]=(uint64_t)va+8u*(uint32_t)i<g_size?PPU_LD(g_base,va+8u*(uint32_t)i):0;
        uint32_t d=(uint32_t)R(3); uint64_t n=R(4);
        char b[1024]; guest_fmt(b,sizeof b,(uint32_t)R(5),a,8);
        size_t l=strlen(b); if(n && l+1>n) l=(size_t)n-1;
        memcpy(g_base+d,b,l); g_base[d+l]=0; R(3)=l; return; }

    if (IS("sys_spu_image_import")){
        uint32_t img=(uint32_t)R(3), src=(uint32_t)R(4);
        uint32_t entry = (src+0x34<=g_size && PPU_LW(g_base,src)==0x7f454c46u) ? PPU_LW(g_base,src+0x18) : 0;
        PPU_STW(g_base,img+0,0);
        PPU_STW(g_base,img+4,entry);
        PPU_STW(g_base,img+8,src);
        PPU_STW(g_base,img+12,(uint32_t)SPU_IMG_RAWELF);
        fprintf(stderr,"[SPU] image_import src=0x%x entry=0x%x\n",src,entry);
        R(3)= entry?0:0x80010002u; return; }
    if (IS("sys_spu_image_close")){ R(3)=0; return; }
    if (IS("_sys_spu_printf_attach_group")||IS("_sys_spu_printf_detach_group")){ R(3)=0; return; }
    if (IS("sys_prx_get_module_id_by_name")){ R(3)=0x8001112eu; return; }

    if (IS("sys_ppu_thread_create")||IS("_sys_ppu_thread_create")){ R(3)=thread_create(ctx); return; }
    if (IS("sys_ppu_thread_get_id")){ if(R(3)) PPU_STD(g_base,(uint32_t)R(3),t_gid?t_gid:1); R(3)=0; return; }
    if (IS("sys_ppu_thread_exit")){ t_retval=R(3); if(t_inthread) longjmp(t_exit,1); R(3)=0; return; }
    if (IS("sys_ppu_thread_yield")){ Sleep(0); R(3)=0; return; }
    if (IS("sys_ppu_thread_join")){
        uint64_t rv=join_thread(R(3));
        if(R(4)) PPU_STD(g_base,(uint32_t)R(4),rv); R(3)=0; return;
    }

    if (IS("sys_lwmutex_lock")||IS("sys_mutex_lock")){ hle_mutex_lock(name,ctx); return; }
    if (IS("sys_lwmutex_unlock")||IS("sys_mutex_unlock")){ hle_mutex_unlock(ctx); return; }
    if (IS("sys_lwmutex_trylock")||IS("sys_mutex_trylock")){ hle_mutex_trylock(name,ctx); return; }
    if (IS("sys_lwcond_wait")||IS("sys_cond_wait")){
        uint32_t cea=(uint32_t)R(3); SyncObj* c=sync_get(cea);
        uint32_t mea = name[4]=='l' ? PPU_LW(g_base,cea) : 0;
        SyncObj* m = mea ? sync_get(mea) : c;
        uint32_t rc=0;
        if(c&&m){
            DWORD self=GetCurrentThreadId(); int saved=m->depth;
            m->owner=0; m->depth=0;
            uint64_t us=R(4);
            if(us==0){
                DWORD t0c=GetTickCount(); DWORD lastc=t0c;
                while(!SleepConditionVariableCS(&c->cv,&m->cs,100)){
                    DWORD now=GetTickCount();
                    if(now-lastc>=(lastc==t0c?5000:30000)){
                        lastc=now;
                        fprintf(stderr,"[COND] STUCK %lums cond=0x%x mutex=0x%x waiter=t%llu(fn=sub_%x lr=0x%llx)\n",
                            (unsigned long)(now-t0c),cea,mea,(unsigned long long)t_gid,g_curfn,(unsigned long long)ctx->lr);
                    }
                }
            } else {
                uint64_t dl=GetTickCount64()+(us+999)/1000;
                for(;;){
                    uint64_t now=GetTickCount64();
                    if(now>=dl){ rc=0x8001000Bu; break; }
                    DWORD slice=(DWORD)(dl-now); if(slice>100) slice=100;
                    if(SleepConditionVariableCS(&c->cv,&m->cs,slice)) break;
                }
            }
            m->owner=self; m->depth=saved>0?saved:1;
        }
        R(3)=rc; return; }
    if (IS("sys_lwcond_signal")||IS("sys_cond_signal")){ SyncObj* s=sync_get((uint32_t)R(3)); if(s)WakeConditionVariable(&s->cv); R(3)=0; return; }
    if (IS("sys_lwcond_signal_all")||IS("sys_cond_signal_all")){ SyncObj* s=sync_get((uint32_t)R(3)); if(s)WakeAllConditionVariable(&s->cv); R(3)=0; return; }

    if (IS("sys_lwmutex_create")){
        uint32_t mea=(uint32_t)R(3), aea=(uint32_t)R(4);
        if(mea){
            PPU_STD(g_base,mea,0xffffffff00000000ull);
            PPU_STW(g_base,mea+8, aea?PPU_LW(g_base,aea+4):0);
            PPU_STW(g_base,mea+12,0);
        }
        R(3)=0; return;
    }
    if (!strncmp(name,"sys_lwmutex",11)||!strncmp(name,"sys_lwcond",10)||
        !strncmp(name,"sys_mutex",9)||!strncmp(name,"sys_cond",8)||
        !strncmp(name,"sys_semaphore",13)||!strncmp(name,"sys_event",9)||
        !strncmp(name,"sys_rwlock",10)){ R(3)=0; return; }

    if (!strncmp(name,"cellSysmodule",13)||!strncmp(name,"sys_prx",7)){ R(3)=0; return; }

    {
        enum{CAP=1024}; static const char* seen[CAP]; static int n=0; int found=0;
        for(int i=0;i<n;i++) if(seen[i]==name){found=1;break;}
        if(!found){ if(n<CAP) seen[n++]=name;
            fprintf(stderr,"[HLE-stub] %s::%s r3=0x%llx r4=0x%llx r5=0x%llx r6=0x%llx lr=0x%llx\n",
                lib,name,(unsigned long long)R(3),(unsigned long long)R(4),
                (unsigned long long)R(5),(unsigned long long)R(6),(unsigned long long)ctx->lr); }
    }
    R(3)=0;
}

typedef struct { uint32_t id; int used, is_cond; uint32_t mutex_id;
                 CRITICAL_SECTION cs; CONDITION_VARIABLE cv; } IdSync;
static IdSync g_idsync[4096]; static int g_nidsync=0; static uint32_t g_idseq=0x6000;
static IdSync* idsync_find(uint32_t id){
    for(int i=0;i<g_nidsync;i++) if(g_idsync[i].used && g_idsync[i].id==id) return &g_idsync[i];
    return 0;
}
static IdSync* idsync_new(int is_cond){
    EnterCriticalSection(&g_lock);
    IdSync* s = (g_nidsync<4096)? &g_idsync[g_nidsync++] : 0;
    if(s){ s->used=1; s->is_cond=is_cond; s->id=++g_idseq; s->mutex_id=0;
           InitializeCriticalSection(&s->cs); InitializeConditionVariable(&s->cv); }
    LeaveCriticalSection(&g_lock);
    return s;
}

static void ppu_syscall_body(PPUContext* ctx, uint8_t* base){
    uint32_t n=(uint32_t)ctx->r[11];
    g_cursc = (int)n;
    if (n==130||n==131||n==134||n==136||n==138||n==184||n==185||n==190||n==191||n==193||n==251){
        enum{SCAP=16}; static uint32_t sn[SCAP],sc_[SCAP]; static int scnt=0;
        int i=0; for(;i<scnt;i++) if(sn[i]==n) break;
        if(i==scnt&&scnt<SCAP){ sn[scnt]=n; sc_[scnt]=0; scnt++; }
        if(i<scnt&&sc_[i]++<40)
            fprintf(stderr,"[sc%u] r3=0x%llx r4=0x%llx r5=0x%llx r6=0x%llx\n",n,
                (unsigned long long)R(3),(unsigned long long)R(4),
                (unsigned long long)R(5),(unsigned long long)R(6));
    }
    switch(n){
    case 1:   ctx->r[3]=0x1000; return;
    case 14:  ctx->r[3]=0; return;
    case 25:  if(R(4)) PPU_STW(base,(uint32_t)R(4),0x00450001u); ctx->r[3]=0; return;
    case 47:  ctx->r[3]=0; return;
    case 48:  if(R(4)) PPU_STW(base,(uint32_t)R(4),1000); ctx->r[3]=0; return;
    case 250: ctx->r[3]=0; return;
    case 145: { LARGE_INTEGER c,f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
                ctx->r[3]=(uint64_t)(c.QuadPart*1000000ull/f.QuadPart); return; }
    case 147: ctx->r[3]=79800000ull; return;
    case 141: {
        uint64_t us = R(3);
        if(us >= 2000 && us < 300000) {   }
        else if(us >= 300000){ Sleep((DWORD)(us/1000)); ctx->r[3]=0; return; }
        LARGE_INTEGER f,s0,c1; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&s0);
        uint64_t target = (uint64_t)s0.QuadPart + us * (uint64_t)f.QuadPart / 1000000ull;
        static int uspin=-1; if(uspin<0) uspin=getenv("PS3_USLEEP_SPIN")?1:0;
        if(!uspin && us>=50){
            static __declspec(thread) HANDLE ht; static volatile long hr_fail;
            if(!ht && !hr_fail){
                ht=CreateWaitableTimerExW(0,0,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_ALL_ACCESS);
                if(!ht){ InterlockedExchange(&hr_fail,1);
                         fprintf(stderr,"[SC141] high-res timer unavailable, spinning\n"); }
            }
            if(ht){
                LARGE_INTEGER due; due.QuadPart=-(LONGLONG)(us*10ull);
                if(SetWaitableTimer(ht,&due,0,0,0,FALSE))
                    WaitForSingleObject(ht,(DWORD)(us/1000)+16);
            }
        }
        do { QueryPerformanceCounter(&c1); if((uint64_t)c1.QuadPart>=target) break; SwitchToThread(); }
        while(1);
        ctx->r[3]=0; return; }
    case 142: Sleep((DWORD)(R(3)*1000)); ctx->r[3]=0; return;
    case 43:  Sleep(0); ctx->r[3]=0; return;
    case 44: {
        uint64_t id=R(3);
        fprintf(stderr,"[join] t%llu joins id=%llu lr=0x%llx\n",
                (unsigned long long)t_gid,(unsigned long long)id,(unsigned long long)ctx->lr);
        uint64_t rv=join_thread(id);
        fprintf(stderr,"[join] t%llu join id=%llu done rv=0x%llx\n",
                (unsigned long long)t_gid,(unsigned long long)id,(unsigned long long)rv);
        if(R(4)) PPU_STD(base,(uint32_t)R(4),rv); ctx->r[3]=0; return; }
    case 45:  ctx->r[3]=0; return;
    case 348: { uint32_t a=mem_alloc((uint32_t)R(3),0x10000); if(R(5)) PPU_STW(base,(uint32_t)R(5),a); ctx->r[3]=a?0:0x80010004u; return; }
    case 350: { uint32_t a=mem_alloc((uint32_t)R(3),0x10000); if(R(6)) PPU_STW(base,(uint32_t)R(6),a); ctx->r[3]=a?0:0x80010004u; return; }
    case 349: mem_free((uint32_t)R(3)); ctx->r[3]=0; return;
    case 351: { uint32_t p=(uint32_t)R(4); if(p){ PPU_STD(base,p,0xFull); PPU_STD(base,p+8,0xFull); PPU_STW(base,p+16,0x10000u); PPU_STW(base,p+20,0u);} ctx->r[3]=0; return; }
    case 352: { uint32_t p=(uint32_t)R(3); if(p){ PPU_STW(base,p,256u*1024*1024); PPU_STW(base,p+4,200u*1024*1024);} ctx->r[3]=0; return; }
    case 330: { uint32_t al=(uint32_t)R(5); uint32_t a=mem_alloc((uint32_t)R(3),al?al:0x10000); if(R(6)) PPU_STW(base,(uint32_t)R(6),a); ctx->r[3]=a?0:0x80010004u; return; }
    case 331: mem_free((uint32_t)R(3)); ctx->r[3]=0; return;
    case 326: { if(R(4)) PPU_STW(base,(uint32_t)R(4),0); ctx->r[3]=0; return; }
    case 337: ctx->r[3]=0; return;
    case 324: { if(R(6)) PPU_STW(base,(uint32_t)R(6),0x4000); ctx->r[3]=0; return; }
    case 169: ctx->r[3]=0; return;
    case 403: { uint32_t buf=(uint32_t)R(4),len=(uint32_t)R(5),pw=(uint32_t)R(6);
                tty_out(base,buf,len);
                if(pw) PPU_STW(base,pw,len); ctx->r[3]=0; return; }
    case 100: { uint32_t p=(uint32_t)R(3); IdSync* s=idsync_new(0); if(p&&s) PPU_STW(base,p,s->id); ctx->r[3]=0; return; }
    case 101: ctx->r[3]=0; return;
    case 102: { IdSync* s=idsync_find((uint32_t)R(3)); if(s) EnterCriticalSection(&s->cs); ctx->r[3]=0; return; }
    case 103: { IdSync* s=idsync_find((uint32_t)R(3)); ctx->r[3]=(s&&!TryEnterCriticalSection(&s->cs))?0x80010005u:0; return; }
    case 104: { IdSync* s=idsync_find((uint32_t)R(3)); if(s) LeaveCriticalSection(&s->cs); ctx->r[3]=0; return; }
    case 105: { uint32_t p=(uint32_t)R(3); IdSync* s=idsync_new(1); if(s) s->mutex_id=(uint32_t)R(4); if(p&&s) PPU_STW(base,p,s->id); ctx->r[3]=0; return; }
    case 106: ctx->r[3]=0; return;
    case 107: { IdSync* c=idsync_find((uint32_t)R(3));
                uint64_t us=R(4); uint32_t rc=0;
                { static volatile long n; long k=++n; if(k<=32||(k%65536)==0) fprintf(stderr,"[cond] wait id=0x%x to=%llu lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",(uint32_t)R(3),(unsigned long long)us,(unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid,k); }
                if(c){
                    IdSync* m=idsync_find(c->mutex_id);
                    if(m){
                        if(us==0){
                            while(!SleepConditionVariableCS(&c->cv,&m->cs,100)){}
                        } else {
                            uint64_t dl=GetTickCount64()+(us+999)/1000;
                            for(;;){
                                uint64_t now=GetTickCount64();
                                if(now>=dl){ rc=0x8001000Bu; break; }
                                DWORD slice=(DWORD)(dl-now); if(slice>100) slice=100;
                                if(SleepConditionVariableCS(&c->cv,&m->cs,slice)) break;
                            }
                        }
                    }
                } else Sleep(1);
                ctx->r[3]=rc; return; }
    case 108: { IdSync* c=idsync_find((uint32_t)R(3)); if(c) WakeConditionVariable(&c->cv);
                { static volatile long n; long k=++n; if(k<=64||(k%65536)==0) fprintf(stderr,"[cond] signal id=0x%x lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",(uint32_t)R(3),(unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid,k); }
                ctx->r[3]=0; return; }
    case 109: { IdSync* c=idsync_find((uint32_t)R(3)); if(c) WakeAllConditionVariable(&c->cv);
                { static volatile long n; long k=++n; if(k<=64||(k%65536)==0) fprintf(stderr,"[cond] signal_all id=0x%x (n=%ld)\n",(uint32_t)R(3),k); }
                ctx->r[3]=0; return; }
    case 70: case 80: case 120: {
        static uint32_t sync_id=0x5000; uint32_t p=(uint32_t)R(3);
        if(p) PPU_STW(base,p,++sync_id); ctx->r[3]=0; return;
    }
    case 82: {
        EnterCriticalSection(&g_lock);
        EvFlag* f=evf_alloc(); uint32_t id=0;
        if(f){ f->bits=R(5); id=f->id; LeaveCriticalSection(&f->cs); }
        LeaveCriticalSection(&g_lock);
        if(!id){ lv2_create_failed("event flag",NEVF,ctx); ctx->r[3]=LV2_EAGAIN; return; }
        if(R(3)) PPU_STW(base,(uint32_t)R(3),id);
        { static volatile long n; long k=InterlockedIncrement(&n);
          if(k<=256||(k%256)==0) fprintf(stderr,"[EVF] create id=0x%x init=0x%llx lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",
                      id,(unsigned long long)R(5),(unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid,k); }
        ctx->r[3]=0; return; }
    case 83: {
        uint32_t id=(uint32_t)R(3), rc=LV2_ESRCH;
        EnterCriticalSection(&g_lock);
        EvFlag* f=evf_lock(id);
        if(f){ if(f->nwait) rc=LV2_EBUSY; else { f->used=0; f->id=0; rc=0; }
               LeaveCriticalSection(&f->cs); }
        LeaveCriticalSection(&g_lock);
        { static volatile long n; long k=InterlockedIncrement(&n);
          if(rc||k<=256||(k%256)==0) fprintf(stderr,"[EVF] destroy id=0x%x rc=0x%x lr=0x%llx t%llu (n=%ld)\n",
                      id,rc,(unsigned long long)ctx->lr,(unsigned long long)t_gid,k); }
        ctx->r[3]=rc; return; }
    case 85: case 86: {
        EvFlag* f=evf_find((uint32_t)R(3)); uint64_t bits=R(4); uint32_t mode=(uint32_t)R(5);
        if(!f){ if(R(6)) PPU_STD(base,(uint32_t)R(6),0); ctx->r[3]=LV2_ESRCH; return; }
        { static volatile long lg; long k=InterlockedIncrement((volatile long*)&lg);
          static uint32_t dbgid=0xffffffffu;
          if(dbgid==0xffffffffu){ const char* e=getenv("PS3_EVFID"); dbgid=e?(uint32_t)strtoul(e,0,16):0; }
          if(dbgid && (uint32_t)R(3)==dbgid)
              fprintf(stderr,"[EVF] %lu %s id=0x%x bits=0x%llx mode=0x%x cur=0x%llx lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",
                  (unsigned long)GetTickCount(),n==86?"try":"wait",(uint32_t)R(3),(unsigned long long)bits,mode,
                  (unsigned long long)f->bits,(unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid,k);
          else if(k<=64||(k%4096)==0) fprintf(stderr,"[EVF] %s id=0x%x bits=0x%llx mode=0x%x t%llu (n=%ld)\n",
              n==86?"try":"wait",(uint32_t)R(3),(unsigned long long)bits,mode,(unsigned long long)t_gid,k); }
        uint32_t rc=0;
        uint64_t towait_us = (n==85) ? R(7) : 0;
        uint64_t dl = towait_us ? GetTickCount64()+(towait_us+999)/1000 : 0;
        LARGE_INTEGER q0={0}; int slept=0;
        if(g_evfprof>0) QueryPerformanceCounter(&q0);
        if(!(f=evf_lock((uint32_t)R(3)))){
            if(R(6)) PPU_STD(base,(uint32_t)R(6),0); ctx->r[3]=LV2_ESRCH; return; }
        f->nwait++;
        int spins = (n==86) ? 4 : -1;
        int wsl=-1;
        for(int i=0;i<6;i++) if(!f->w[i].tid){ wsl=i; f->w[i].tid=t_gid; f->w[i].bits=bits; f->w[i].mode=mode; break; }
        for(;;){
            int hit = (mode&1) ? ((f->bits&bits)==bits) : ((f->bits&bits)!=0);
            if(hit) break;
            if(spins==0){ rc=LV2_EBUSY; break; }
            if(dl && GetTickCount64()>=dl){ rc=0x8001000bu; break; }
            if(spins>0) spins--;
            DWORD slice=(spins>=0)?5:100;
            if(dl){ uint64_t now=GetTickCount64(); if(now<dl && dl-now<slice) slice=(DWORD)(dl-now); }
            slept=1;
            SleepConditionVariableCS(&f->cv,&f->cs,slice);
        }
        if(g_evfprof>0 && q0.QuadPart){
            LARGE_INTEGER q1; QueryPerformanceCounter(&q1);
            f->p_wt_tk += q1.QuadPart-q0.QuadPart; f->p_wt_n++;
            if(!rc && slept && f->p_set_qpc > q0.QuadPart){
                LONG64 lat=q1.QuadPart-f->p_set_qpc;
                if(lat>=0){ f->p_wl_tk+=lat; f->p_wl_n++; if(lat>f->p_wl_max) f->p_wl_max=lat; }
            }
        }
        if(wsl>=0) f->w[wsl].tid=0;
        uint64_t got=f->bits;
        if(!rc){ if(mode&0x20) f->bits=0; else if(mode&0x10) f->bits&=~bits; }
        f->nwait--;
        LeaveCriticalSection(&f->cs);
        if(!rc&&R(6)) PPU_STD(base,(uint32_t)R(6),got);
        ctx->r[3]=rc; return; }
    case 87: { EvFlag* f=evf_lock((uint32_t)R(3)); if(f){ f->bits|=R(4);
                   f->last_set_tid=t_gid; f->last_set_tick=GetTickCount();
                   if(g_evfprof>0){ int hw=0; for(int i=0;i<6;i++) if(f->w[i].tid){hw=1;break;}
                       if(hw){ LARGE_INTEGER q; QueryPerformanceCounter(&q); f->p_set_qpc=q.QuadPart; } }
                   WakeAllConditionVariable(&f->cv); LeaveCriticalSection(&f->cs);}
        { static volatile long n; long k=InterlockedIncrement((volatile long*)&n);
          static uint32_t dbgid=0xffffffffu;
          if(dbgid==0xffffffffu){ const char* e=getenv("PS3_EVFID"); dbgid=e?(uint32_t)strtoul(e,0,16):0; }
          if(dbgid && (uint32_t)R(3)==dbgid)
              fprintf(stderr,"[EVF] %lu set id=0x%x bits=0x%llx lr=0x%llx fn=sub_%x t%llu (n=%ld)\n",
                      (unsigned long)GetTickCount(),(uint32_t)R(3),(unsigned long long)R(4),
                      (unsigned long long)ctx->lr,g_curfn,(unsigned long long)t_gid,k);
          else if(k<=64||(k%4096)==0) fprintf(stderr,"[EVF] set id=0x%x bits=0x%llx t%llu (n=%ld)\n",(uint32_t)R(3),(unsigned long long)R(4),(unsigned long long)t_gid,k); }
        ctx->r[3]=f?0:LV2_ESRCH; return; }
    case 118:{ EvFlag* f=evf_lock((uint32_t)R(3)); if(f){ f->bits&=R(4); LeaveCriticalSection(&f->cs);} ctx->r[3]=f?0:LV2_ESRCH; return; }
    case 139:{ EvFlag* f=evf_lock((uint32_t)R(3)); uint64_t b=0; if(f){ b=f->bits; LeaveCriticalSection(&f->cs); }
               if(R(4)) PPU_STD(base,(uint32_t)R(4),b); ctx->r[3]=f?0:LV2_ESRCH; return; }
    case 90: {
        EnterCriticalSection(&g_lock);
        Sem* s=sem_alloc(); uint32_t id=0;
        if(s){ s->count=(int32_t)R(5); id=s->id; LeaveCriticalSection(&s->cs); }
        LeaveCriticalSection(&g_lock);
        if(!id){ lv2_create_failed("semaphore",NSEM,ctx); ctx->r[3]=LV2_EAGAIN; return; }
        if(R(3)) PPU_STW(base,(uint32_t)R(3),id); ctx->r[3]=0; return; }
    case 91: {
        uint32_t id=(uint32_t)R(3), rc=LV2_ESRCH;
        EnterCriticalSection(&g_lock);
        Sem* s=sem_lock(id);
        if(s){ if(s->nwait) rc=LV2_EBUSY; else { s->used=0; s->id=0; rc=0; }
               LeaveCriticalSection(&s->cs); }
        LeaveCriticalSection(&g_lock);
        if(rc) fprintf(stderr,"[sem] destroy id=0x%x rc=0x%x lr=0x%llx t%llu\n",id,rc,(unsigned long long)ctx->lr,(unsigned long long)t_gid);
        ctx->r[3]=rc; return; }
    case 92: case 93: {
        Sem* s=sem_find((uint32_t)R(3)); if(!s){ ctx->r[3]=LV2_ESRCH; return; }
        uint32_t rc=0;
        uint64_t sto=(n==92)?R(4):0;
        uint64_t sdl=sto?GetTickCount64()+(sto+999)/1000:0;
        { static volatile long wn; long k=++wn; if(k<=48||(k%4096)==0) fprintf(stderr,"[sem] wait id=0x%x cnt=%d to=%llu (k=%ld)\n",s->id,s->count,(unsigned long long)sto,k); }
        if(!(s=sem_lock((uint32_t)R(3)))){ ctx->r[3]=LV2_ESRCH; return; }
        s->nwait++;
        while(s->count<=0){
            if(n==93){ rc=LV2_EBUSY; break; }
            if(sdl && GetTickCount64()>=sdl){ rc=0x8001000bu; break; }
            DWORD slice=100;
            if(sdl){ uint64_t now=GetTickCount64(); if(now<sdl && sdl-now<slice) slice=(DWORD)(sdl-now); }
            SleepConditionVariableCS(&s->cv,&s->cs,slice);
        }
        if(!rc) s->count--;
        s->nwait--;
        LeaveCriticalSection(&s->cs); ctx->r[3]=rc; return; }
    case 94: { Sem* s=sem_lock((uint32_t)R(3)); if(s){ s->count+=(int32_t)R(4); WakeAllConditionVariable(&s->cv); LeaveCriticalSection(&s->cs);}
               { static volatile long n; long k=++n; if(k<=48||(k%4096)==0) fprintf(stderr,"[sem] post id=0x%x n=%lld (k=%ld)\n",(uint32_t)R(3),(long long)R(4),k); }
               ctx->r[3]=s?0:LV2_ESRCH; return; }
    case 114:{ Sem* s=sem_lock((uint32_t)R(3)); int32_t c=0; if(s){ c=s->count; LeaveCriticalSection(&s->cs); }
               if(R(4)) PPU_STW(base,(uint32_t)R(4),(uint32_t)(c<0?0:c)); ctx->r[3]=s?0:LV2_ESRCH; return; }
    case 128:{ uint32_t id=evq_create(); if(id&&R(3)) PPU_STW(base,(uint32_t)R(3),id);
               { EvQueue* q=evq_find(id); if(q) q->key=R(5); }
               ctx->r[3]=id?0:LV2_EAGAIN; return; }
    case 129:{
        uint32_t id=(uint32_t)R(3), mode=(uint32_t)R(4), rc=LV2_ESRCH;
        if(mode>1){ ctx->r[3]=LV2_EINVAL; return; }
        EnterCriticalSection(&g_lock);
        EvQueue* q=evq_lock(id);
        if(q){ if(q->nwait && !(mode&1)) rc=LV2_EBUSY;
               else { q->used=0; q->id=0; q->n=0; WakeAllConditionVariable(&q->cv); rc=0; }
               LeaveCriticalSection(&q->cs); }
        if(!rc){
            for(int i=0;i<NEVP;i++) if(g_evp[i].used && g_evp[i].queue==id) g_evp[i].queue=0;
            for(int i=0;i<NSPUGRP;i++) if(g_spugrp[i].used)
                for(int b=0;b<64;b++) if(g_spugrp[i].spup_q[b]==id) g_spugrp[i].spup_q[b]=0; }
        LeaveCriticalSection(&g_lock);
        fprintf(stderr,"[EVQ] destroy id=0x%x mode=%u rc=0x%x lr=0x%llx t%llu\n",id,mode,rc,(unsigned long long)ctx->lr,(unsigned long long)t_gid);
        ctx->r[3]=rc; return; }
    case 130:{
        LvEvent ev={0}; uint32_t rc=evq_pop((uint32_t)R(3),&ev,R(5));
        { static volatile long lg; long k=InterlockedIncrement((volatile long*)&lg);
          if(k<=64||(k%8192)==0) fprintf(stderr,"[EVQ] recv id=0x%x rc=0x%x src=0x%llx d1=0x%llx t%llu (n=%ld)\n",
              (uint32_t)R(3),rc,(unsigned long long)ev.src,(unsigned long long)ev.d1,(unsigned long long)t_gid,k); }
        if(!rc){ ctx->r[4]=ev.src; ctx->r[5]=ev.d1; ctx->r[6]=ev.d2; ctx->r[7]=ev.d3; }
        ctx->r[3]=rc; return; }
    case 131:{
        EvQueue* q=evq_lock((uint32_t)R(3)); uint32_t arr=(uint32_t)R(4),cap=(uint32_t)R(5),cntp=(uint32_t)R(6);
        uint32_t got=0;
        if(q){
            while(q->n>0 && got<cap){ LvEvent* e=&q->ev[0];
                PPU_STD(base,arr+got*32+0,e->src); PPU_STD(base,arr+got*32+8,e->d1);
                PPU_STD(base,arr+got*32+16,e->d2); PPU_STD(base,arr+got*32+24,e->d3);
                for(int i=1;i<q->n;i++) q->ev[i-1]=q->ev[i]; q->n--; got++; }
            LeaveCriticalSection(&q->cs); }
        if(cntp) PPU_STW(base,cntp,got); ctx->r[3]=q?0:LV2_ESRCH; return; }
    case 133:{ EvQueue* q=evq_lock((uint32_t)R(3)); if(q){ q->n=0; LeaveCriticalSection(&q->cs);} ctx->r[3]=q?0:LV2_ESRCH; return; }
    case 134:{
        EnterCriticalSection(&g_lock);
        EvPort* p=0; for(int i=0;i<NEVP;i++) if(!g_evp[i].used){ p=&g_evp[i]; break; }
        if(p){ memset(p,0,sizeof *p); p->id=++g_spu_idseq; p->name=R(5); p->used=1; }
        uint32_t id=p?p->id:0;
        LeaveCriticalSection(&g_lock);
        if(!id){ lv2_create_failed("event port",NEVP,ctx); ctx->r[3]=LV2_EAGAIN; return; }
        if(R(3)) PPU_STW(base,(uint32_t)R(3),id); ctx->r[3]=0; return; }
    case 135:{
        uint32_t id=(uint32_t)R(3), rc=LV2_ESRCH;
        EnterCriticalSection(&g_lock);
        EvPort* p=evp_find(id);
        if(p){ if(p->queue) rc=LV2_EISCONN; else { p->used=0; p->id=0; rc=0; } }
        LeaveCriticalSection(&g_lock);
        if(rc) fprintf(stderr,"[EVP] destroy id=0x%x rc=0x%x lr=0x%llx t%llu\n",id,rc,(unsigned long long)ctx->lr,(unsigned long long)t_gid);
        ctx->r[3]=rc; return; }
    case 136:{ EvPort* p=evp_find((uint32_t)R(3)); if(p) p->queue=(uint32_t)R(4); ctx->r[3]=p?0:LV2_ESRCH; return; }
    case 137:{ EvPort* p=evp_find((uint32_t)R(3)); if(p) p->queue=0; ctx->r[3]=p?0:LV2_ESRCH; return; }
    case 138:{
        EvPort* p=evp_find((uint32_t)R(3)); uint32_t qid=p?p->queue:0;
        EvQueue* q=qid?evq_find(qid):0;
        int ok = q && evq_push(q, qid, p->name?p->name:p->id, R(4), R(5), R(6));
        ctx->r[3]=ok?0:(p?LV2_ENOTCONN:LV2_ESRCH); return; }
    case 165:{ SpuThr* t=sputhr_find((uint32_t)R(3)); if(t&&R(4)) PPU_STW(base,(uint32_t)R(4),t->t?spu_thread_stop_code(t->t):0); ctx->r[3]=0; return; }
    case 166:{ SpuThr* t=sputhr_find((uint32_t)R(3)); uint32_t a=(uint32_t)R(4);
               if(t&&a){ for(int i=0;i<4;i++) t->arg[i]=PPU_LD(base,a+8u*(uint32_t)i); } ctx->r[3]=0; return; }
    case 170: ctx->r[3]=spu_grp_create((uint32_t)R(3),(uint32_t)R(4)); return;
    case 171: ctx->r[3]=0; return;
    case 172: ctx->r[3]=spu_thr_init((uint32_t)R(3),(uint32_t)R(4),(uint32_t)R(5),(uint32_t)R(6),(uint32_t)R(8)); return;
    case 173: ctx->r[3]=spu_grp_start((uint32_t)R(3)); return;
    case 174: case 175: case 176: case 177: case 179: case 180: ctx->r[3]=0; return;
    case 178:{
        SpuGrp* g=spugrp_find((uint32_t)R(3)); if(!g){ ctx->r[3]=0x8001000au; return; }
        for(int i=0;i<g->nthr;i++){ SpuThr* t=sputhr_find(g->thr[i]);
            if(t&&t->started&&t->t) spu_thread_join(t->t); }
        if(R(4)) PPU_STW(base,(uint32_t)R(4),1);
        if(R(5)) PPU_STW(base,(uint32_t)R(5),0);
        ctx->r[3]=0; return; }
    case 181:{
        SpuThr* t=sputhr_find((uint32_t)R(3)); uint32_t a=(uint32_t)R(4); uint64_t v=R(5); uint32_t sz=(uint32_t)R(6);
        if(t&&t->t){ uint8_t buf[8]; for(uint32_t i=0;i<sz&&i<8;i++) buf[i]=(uint8_t)(v>>(8*(sz-1-i))); spu_thread_write_ls(t->t,a,buf,sz>8?8:sz); }
        ctx->r[3]=0; return; }
    case 182:{
        SpuThr* t=sputhr_find((uint32_t)R(3)); uint32_t a=(uint32_t)R(4),vp=(uint32_t)R(5),sz=(uint32_t)R(6);
        uint64_t v=0; if(t&&t->t){ uint8_t* ls=spu_thread_ls(t->t); for(uint32_t i=0;i<sz&&i<8&&a+i<0x40000;i++) v=(v<<8)|ls[a+i]; }
        if(vp) PPU_STD(base,vp,v); ctx->r[3]=0; return; }
    case 184:{ SpuThr* t=sputhr_find((uint32_t)R(3)); if(t&&t->t) spu_signal(t->t,(int)R(4)==1?2:1,(uint32_t)R(5)); ctx->r[3]=0; return; }
    case 185:{ SpuGrp* g=spugrp_find((uint32_t)R(3)); if(g) g->evq=(uint32_t)R(4); ctx->r[3]=0; return; }
    case 251:{
        SpuGrp* g=spugrp_find((uint32_t)R(3)); uint64_t req=R(5); uint32_t outp=(uint32_t)R(6);
        if(!g){ ctx->r[3]=0x8001000au; return; }
        int spup=-1;
        for(int b=0;b<64;b++) if((req>>(63-b))&1 && !g->spup_q[b]){ spup=b; break; }
        if(spup<0){ ctx->r[3]=0x80010004u; return; }
        g->spup_q[spup]=(uint32_t)R(4);
        if(outp) PPU_STB(base,outp,(uint8_t)spup);
        fprintf(stderr,"[SPU] connect_event_all_threads grp=0x%x q=0x%x spup=%d\n",
                (uint32_t)R(3),(uint32_t)R(4),spup);
        ctx->r[3]=0; return; }
    case 252:{
        SpuGrp* g=spugrp_find((uint32_t)R(3)); uint32_t spup=(uint32_t)(uint8_t)R(4);
        if(!g){ ctx->r[3]=LV2_ESRCH; return; }
        if(spup>63){ ctx->r[3]=LV2_EINVAL; return; }
        fprintf(stderr,"[SPU] disconnect_event_all_threads grp=0x%x spup=%u (q=0x%x)\n",
                (uint32_t)R(3),spup,g->spup_q[spup]);
        g->spup_q[spup]=0; ctx->r[3]=0; return; }
    case 186: ctx->r[3]=0; return;
    case 187: ctx->r[3]=0; return;
    case 188:{ if(R(4)) PPU_STD(base,(uint32_t)R(4),0); ctx->r[3]=0; return; }
    case 190:{ SpuThr* t=sputhr_find((uint32_t)R(3)); if(t&&t->t) spu_push_inmbox(t->t,(uint32_t)R(4)); ctx->r[3]=0; return; }
    case 191: case 192: case 193: case 194: ctx->r[3]=0; return;
    case 801:
        ctx->r[3]=fs_open(base,(uint32_t)R(3),(int)(int32_t)R(4),(uint32_t)R(5)); return;
    case 802: {
        int fd=(int)(int32_t)R(3); uint32_t buf=(uint32_t)R(4),nb=(uint32_t)R(5),pn=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ ctx->r[3]=CELL_FS_EBADF; return; }
        if((uint64_t)buf+nb>g_size){ ctx->r[3]=CELL_FS_EINVAL; return; }
        fswatch_check("sys_fs_read",buf,nb,fd,ctx);
        int64_t mtoff = g_mtrc_on ? _ftelli64(g_fsfd[fd].fp) : 0;
        size_t r=fread(base+buf,1,nb,g_fsfd[fd].fp);
        MTRC(MTRC_FS_READ,(uint32_t)fd,(uint32_t)mtoff,nb,(uint32_t)r,g_fsfd[fd].name);
        { static volatile long n; long k=++n; if(k<=32||(k%2048)==0) fprintf(stderr,"[FS] read fd=%d nb=0x%x got=0x%zx lr=0x%llx fn=sub_%x (n=%ld)\n",fd,nb,r,(unsigned long long)ctx->lr,g_curfn,k); }
        if(pn) PPU_STD(base,pn,(uint64_t)r); ctx->r[3]=CELL_FS_OK; return; }
    case 803: {
        int fd=(int)(int32_t)R(3); uint32_t buf=(uint32_t)R(4),nb=(uint32_t)R(5),pn=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ ctx->r[3]=CELL_FS_EBADF; return; }
        if((uint64_t)buf+nb>g_size){ ctx->r[3]=CELL_FS_EINVAL; return; }
        size_t w=fwrite(base+buf,1,nb,g_fsfd[fd].fp);
        if(pn) PPU_STD(base,pn,(uint64_t)w); ctx->r[3]=CELL_FS_OK; return; }
    case 804: {
        int fd=(int)(int32_t)R(3);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ ctx->r[3]=CELL_FS_EBADF; return; }
        fclose(g_fsfd[fd].fp); g_fsfd[fd].fp=0; g_fsfd[fd].used=0; ctx->r[3]=CELL_FS_OK; return; }
    case 818: {
        int fd=(int)(int32_t)R(3); int64_t off=(int64_t)R(4); int wh=(int)(int32_t)R(5); uint32_t pp=(uint32_t)R(6);
        if(fd<0||fd>=256||!g_fsfd[fd].used){ ctx->r[3]=CELL_FS_EBADF; return; }
        int o = wh==1?SEEK_CUR : wh==2?SEEK_END : SEEK_SET;
        if(_fseeki64(g_fsfd[fd].fp,off,o)!=0){ ctx->r[3]=CELL_FS_EINVAL; return; }
        { static volatile long n; long k=++n; if(k<=32||(k%2048)==0) fprintf(stderr,"[FS] seek fd=%d off=0x%llx wh=%d (n=%ld)\n",fd,(unsigned long long)off,wh,k); }
        if(pp) PPU_STD(base,pp,(uint64_t)_ftelli64(g_fsfd[fd].fp)); ctx->r[3]=CELL_FS_OK; return; }
    case 805: ctx->r[3]=fs_opendir(base,(uint32_t)R(3),(uint32_t)R(4)); return;
    case 806: ctx->r[3]=fs_readdir(base,(int)(int32_t)R(3),(uint32_t)R(4),(uint32_t)R(5)); return;
    case 807: ctx->r[3]=fs_closedir((int)(int32_t)R(3)); return;
    case 808: ctx->r[3]=fs_stat(base,(uint32_t)R(3),(uint32_t)R(4)); return;
    case 809: ctx->r[3]=fs_fstat(base,(int)(int32_t)R(3),(uint32_t)R(4)); return;
    default: {
        enum{CAP=256}; static uint32_t seen[CAP]; static int cnt=0; int found=0;
        for(int i=0;i<cnt;i++) if(seen[i]==n){found=1;break;}
        if(!found){ if(cnt<CAP) seen[cnt++]=n;
            fprintf(stderr,"[SC] syscall %u (unhandled) r3=0x%llx r4=0x%llx "
                    "r5=0x%llx r6=0x%llx lr=0x%llx fn=sub_%x\n",n,
                    (unsigned long long)R(3),(unsigned long long)R(4),
                    (unsigned long long)R(5),(unsigned long long)R(6),
                    (unsigned long long)ctx->lr,g_curfn); }
        ctx->r[3]=0; return;
    }}
}

static void ctxreg_main(PPUContext* ctx){
    static __declspec(thread) int done;
    if(done || t_gid!=1) return;
    done=1;
    long i=InterlockedIncrement(&g_nctxreg)-1;
    if(i<64){ g_ctxreg[i].tid=1; g_ctxreg[i].ctx=ctx;
              g_ctxreg[i].htid=GetCurrentThreadId(); }
}
void ppu_syscall(PPUContext* ctx, uint8_t* base){
    ctxreg_main(ctx);
    int sc_prev = g_cursc;
    if(g_scprof<0) g_scprof=getenv("PS3_SCPROF")?1:0;
    if(!g_scprof){ ppu_syscall_body(ctx,base); g_cursc=sc_prev; return; }
    uint32_t n=(uint32_t)ctx->r[11]; if(n>=SCP_NSC) n=SCP_NSC-1;
    LARGE_INTEGER a,b; QueryPerformanceCounter(&a);
    ppu_syscall_body(ctx,base);
    QueryPerformanceCounter(&b);
    g_cursc = sc_prev;
    InterlockedIncrement64(&g_scp_cnt[n]);
    InterlockedExchangeAdd64(&g_scp_tk[n], b.QuadPart-a.QuadPart);
    uint32_t t2=(uint32_t)t_gid;
    if(t2<SCP_NT){ InterlockedIncrement64(&g_scp_tct[t2][n]);
                   InterlockedExchangeAdd64(&g_scp_ttk[t2][n], b.QuadPart-a.QuadPart); }
}
void ppu_hle(uint32_t nid, const char* lib, const char* name, PPUContext* ctx, uint8_t* base){
    ctxreg_main(ctx);
    const char* hle_prev = g_curhle;
    if(g_scprof<0) g_scprof=getenv("PS3_SCPROF")?1:0;
    if(!g_scprof){ ppu_hle_body(nid,lib,name,ctx,base); g_curhle=hle_prev; return; }
    LARGE_INTEGER a,b; QueryPerformanceCounter(&a);
    ppu_hle_body(nid,lib,name,ctx,base);
    QueryPerformanceCounter(&b);
    g_curhle = hle_prev;
    scprof_hle_add(name, b.QuadPart-a.QuadPart);
}

static int sc_ptr_ok(uint64_t v){
    return !(v>>32) && (uint32_t)v>=0x10000 && (uint64_t)(uint32_t)v+32<=g_size;
}
static void sc_hex32(FILE* f, const char* pfx, uint32_t ea){
    fprintf(f,"%s0x%08x:",pfx,ea);
    for(int i=0;i<8;i++) fprintf(f," %08x",(uint32_t)PPU_LW(g_base,ea+i*4));
    fputc(' ',f);
    for(int i=0;i<32;i++){ uint8_t c=g_base[ea+i]; fputc(c>=32&&c<127?c:'.',f); }
    fputc('\n',f);
}

static void sc_threads(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/ppu.txt",dir);
    FILE* f=fopen(p,"wb"); if(!f) return;
    fprintf(f,"== lv2 thread table ==\n");
    for(int i=0;i<g_nthreads;i++) if(g_threads[i].id)
        fprintf(f,"  id=%-4llu handle=%s retval=0x%llx\n",
                (unsigned long long)g_threads[i].id,
                g_threads[i].h?"live":"joined",
                (unsigned long long)g_threads[i].retval);
    fprintf(f,"\n== last-entered function, all registered threads ==\n");
    { long n=g_nppumon; if(n>64) n=64;
      for(long i=0;i<n;i++){
          int sc=g_ppumon[i].sc?*g_ppumon[i].sc:-1;
          const char* h=g_ppumon[i].hle?*g_ppumon[i].hle:0;
          fprintf(f,"  t%-4llu host=%-6lu fn=sub_%x",
                  (unsigned long long)g_ppumon[i].id,(unsigned long)g_ppumon[i].htid,
                  g_ppumon[i].fn?*g_ppumon[i].fn:0);
          if(sc>=0) fprintf(f," sc=%d",sc);
          if(h)     fprintf(f," hle=%s",h);
          fputc('\n',f);
      } }
    long nc=g_nctxreg; if(nc>64) nc=64;
    for(long i=0;i<nc;i++){
        PPUContext* c=g_ctxreg[i].ctx; if(!c) continue;
        fprintf(f,"\n== t%llu (host %lu) ==\n",
                (unsigned long long)g_ctxreg[i].tid,(unsigned long)g_ctxreg[i].htid);
        for(int r=0;r<32;r+=4){
            fprintf(f,"  r%-2d",r);
            for(int j=0;j<4;j++) fprintf(f," %016llx",(unsigned long long)c->r[r+j]);
            fputc('\n',f);
        }
        fprintf(f,"  lr=%016llx ctr=%016llx ca=%u ov=%u so=%u fpscr=%08x vrsave=%08x\n",
                (unsigned long long)c->lr,(unsigned long long)c->ctr,
                c->ca,c->ov,c->so,c->fpscr,c->vrsave);
        fprintf(f,"  cr=");
        for(int k=0;k<8;k++) fprintf(f,"%x",c->cr[k]&0xf);
        fprintf(f,"  reserve=%s0x%llx resume_pc=0x%x\n",
                c->reserve_valid?"":"(stale)",
                (unsigned long long)c->reserve_addr,c->resume_pc);
        for(int r=0;r<32;r+=4){
            fprintf(f,"  f%-2d",r);
            for(int j=0;j<4;j++) fprintf(f," %-14g",c->f[r+j]);
            fputc('\n',f);
        }
        { uint32_t sp=(uint32_t)c->r[1];
          fprintf(f,"  stack r1=0x%x:",sp);
          for(int d=0;d<24;d++){
              if((uint64_t)sp+24>g_size) break;
              uint32_t back=(uint32_t)PPU_LW(g_base,sp+4);
              if(back<=sp||(uint64_t)back+24>g_size) break;
              fprintf(f," sub_%x",(uint32_t)PPU_LW(g_base,back+20));
              sp=back;
          }
          fputc('\n',f); }
        for(int r=1;r<32;r++){
            if(!sc_ptr_ok(c->r[r])) continue;
            char pfx[24]; snprintf(pfx,sizeof pfx,"    r%-2d -> ",r);
            sc_hex32(f,pfx,(uint32_t)c->r[r]);
        }
        if(sc_ptr_ok(c->r[1])){
            uint32_t sp=(uint32_t)c->r[1];
            for(uint32_t o=0;o<0x80;o+=32){
                if((uint64_t)sp+o+32>g_size) break;
                sc_hex32(f,"    stk ",sp+o);
            }
        }
    }
    fclose(f);
}

static void sc_sync(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/sync.txt",dir);
    FILE* f=fopen(p,"wb"); if(!f) return;
    DWORD now=GetTickCount();
    fprintf(f,"== event flags ==\n");
    for(int i=0;i<NEVF;i++){
        EvFlag* e=&g_evf[i]; if(!e->used) continue;
        fprintf(f,"  id=0x%-6x bits=0x%016llx lastset=",e->id,(unsigned long long)e->bits);
        if(e->last_set_tick) fprintf(f,"%s %lums ago",
            e->last_set_tid==~0ull?"SPU":"PPU",(unsigned long)(now-e->last_set_tick));
        else fprintf(f,"never");
        for(int j=0;j<6;j++) if(e->w[j].tid)
            fprintf(f," | wait t%llu bits=0x%llx mode=0x%x",
                (unsigned long long)e->w[j].tid,
                (unsigned long long)e->w[j].bits,e->w[j].mode);
        fputc('\n',f);
    }
    fprintf(f,"\n== semaphores ==\n");
    for(int i=0;i<NSEM;i++) if(g_sem[i].used)
        fprintf(f,"  id=0x%-6x count=%d\n",g_sem[i].id,g_sem[i].count);
    fprintf(f,"\n== event queues ==\n");
    for(int i=0;i<NEVQ;i++){
        EvQueue* q=&g_evq[i]; if(!q->used) continue;
        fprintf(f,"  id=0x%-6x key=0x%llx pending=%d",q->id,
                (unsigned long long)q->key,q->n);
        for(int j=0;j<q->n&&j<4;j++)
            fprintf(f," | ev src=0x%llx d1=0x%llx",
                (unsigned long long)q->ev[j].src,(unsigned long long)q->ev[j].d1);
        fputc('\n',f);
    }
    fprintf(f,"\n== event ports ==\n");
    for(int i=0;i<NEVP;i++) if(g_evp[i].used)
        fprintf(f,"  id=0x%-6x queue=0x%x name=0x%llx\n",g_evp[i].id,g_evp[i].queue,
                (unsigned long long)g_evp[i].name);
    fprintf(f,"\n== mutex / cond ==\n");
    { int nm=0,ncv=0;
      for(int i=0;i<g_nidsync;i++) if(g_idsync[i].used){ if(g_idsync[i].is_cond) ncv++; else nm++; }
      fprintf(f,"  %d mutexes, %d condition variables in use\n",nm,ncv);
      for(int i=0;i<g_nidsync;i++) if(g_idsync[i].used&&g_idsync[i].is_cond)
          fprintf(f,"  cond id=0x%x on mutex 0x%x\n",g_idsync[i].id,g_idsync[i].mutex_id); }
    fprintf(f,"\n== SPU thread groups ==\n");
    for(int i=0;i<NSPUGRP;i++){
        SpuGrp* g=&g_spugrp[i]; if(!g->used) continue;
        fprintf(f,"  grp id=0x%x nthr=%d started=%d evq=0x%x thr:",
                g->id,g->nthr,g->started,g->evq);
        for(int j=0;j<g->nthr&&j<8;j++) fprintf(f," 0x%x",g->thr[j]);
        fputc('\n',f);
    }
    fprintf(f,"\n== SPU threads (lv2 view) ==\n");
    for(int i=0;i<NSPUTHR;i++){
        SpuThr* t=&g_sputhr[i]; if(!t->used) continue;
        fprintf(f,"  id=0x%-6x group=0x%-6x entry=0x%05x started=%d arg=%llx,%llx\n",
                t->id,t->group,t->entry,t->started,
                (unsigned long long)t->arg[0],(unsigned long long)t->arg[1]);
    }
    fclose(f);
}

static void sc_hle(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/hle.txt",dir);
    FILE* f=fopen(p,"wb"); if(!f) return;
    fprintf(f,"== guest heap (runtime allocator) ==\n");
    { uint32_t used=0,freeb=0;
      for(int i=0;i<g_nmemblk;i++){ if(g_memblk[i].free) freeb+=g_memblk[i].size;
                                    else used+=g_memblk[i].size; }
      fprintf(f,"  %d blocks, %u bytes in use, %u free\n",g_nmemblk,used,freeb);
      for(int i=0;i<g_nmemblk&&i<64;i++)
          fprintf(f,"  [%2d] addr=0x%08x size=0x%-8x %s\n",i,g_memblk[i].addr,
                  g_memblk[i].size,g_memblk[i].free?"free":"used"); }
    fprintf(f,"\n== open files ==\n");
    for(int i=0;i<256;i++) if(g_fsfd[i].used)
        fprintf(f,"  fd=%-3d %-6s %s\n",i,g_fsfd[i].is_dir?"dir":"file",g_fsfd[i].name);
    fprintf(f,"\n== GCM io map (EA <-> RSX io offset) ==\n");
    for(int i=0;i<g_ngcmio;i++)
        fprintf(f,"  ea=0x%08x io=0x%08x size=0x%x\n",
                g_gcmio[i].ea,g_gcmio[i].io,g_gcmio[i].size);
    fclose(f);
}

static void sc_gcm(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/gcm.txt",dir);
    FILE* f=fopen(p,"wb"); if(!f) return;
    fprintf(f,"ctx=0x%08x ctrl=0x%08x label=0x%08x local=0x%08x io=0x%08x+0x%x\n",
            gcm_ctx_ea,gcm_ctrl_ea,gcm_label_ea,gcm_cfg_local_ea,gcm_io_ea,gcm_io_size);
    fprintf(f,"cb=0x%08x+0x%x\n",gcm_cb_ea,gcm_cb_size);
    fprintf(f,"flips=%ld flip_pending=%ld flip_status=%ld flip_buf=%ld flip_mode=%ld\n",
            g_flipno,gcm_flip_pending,gcm_flip_status,gcm_flip_buf,gcm_flip_mode);
    if(gcm_ctrl_ea){
        uint32_t put=(uint32_t)PPU_LW(g_base,gcm_ctrl_ea+0);
        uint32_t get=(uint32_t)PPU_LW(g_base,gcm_ctrl_ea+4);
        uint32_t ref=(uint32_t)PPU_LW(g_base,gcm_ctrl_ea+8);
        fprintf(f,"ctrl: put=0x%08x get=0x%08x ref=0x%08x %s\n",put,get,ref,
                put==get?"(drained)":"(FIFO has work outstanding)");
        uint32_t gea=gcm_ioff2ea(get);
        if(gea && (uint64_t)gea+256<=g_size){
            fprintf(f,"\nFIFO words at get (ea=0x%08x):\n",gea);
            for(uint32_t o=0;o<256;o+=16){
                fprintf(f,"  +%03x",o);
                for(int i=0;i<4;i++) fprintf(f," %08x",(uint32_t)PPU_LW(g_base,gea+o+i*4));
                fputc('\n',f);
            }
        }
    }
    if(gcm_label_ea && (uint64_t)gcm_label_ea+0x800<=g_size){
        fprintf(f,"\nlabel block (semaphore/report area) 0x%08x, non-zero entries:\n",
                gcm_label_ea);
        for(uint32_t o=0;o<0x800;o+=4){
            uint32_t v=(uint32_t)PPU_LW(g_base,gcm_label_ea+o);
            if(v) fprintf(f,"  +0x%03x = 0x%08x\n",o,v);
        }
    }
    fclose(f);
}

static void ppu_statecap(const char* dir){
    sc_threads(dir);
    sc_sync(dir);
    sc_hle(dir);
    sc_gcm(dir);
}
