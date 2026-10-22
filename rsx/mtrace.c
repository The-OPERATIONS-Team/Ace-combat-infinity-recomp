#include "mtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int g_mtrc_on = 0;

static MtrcProviders g_prov;
static uint32_t      g_t0;

void mtrc_set_providers(const MtrcProviders* p){ if(p) g_prov = *p; }

#define RING 8192
typedef struct {
    volatile LONG seq;
    uint32_t cat, a, b, c, d, t_ms, tid;
    const char* name;
} RingEv;
static RingEv          g_ring[RING];
static volatile LONG64 g_wr;
static LONG64          g_rd;
static volatile LONG   g_drop;

void mtrc_event(uint32_t cat, uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                const char* name){
    if(!g_mtrc_on) return;
    LONG64 i = InterlockedIncrement64(&g_wr) - 1;
    RingEv* s = &g_ring[i & (RING - 1)];
    s->cat = cat; s->a = a; s->b = b; s->c = c; s->d = d;
    s->t_ms = (uint32_t)(GetTickCount() - g_t0);
    s->tid  = (uint32_t)GetCurrentThreadId();
    s->name = name;
    InterlockedExchange(&s->seq, (LONG)(i + 1));
}

#define MAXPPU 64
#define MAXHLE 256
#define MAXSC  64
#define MAXSPU 128
#define MAXEV  2048
#define MAXSTR 1024

static MtrcPpuRow  g_ppu[MAXPPU];
static MtrcNameRow g_hle[MAXHLE], g_spu[MAXSPU];
static MtrcScRow   g_sc [MAXSC];
static MtrcFileEv  g_ev [MAXEV];

static const char* g_hle_nm[MAXHLE];
static const char* g_spu_nm[MAXSPU];
static uint32_t    g_hle_ca[MAXHLE], g_hle_us[MAXHLE];
static uint32_t    g_spu_ca[MAXSPU], g_spu_us[MAXSPU];
static const char* g_ppu_hle[MAXPPU];

static const char* g_str[MAXSTR];
static int         g_nstr;

static uint32_t intern(const char* s){
    if(!s || !*s) return 0;
    for(int i = 1; i <= g_nstr; i++)
        if(g_str[i] == s || !strcmp(g_str[i], s)) return (uint32_t)i;
    if(g_nstr + 1 >= MAXSTR) return 0;
    g_str[++g_nstr] = s;
    return (uint32_t)g_nstr;
}

static uint8_t* g_out;
static size_t   g_outcap, g_outn;

static int out_reserve(size_t need){
    if(g_outcap >= need) return 1;
    size_t c = g_outcap ? g_outcap : 16384;
    while(c < need) c += c / 2 + 16384;
    uint8_t* np = (uint8_t*)realloc(g_out, c);
    if(!np) return 0;
    g_out = np; g_outcap = c; return 1;
}
static int out_put(const void* d, size_t n){
    if(!n) return 1;
    if(!out_reserve(g_outn + n)) return 0;
    memcpy(g_out + g_outn, d, n); g_outn += n; return 1;
}

void mtrc_start(uint32_t t0){
    g_t0 = t0;
    g_rd = g_wr = 0; g_drop = 0;
    memset(g_ring, 0, sizeof g_ring);
    if(g_prov.enable) g_prov.enable(1);
    g_mtrc_on = 1;
}

void mtrc_stop(void){
    g_mtrc_on = 0;
    if(g_prov.enable) g_prov.enable(0);
}

const void* mtrc_frame(uint32_t* nbytes){
    *nbytes = 0;
    if(!g_mtrc_on) return NULL;

    g_nstr = 0; g_outn = 0;

    int nppu = 0;
    if(g_prov.ppu){
        nppu = g_prov.ppu(g_ppu, MAXPPU, g_ppu_hle);
        if(nppu < 0) nppu = 0;
        if(nppu > MAXPPU) nppu = MAXPPU;
        for(int i = 0; i < nppu; i++) g_ppu[i].str_hle = intern(g_ppu_hle[i]);
    }

    int nhle = 0;
    if(g_prov.hle){
        nhle = g_prov.hle(g_hle_nm, g_hle_ca, g_hle_us, MAXHLE);
        if(nhle < 0) nhle = 0;
        if(nhle > MAXHLE) nhle = MAXHLE;
        for(int i = 0; i < nhle; i++){
            g_hle[i].str = intern(g_hle_nm[i]);
            g_hle[i].calls = g_hle_ca[i];
            g_hle[i].us = g_hle_us[i];
        }
    }
    int nsc = 0;
    if(g_prov.sc){
        nsc = g_prov.sc(g_sc, MAXSC);
        if(nsc < 0) nsc = 0;
        if(nsc > MAXSC) nsc = MAXSC;
    }

    int nspu = 0;
    uint32_t wait_us = 0, lock_us = 0, res_us = 0;
    if(g_prov.spu){
        nspu = g_prov.spu(g_spu_nm, g_spu_ca, g_spu_us, MAXSPU,
                          &wait_us, &lock_us, &res_us);
        if(nspu < 0) nspu = 0;
        if(nspu > MAXSPU) nspu = MAXSPU;
        for(int i = 0; i < nspu; i++){
            g_spu[i].str = intern(g_spu_nm[i]);
            g_spu[i].calls = g_spu_ca[i];
            g_spu[i].us = g_spu_us[i];
        }
    }

    int nev = 0;
    {
        LONG64 wr = g_wr, rd = g_rd;
        if(wr - rd > RING){
            InterlockedExchangeAdd(&g_drop, (LONG)(wr - rd - RING));
            rd = wr - RING;
        }
        for(; rd < wr && nev < MAXEV; rd++){
            RingEv* s = &g_ring[rd & (RING - 1)];
            if(s->seq != (LONG)(rd + 1)) continue;
            g_ev[nev].cat = s->cat; g_ev[nev].a = s->a; g_ev[nev].b = s->b;
            g_ev[nev].c = s->c;     g_ev[nev].d = s->d;
            g_ev[nev].t_ms = s->t_ms; g_ev[nev].tid = s->tid;
            g_ev[nev].str = intern(s->name);
            nev++;
        }
        g_rd = rd;
    }

    MtrcHdr h;
    h.magic = MTRC_MAGIC;
    h.nppu = (uint32_t)nppu; h.nhle = (uint32_t)nhle;
    h.nsc  = (uint32_t)nsc;  h.nspu = (uint32_t)nspu;
    h.nev  = (uint32_t)nev;  h.nstr = (uint32_t)g_nstr;
    h.wait_us = wait_us; h.lock_us = lock_us; h.resolve_us = res_us;
    h.dropped = (uint32_t)InterlockedExchange(&g_drop, 0);

    if(!out_put(&h, sizeof h)) return NULL;
    if(!out_put(g_ppu, sizeof(MtrcPpuRow)  * (size_t)nppu)) return NULL;
    if(!out_put(g_hle, sizeof(MtrcNameRow) * (size_t)nhle)) return NULL;
    if(!out_put(g_sc,  sizeof(MtrcScRow)   * (size_t)nsc )) return NULL;
    if(!out_put(g_spu, sizeof(MtrcNameRow) * (size_t)nspu)) return NULL;
    if(!out_put(g_ev,  sizeof(MtrcFileEv)  * (size_t)nev )) return NULL;
    for(int i = 1; i <= g_nstr; i++){
        size_t n = strlen(g_str[i]);
        if(n > 65535) n = 65535;
        uint16_t l = (uint16_t)n;
        if(!out_put(&l, 2) || !out_put(g_str[i], n)) return NULL;
    }

    *nbytes = (uint32_t)g_outn;
    return g_out;
}
