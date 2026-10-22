#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "ptrace.h"

int g_ptrc_on;

#define PT_RING 8192
typedef struct {
    PtEv ev[PT_RING];
    volatile LONG n;
    uint32_t dropped;
} PtSlot;
static PtSlot   g_slot[PT_SLOTS];
static uint32_t g_cap = 4096;
static uint64_t g_qpf, g_t0;
static PtEv*    g_out;
static uint32_t g_outcap;

void ptrc_start(void){
    if(!getenv("PS3_CAP_PTRACE")) return;
    const char* m = getenv("PS3_CAP_PTMAX");
    if(m && atoi(m) > 0){ g_cap = (uint32_t)atoi(m);
                          if(g_cap > PT_RING) g_cap = PT_RING; }
    LARGE_INTEGER f, q; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&q);
    g_qpf = (uint64_t)f.QuadPart; g_t0 = (uint64_t)q.QuadPart;
    for(int i = 0; i < PT_SLOTS; i++){ g_slot[i].n = 0; g_slot[i].dropped = 0; }
    if(!g_out){
        g_outcap = (uint32_t)PT_SLOTS * PT_RING;
        g_out = (PtEv*)malloc((size_t)g_outcap * sizeof(PtEv));
        if(!g_out){ fprintf(stderr, "[PTRACE] out of memory, not arming\n"); return; }
    }
    g_ptrc_on = 1;
    fprintf(stderr, "[PTRACE] armed: up to %u events per worker per frame "
                    "(PS3_CAP_PTMAX)\n", g_cap);
}

void ptrc_stop(void){ g_ptrc_on = 0; }

void ptrc_ev(uint32_t slot, uint32_t kind, uint32_t a, uint32_t b){
    if(slot >= PT_SLOTS) return;
    PtSlot* s = &g_slot[slot];
    LONG n = s->n;
    if(n >= (LONG)g_cap){ s->dropped++; return; }
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    PtEv* e = &s->ev[n];
    e->kind = kind; e->slot = slot; e->a = a; e->b = b;
    e->t_us = (uint32_t)(((uint64_t)q.QuadPart - g_t0) * 1000000ull / g_qpf);
    s->n = n + 1;
}

const void* ptrc_frame(uint32_t* nbytes){
    *nbytes = 0;
    if(!g_ptrc_on || !g_out) return NULL;

    static uint8_t* blk; static uint32_t blkcap;
    uint32_t nev = 0, dropped = 0, per[PT_SLOTS];
    for(int i = 0; i < PT_SLOTS; i++){
        LONG n = g_slot[i].n;
        if(n > (LONG)g_cap) n = (LONG)g_cap;
        per[i] = (uint32_t)n;
        if(nev + per[i] <= g_outcap){
            memcpy(g_out + nev, g_slot[i].ev, (size_t)per[i] * sizeof(PtEv));
            nev += per[i];
        } else per[i] = 0;
        dropped += g_slot[i].dropped;
        g_slot[i].dropped = 0;
        g_slot[i].n = 0;
    }
    if(!nev && !dropped) return NULL;

    uint32_t need = (uint32_t)sizeof(PtHdr) + nev * (uint32_t)sizeof(PtEv);
    if(need > blkcap){
        uint8_t* nb = (uint8_t*)realloc(blk, need);
        if(!nb) return NULL;
        blk = nb; blkcap = need;
    }
    PtHdr h; memset(&h, 0, sizeof h);
    h.magic = PT_MAGIC; h.nev = nev; h.nslot = PT_SLOTS;
    h.cap_per_slot = g_cap; h.dropped = dropped;
    for(int i = 0; i < PT_SLOTS; i++) h.nev_slot[i] = per[i];
    memcpy(blk, &h, sizeof h);
    memcpy(blk + sizeof h, g_out, (size_t)nev * sizeof(PtEv));
    *nbytes = need;
    return blk;
}
