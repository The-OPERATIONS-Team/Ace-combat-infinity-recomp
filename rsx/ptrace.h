#pragma once
#include <stdint.h>

enum {
    PT_GETLLAR = 1,
    PT_PUTLLC,
    PT_RCHCNT,
    PT_DMA,
    PT_WORK,
};

#define PT_MAGIC   0x31525450u
#define PT_SLOTS   8

typedef struct {
    uint32_t kind;
    uint32_t slot;
    uint32_t a, b;
    uint32_t t_us;
} PtEv;

typedef struct {
    uint32_t magic, nev, nslot, cap_per_slot;
    uint32_t dropped;
    uint32_t nev_slot[PT_SLOTS];
    uint32_t pad[3];
} PtHdr;

extern int g_ptrc_on;

void ptrc_start(void);
void ptrc_stop(void);
const void* ptrc_frame(uint32_t* nbytes);

void ptrc_ev(uint32_t slot, uint32_t kind, uint32_t a, uint32_t b);
#define PTRC(slot, kind, a, b) \
    do{ if(g_ptrc_on) ptrc_ev((slot), (kind), (a), (b)); }while(0)
