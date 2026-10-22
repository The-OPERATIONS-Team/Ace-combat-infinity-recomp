#pragma once
#include <stdint.h>
#include <string.h>

static inline uint64_t spd_tag128(const void* p){
    const uint8_t* b = (const uint8_t*)p;
    uint64_t h = 0x9e3779b97f4a7c15ull;
    for(int i = 0; i < 16; i++){
        uint64_t w; memcpy(&w, b + i * 8, 8);
        h = (h ^ w) * 0xff51afd7ed558ccdull;
        h ^= h >> 29;
    }
    return h;
}

#define SPD_LLSEEN 16
typedef struct {
    uint32_t ea[SPD_LLSEEN];
    uint64_t tag[SPD_LLSEEN];
    uint8_t  valid[SPD_LLSEEN];
    uint32_t idle;
} SpdLlNew;

static inline uint32_t spd_ll_new(SpdLlNew* s, uint32_t ea, uint64_t tag){
    unsigned i = (ea >> 7) & (SPD_LLSEEN - 1);
    if(s->valid[i] && s->ea[i] == ea && s->tag[i] == tag) return ++s->idle;
    s->ea[i] = ea; s->tag[i] = tag; s->valid[i] = 1;
    s->idle = 0;
    return 0;
}

typedef struct {
    uint32_t resv_ea; uint64_t resv_tag; uint8_t resv_valid;
    uint32_t sp_ea, sp_n;
} SpdLlOld;

static inline uint32_t spd_ll_old(SpdLlOld* s, uint32_t ea, uint64_t tag){
    uint32_t out = 0;
    if(s->resv_valid && s->resv_ea == ea && s->resv_tag == tag){
        if(s->sp_ea == ea) out = ++s->sp_n;
        else { s->sp_ea = ea; s->sp_n = 0; }
    } else { s->sp_ea = ea; s->sp_n = 0; }
    s->resv_ea = ea; s->resv_tag = tag; s->resv_valid = 1;
    return out;
}

typedef struct { uint32_t ch, val, n; } SpdCh;

static inline int spd_ch_blocking(uint32_t ch){
    switch(ch){
        case 0:
        case 3:
        case 4:
        case 28:
        case 29:
        case 30:
            return 1;
        default: return 0;
    }
}

static inline uint32_t spd_ch(SpdCh* s, uint32_t ch, uint32_t val){
    if(s->ch != ch || s->val != val){ s->ch = ch; s->val = val; s->n = 0; return 0; }
    return ++s->n;
}

enum { SPD_SPIN = 0, SPD_YIELD = 1, SPD_PARK = 2 };
static inline int spd_action(uint32_t streak, int yield_at, int park_at){
    if(yield_at <= 0 || streak < (uint32_t)yield_at) return SPD_SPIN;
    if(park_at  >  0 && streak >= (uint32_t)park_at) return SPD_PARK;
    return SPD_YIELD;
}

#define SPD_STRIPES_OLD 64
#define SPD_STRIPES_NEW 256
static inline uint32_t spd_stripe_old(uint32_t ea){
    return (ea >> 7) & (SPD_STRIPES_OLD - 1);
}
static inline uint32_t spd_stripe_new(uint32_t ea){
    uint32_t g = ea >> 7;
    return ((g * 2654435761u) >> 16) & (SPD_STRIPES_NEW - 1);
}
static inline uint32_t spd_stripe_line_old(uint32_t s){ return s >> 3; }
static inline uint32_t spd_stripe_line_new(uint32_t s){ return s; }
