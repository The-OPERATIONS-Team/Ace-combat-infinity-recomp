#pragma once
#include <stdint.h>
#include <stddef.h>

enum {
    MTRC_FIFO_DRAIN = 1,
    MTRC_FIFO_STALL,
    MTRC_FIFO_INTR,
    MTRC_FIFO_FLIP,
    MTRC_FS_OPEN,
    MTRC_FS_READ,
    MTRC_FS_SEEK,
    MTRC_SPU_INTERP,
};

typedef struct { uint32_t tid, htid, curfn; int32_t sc; uint32_t str_hle; } MtrcPpuRow;
typedef struct { uint32_t str, calls, us; } MtrcNameRow;
typedef struct { uint32_t num, calls, us; } MtrcScRow;

typedef struct {
    int  (*ppu)(MtrcPpuRow* out, int max, const char** hle_names);
    int  (*hle)(const char** name, uint32_t* calls, uint32_t* us, int max);
    int  (*sc )(MtrcScRow* out, int max);
    int  (*spu)(const char** name, uint32_t* calls, uint32_t* us, int max,
                uint32_t* wait_us, uint32_t* lock_us, uint32_t* resolve_us);
    void (*enable)(int on);
} MtrcProviders;
void mtrc_set_providers(const MtrcProviders* p);

int  spu_mtrace_drain(const char** name, uint32_t* calls, uint32_t* us, int max,
                      uint32_t* wait_us, uint32_t* lock_us, uint32_t* resolve_us);
void spu_mtrace_enable(int on);

extern int g_mtrc_on;

void mtrc_event(uint32_t cat, uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                const char* name);
#define MTRC(cat, a, b, c, d, nm) \
    do{ if(g_mtrc_on) mtrc_event((cat), (a), (b), (c), (d), (nm)); }while(0)

void mtrc_start(uint32_t t0);
void mtrc_stop(void);
const void* mtrc_frame(uint32_t* nbytes);

#define MTRC_MAGIC 0x3152544du
typedef struct {
    uint32_t magic, nppu, nhle, nsc, nspu, nev, nstr;
    uint32_t wait_us, lock_us, resolve_us;
    uint32_t dropped;
} MtrcHdr;
typedef struct {
    uint32_t cat, a, b, c, d, t_ms, tid, str;
} MtrcFileEv;
