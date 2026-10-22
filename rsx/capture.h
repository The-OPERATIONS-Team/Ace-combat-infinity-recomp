#pragma once
#include <stdint.h>

typedef struct { int valid; uint32_t offset, pitch, width, height; } RsxDispBufCap;

typedef struct {
    char     magic[8];
    uint32_t state_size;
    uint32_t local_ea, local_size;
    uint64_t mem_size;
    uint32_t blk_shift;
    uint32_t nblk;
    uint32_t niopg;
    uint32_t ndisp;
    uint32_t nrec;
    uint32_t pad;
} CapHdr;

#define CAP2_MAGIC   "RSXCAP2"
#define CAPFRAME_TAG 0x324d5246u
#define CAPF_LZ4     1u

typedef struct {
    char     magic[8];
    uint32_t hdr_size;
    uint32_t state_size;
    uint64_t mem_size;
    uint64_t frames_off;
    uint64_t total_bytes;
    uint64_t patch_bytes;
    uint32_t local_ea, local_size;
    uint32_t blk_shift;
    uint32_t nblk;
    uint32_t niopg;
    uint32_t ndisp;
    uint32_t page_shift;
    uint32_t nframes;
    uint32_t flags;
    uint32_t pad[43];
} CapHdr2;

typedef struct {
    uint32_t magic;
    uint32_t index;
    uint32_t raw;
    uint32_t comp;
    uint32_t nrec;
    uint32_t npatch;
    uint32_t nio;
    uint32_t patch_bytes;
    uint32_t t_ms;
    uint32_t flags;
    uint32_t mt_bytes;
    uint32_t pt_bytes;
} CapFrame;

extern int g_cap_recording;
extern int g_cap_disable;
extern int g_cap_writewatch;

void cap_init(uint8_t* base, uint64_t mem_size);

void cap_request(const char* path, int frames);

void cap_stop(const char* why);

void cap_method(uint32_t mth, uint32_t arg);
void cap_setdisp(uint32_t id, uint32_t off, uint32_t pitch, uint32_t w, uint32_t h);
void cap_flip(uint32_t bufid);
void cap_maybe_start(uint8_t* base, uint64_t mem_size, uint32_t local_ea,
                     uint32_t local_size, uint32_t (*ioff2ea)(uint32_t),
                     const RsxDispBufCap* disp8);
