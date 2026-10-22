#pragma once
#include <stdint.h>

typedef struct {
    const uint32_t* words;
    uint32_t nwords;
    uint32_t ctrl;
    uint32_t remap[16];
    uint32_t alpha_func, alpha_ref;
    uint8_t shadow[16];
    uint8_t shadow_linear[16];
    uint8_t tex_type[16];
    uint32_t point_sprite;
} FpProgramSrc;
enum { FP_TEX_2D=0, FP_TEX_3D=1, FP_TEX_CUBE=2 };

typedef struct {
    uint32_t nopersp_attrs;
    uint32_t tex_used;
    uint32_t ninstr;
    int      kil;
    uint32_t nconst;
} FpMeta;

uint32_t fp_collect_consts(const uint32_t* words, uint32_t nwords,
                           float (*out)[4], uint32_t cap);

int fp_translate(const FpProgramSrc* p, uint32_t* out, int cap, FpMeta* meta);
