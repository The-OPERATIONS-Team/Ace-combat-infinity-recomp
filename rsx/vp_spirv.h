#pragma once
#include <stdint.h>

typedef struct {
    const uint32_t (*instr)[4];
    uint32_t start;
    uint32_t nconst;
} VpProgram;

int vp_translate(const VpProgram* p, uint32_t* out, int cap,
                 uint32_t* used_attrs, uint32_t* written_outs,
                 uint32_t* vtex_used);
