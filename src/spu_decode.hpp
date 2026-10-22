#pragma once
#include <cstdint>

enum SpuFmt { RR, RRR, RI7, RI8, RI10, RI16, RI18, FMT_NONE };

struct SpuInsn {
    const char* mnem;
    SpuFmt fmt;
    uint8_t  rt, ra, rb, rc;
    int32_t  imm;
    uint32_t raw;
};

SpuInsn spu_decode(uint32_t insn);
