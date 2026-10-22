#include "spu_decode.hpp"

namespace {
struct Entry { uint32_t val; int nbits; SpuFmt fmt; const char* mnem; };
const Entry kTable[] = {
#include "../spu/spu_decode_table.inc"
};

struct Slot { const char* mnem; SpuFmt fmt; };
Slot g_disp[2048];
bool g_init = false;

void build() {
    for (auto& s : g_disp) { s.mnem = nullptr; s.fmt = FMT_NONE; }
    for (const auto& e : kTable) {
        int shift = 11 - e.nbits;
        uint32_t base = e.val << shift, span = 1u << shift;
        for (uint32_t i = 0; i < span; ++i) {
            Slot& s = g_disp[base + i];
            s.mnem = e.mnem; s.fmt = e.fmt;
        }
    }
    g_init = true;
}

inline int32_t sext(uint32_t v, int bits) {
    uint32_t m = 1u << (bits - 1);
    return (int32_t)((v ^ m) - m);
}
}

SpuInsn spu_decode(uint32_t insn) {
    if (!g_init) build();
    SpuInsn o{};
    o.raw = insn;
    const Slot& s = g_disp[(insn >> 21) & 0x7ff];
    o.mnem = s.mnem; o.fmt = s.fmt;
    if (((insn >> 21) & 0x7ff) == 0x1ac) o.mnem = (insn & 0x00100000) ? "hbrp" : "hbr";
    o.rt = insn & 0x7f;
    o.ra = (insn >> 7) & 0x7f;
    o.rb = (insn >> 14) & 0x7f;
    switch (s.fmt) {
        case RR:   break;
        case RRR:  o.rt = (insn >> 21) & 0x7f; o.rc = insn & 0x7f; break;
        case RI7:  o.imm = sext((insn >> 14) & 0x7f, 7); break;
        case RI8:  o.imm = (int32_t)((insn >> 14) & 0xff); break;
        case RI10: o.imm = sext((insn >> 14) & 0x3ff, 10); break;
        case RI16: o.imm = sext((insn >> 7) & 0xffff, 16); break;
        case RI18: o.imm = (int32_t)((insn >> 7) & 0x3ffff); break;
        default:   break;
    }
    return o;
}
