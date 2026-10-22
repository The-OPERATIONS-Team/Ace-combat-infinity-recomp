#pragma once
#include <stdint.h>

enum {
    FP_NOP=0x00, FP_MOV=0x01, FP_MUL=0x02, FP_ADD=0x03, FP_MAD=0x04,
    FP_DP3=0x05, FP_DP4=0x06, FP_DST=0x07, FP_MIN=0x08, FP_MAX=0x09,
    FP_SLT=0x0a, FP_SGE=0x0b, FP_SLE=0x0c, FP_SGT=0x0d, FP_SNE=0x0e,
    FP_SEQ=0x0f, FP_FRC=0x10, FP_FLR=0x11, FP_KIL=0x12, FP_PK4=0x13,
    FP_UP4=0x14, FP_DDX=0x15, FP_DDY=0x16, FP_TEX=0x17, FP_TXP=0x18,
    FP_TXD=0x19, FP_RCP=0x1a, FP_RSQ=0x1b, FP_EX2=0x1c, FP_LG2=0x1d,
    FP_LIT=0x1e, FP_LRP=0x1f, FP_STR=0x20, FP_SFL=0x21, FP_COS=0x22,
    FP_SIN=0x23, FP_PK2=0x24, FP_UP2=0x25, FP_POW=0x26, FP_PKB=0x27,
    FP_UPB=0x28, FP_PK16=0x29, FP_UP16=0x2a, FP_BEM=0x2b, FP_PKG=0x2c,
    FP_UPG=0x2d, FP_DP2A=0x2e, FP_TXL=0x2f, FP_TXB=0x31, FP_TEXBEM=0x33,
    FP_TXPBEM=0x34, FP_BEMLUM=0x35, FP_REFL=0x36, FP_TIMESWTEX=0x37,
    FP_DP2=0x38, FP_NRM=0x39, FP_DIV=0x3a, FP_DIVSQ=0x3b, FP_LIF=0x3c,
    FP_FENCT=0x3d, FP_FENCB=0x3e,
    FP_BRK=0x40, FP_CAL=0x41, FP_IFE=0x42, FP_LOOP=0x43, FP_REP=0x44,
    FP_RET=0x45
};
enum { FP_REG_TEMP=0, FP_REG_INPUT=1, FP_REG_CONST=2 };
enum { FP_PREC_FULL=0, FP_PREC_HALF=1, FP_PREC_FIXED12=2, FP_PREC_FIXED9=3 };

typedef struct {
    uint8_t reg_type;
    uint8_t tmp_idx, fp16;
    uint8_t swz[4];
    uint8_t neg, abs;
} FpSrc;

typedef struct {
    uint8_t  opcode;
    uint8_t  end, saturate, no_dest, set_cond;
    uint8_t  dest_idx, dest_fp16, dest_half_pair;
    uint8_t  mask;
    uint8_t  input_attr;
    uint8_t  nopersp;
    uint8_t  tex_unit;
    uint8_t  prec, scale;
    uint8_t  in_prec;
    uint8_t  exec_lt, exec_eq, exec_gt;
    uint8_t  cond_swz[4], cond_reg1, cond_mod_reg1;
    FpSrc    src[3];
    float    imm[4];
    uint8_t  has_imm;
    uint32_t else_off, end_off;
    uint8_t  loop_count, loop_init, loop_incr;
    uint32_t raw[4];
} FpInstr;

int fp_decode_instr(const uint32_t* w, FpInstr* out);

static inline uint32_t fp_word(const uint8_t* p){
    uint32_t be=(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
    return (be<<16)|(be>>16);
}

void fp_disasm_instr(const FpInstr* in, char* buf, int buflen);
