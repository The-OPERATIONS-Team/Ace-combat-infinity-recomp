#pragma once
#include <stdint.h>

enum {
    VPV_NOP=0, VPV_MOV=1, VPV_MUL=2, VPV_ADD=3, VPV_MAD=4, VPV_DP3=5,
    VPV_DPH=6, VPV_DP4=7, VPV_DST=8, VPV_MIN=9, VPV_MAX=10, VPV_SLT=11,
    VPV_SGE=12, VPV_ARL=13, VPV_FRC=14, VPV_FLR=15, VPV_SEQ=16, VPV_SFL=17,
    VPV_SGT=18, VPV_SLE=19, VPV_SNE=20, VPV_STR=21, VPV_SSG=22, VPV_ARR=23,
    VPV_ARA=24, VPV_TXL=25
};
enum {
    VPS_NOP=0, VPS_MOV=1, VPS_RCP=2, VPS_RCC=3, VPS_RSQ=4, VPS_EXP=5,
    VPS_LOG=6, VPS_LIT=7, VPS_BRA=8, VPS_BRI=9, VPS_CAL=10, VPS_CLI=11,
    VPS_RET=12, VPS_LG2=13, VPS_EX2=14, VPS_SIN=15, VPS_COS=16, VPS_BRB=17,
    VPS_CLB=18, VPS_PSH=19, VPS_POP=20
};
enum { VP_SRC_TEMP=1, VP_SRC_INPUT=2, VP_SRC_CONST=3 };

typedef struct {
    uint8_t reg_type;
    uint8_t tmp_idx;
    uint8_t swz[4];
    uint8_t neg, abs;
} VpSrc;

typedef struct {
    uint8_t  vec_op, sca_op;
    VpSrc    src[3];
    uint8_t  input_idx;
    uint16_t const_idx;
    uint8_t  vec_mask, sca_mask;
    uint8_t  dst_tmp;
    uint8_t  sca_dst_tmp;
    uint8_t  out_reg;
    uint8_t  vec_result;
    uint8_t  index_const;
    uint8_t  index_input;
    uint8_t  saturate;
    uint8_t  cond_test, cond, cond_swz[4], cond_reg1, cond_upd0, cond_upd1;
    uint8_t  addr_reg1, addr_swz;
    uint8_t  end;
    uint32_t iaddr;
    uint8_t  tex_unit;
} VpInstr;

void vp_decode_instr(const uint32_t d[4], VpInstr* out);

void vp_disasm_instr(const VpInstr* in, char* buf, int buflen);
