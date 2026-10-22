#include "vp_decode.h"
#include <stdio.h>
#include <string.h>

static void unpack_src(uint32_t field, VpSrc* s, uint32_t abs_bit){
    s->reg_type=field&3;
    s->tmp_idx=(field>>2)&0x3f;
    s->swz[3]=(field>>8)&3;
    s->swz[2]=(field>>10)&3;
    s->swz[1]=(field>>12)&3;
    s->swz[0]=(field>>14)&3;
    s->neg=(field>>16)&1;
    s->abs=(uint8_t)abs_bit;
}

void vp_decode_instr(const uint32_t d[4], VpInstr* o){
    uint32_t d0=d[0],d1=d[1],d2=d[2],d3=d[3];
    memset(o,0,sizeof *o);
    o->vec_op=(d1>>22)&0x1f;
    o->sca_op=(d1>>27)&0x1f;
    o->input_idx=(d1>>8)&0xf;
    o->const_idx=(uint16_t)((d1>>12)&0x3ff);
    unpack_src(((d1&0xff)<<9)|(d2>>23), &o->src[0], (d0>>21)&1);
    unpack_src((d2>>6)&0x1ffff,         &o->src[1], (d0>>22)&1);
    unpack_src(((d2&0x3f)<<11)|(d3>>21),&o->src[2], (d0>>23)&1);
    o->end        = d3&1;
    o->index_const=(d3>>1)&1;
    o->out_reg    =(d3>>2)&0x1f;
    o->sca_dst_tmp=(d3>>7)&0x3f;
    o->vec_mask   =(d3>>13)&0xf;
    o->sca_mask   =(d3>>17)&0xf;
    o->addr_swz   = d0&3;
    o->cond_swz[0]=(d0>>8)&3; o->cond_swz[1]=(d0>>6)&3;
    o->cond_swz[2]=(d0>>4)&3; o->cond_swz[3]=(d0>>2)&3;
    o->cond       =(d0>>10)&7;
    o->cond_test  =(d0>>13)&1;
    o->cond_upd0  =(d0>>14)&1;
    o->dst_tmp    =(d0>>15)&0x3f;
    o->addr_reg1  =(d0>>24)&1;
    o->cond_reg1  =(d0>>25)&1;
    o->saturate   =(d0>>26)&1;
    o->index_input=(d0>>27)&1;
    o->cond_upd1  =(d0>>29)&1;
    o->vec_result =(d0>>30)&1;
    o->iaddr=((d2&0x3f)<<3)|((d3>>29)&7);
    o->tex_unit=(uint8_t)((d2>>8)&3);
}

static const char* VEC_NM[32]={"NOP","MOV","MUL","ADD","MAD","DP3","DPH","DP4",
    "DST","MIN","MAX","SLT","SGE","ARL","FRC","FLR","SEQ","SFL","SGT","SLE",
    "SNE","STR","SSG","ARR","ARA","TXL","?26","?27","?28","?29","?30","?31"};
static const char* SCA_NM[32]={"NOP","MOV","RCP","RCC","RSQ","EXP","LOG","LIT",
    "BRA","BRI","CAL","CLI","RET","LG2","EX2","SIN","COS","BRB","CLB","PSH",
    "POP","?21","?22","?23","?24","?25","?26","?27","?28","?29","?30","?31"};
static const char* COND_NM[8]={"FL","LT","EQ","LE","GT","NE","GE","TR"};

static void swz_str(const uint8_t swz[4], char* out){
    static const char C[4]={'x','y','z','w'};
    if(swz[0]==0&&swz[1]==1&&swz[2]==2&&swz[3]==3){ out[0]=0; return; }
    out[0]='.';
    for(int i=0;i<4;i++) out[1+i]=C[swz[i]];
    out[5]=0;
    if(swz[0]==swz[1]&&swz[1]==swz[2]&&swz[2]==swz[3]){ out[2]=0; }
}
static void mask_str(uint8_t mask, char* out){
    static const char C[4]={'x','y','z','w'};
    if(mask==0xf){ out[0]=0; return; }
    int n=0; out[n++]='.';
    for(int i=0;i<4;i++) if(mask&(8>>i)) out[n++]=C[i];
    out[n]=0;
}
static void src_str(const VpInstr* in, int i, char* out, int outlen){
    const VpSrc* s=&in->src[i];
    char sw[8]; swz_str(s->swz,sw);
    char body[64];
    switch(s->reg_type){
    case VP_SRC_TEMP:  snprintf(body,sizeof body,"R%u",s->tmp_idx); break;
    case VP_SRC_INPUT:
        if(in->index_input) snprintf(body,sizeof body,"v[A%d.%c+%u]",
            in->addr_reg1,"xyzw"[in->addr_swz],in->input_idx);
        else snprintf(body,sizeof body,"v[%u]",in->input_idx);
        break;
    case VP_SRC_CONST:
        if(in->index_const) snprintf(body,sizeof body,"c[A%d.%c+%u]",
            in->addr_reg1,"xyzw"[in->addr_swz],in->const_idx);
        else snprintf(body,sizeof body,"c[%u]",in->const_idx);
        break;
    default: snprintf(body,sizeof body,"?src%u",s->reg_type); break;
    }
    snprintf(out,outlen,"%s%s%s%s%s%s",
             s->neg?"-":"", s->abs?"|":"", body, s->abs?"|":"", sw, "");
}

static const uint8_t VEC_NSRC[32]={0,1,2,2,3,2,2,2,2,2,2,2,2,1,1,1,2,2,2,2,2,2,1,1,1,1};
static const uint8_t SCA_NSRC[32]={0,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,0,0};

static int sca_is_branch(uint8_t op){
    return op==8 ||op==9 ||op==10 ||op==11 ||
           op==17 ||op==18 ;
}
static int branch_text(const VpInstr* in, char* out, int outlen){
    char csw[8];
    uint8_t u[4]={in->cond_swz[0],in->cond_swz[1],in->cond_swz[2],in->cond_swz[3]};
    swz_str(u,csw);
    return snprintf(out,outlen,"%s(%s%s) @%u",SCA_NM[in->sca_op],
                    COND_NM[in->cond],csw[0]?csw:".xyzw",in->iaddr);
}

static void dst_text(const VpInstr* in, int is_sca, const char* m,
                     const char* cond, char* out, int outlen){
    uint8_t tmp   = is_sca ? in->sca_dst_tmp : in->dst_tmp;
    int     toout = is_sca ? !in->vec_result : (in->vec_result!=0);
    int     coiss = in->vec_op&&in->sca_op;
    char reg[32]="";
    if(tmp!=0x3f) snprintf(reg,sizeof reg,"R%u",tmp);
    else if(!toout||(is_sca&&coiss)) snprintf(reg,sizeof reg,"RC");
    if(toout&&in->out_reg<16){
        if(reg[0]) snprintf(out,outlen,"o[%u]%s %s%s%s",in->out_reg,m,reg,m,cond);
        else       snprintf(out,outlen,"o[%u]%s%s",in->out_reg,m,cond);
    } else snprintf(out,outlen,"%s%s%s",reg,m,cond);
}

void vp_disasm_instr(const VpInstr* in, char* buf, int buflen){
    char dst[64]="", m[8], cond[32]="", tail[160]="";
    int n=0; buf[0]=0;
    if(in->cond_test){
        char csw[8];
        uint8_t u[4]={in->cond_swz[0],in->cond_swz[1],in->cond_swz[2],in->cond_swz[3]};
        swz_str(u,csw);
        snprintf(cond,sizeof cond,"(%s%s)",COND_NM[in->cond],csw[0]?csw:".xyzw");
    }
    if(in->sca_op&&in->vec_op){
        if(sca_is_branch(in->sca_op)) n=branch_text(in,buf,buflen);
        else {
            mask_str(in->sca_mask,m);
            char sdst[80]; dst_text(in,1,m,cond,sdst,sizeof sdst);
            n=snprintf(buf,buflen,"%s%s %s",SCA_NM[in->sca_op],in->saturate?"_sat":"",sdst);
            if(SCA_NSRC[in->sca_op]){
                char s[96]; src_str(in,2,s,sizeof s);
                n+=snprintf(buf+n,buflen-n,", %s",s);
            }
        }
        n+=snprintf(buf+n,buflen-n," &\n");
    }
    if(in->vec_op){
        mask_str(in->vec_mask,m);
        if(in->vec_op==VPV_ARL) snprintf(dst,sizeof dst,"A%d%s",in->addr_reg1,m);
        else dst_text(in,0,m,cond,dst,sizeof dst);
        n+=snprintf(buf+n,buflen-n,"%s%s%s %s",VEC_NM[in->vec_op],
                   in->cond_upd0&&in->dst_tmp==0x3f&&!in->vec_result?"C":"",
                   in->saturate?"_sat":"",dst);
        int ns=VEC_NSRC[in->vec_op];
        int slots3[3]={0,1,2}, nsl=ns;
        if(in->vec_op==VPV_ADD){ slots3[1]=2; }
        for(int i=0;i<nsl;i++){
            char s[96]; src_str(in,slots3[i],s,sizeof s);
            n+=snprintf(buf+n,buflen-n,", %s",s);
        }
        if(in->vec_op==VPV_TXL) n+=snprintf(buf+n,buflen-n,", TEX%u",in->tex_unit);
        n+=snprintf(buf+n,buflen-n,";");
    }
    if(in->sca_op&&!in->vec_op){
        if(sca_is_branch(in->sca_op)){
            int k=branch_text(in,tail,sizeof tail);
            snprintf(tail+k,sizeof tail-k,";");
        }
        else {
        mask_str(in->sca_mask,m);
        char sdst[80]; dst_text(in,1,m,cond,sdst,sizeof sdst);
        int k=snprintf(tail,sizeof tail,"%s%s %s",SCA_NM[in->sca_op],
                       in->saturate?"_sat":"",sdst);
        if(SCA_NSRC[in->sca_op]){
            char s[96]; src_str(in,2,s,sizeof s);
            k+=snprintf(tail+k,sizeof tail-k,", %s",s);
        }
        snprintf(tail+k,sizeof tail-k,";");
        }
        if(in->vec_op) snprintf(buf+n,buflen-n," + %s",tail);
        else snprintf(buf,buflen,"%s",tail);
    }
    if(!in->vec_op&&!in->sca_op) snprintf(buf,buflen,"NOP;");
}
