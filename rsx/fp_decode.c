#include "fp_decode.h"
#include <stdio.h>
#include <string.h>

static void unpack_src(uint32_t c, FpSrc* s){
    s->reg_type=c&3;
    s->tmp_idx=(c>>2)&0x3f;
    s->fp16=(c>>8)&1;
    s->swz[0]=(c>>9)&3; s->swz[1]=(c>>11)&3;
    s->swz[2]=(c>>13)&3; s->swz[3]=(c>>15)&3;
    s->neg=(c>>17)&1;
    s->abs=(c>>18)&1;
}

int fp_decode_instr(const uint32_t* w, FpInstr* o){
    uint32_t d0=w[0],d1=w[1],d2=w[2],d3=w[3];
    memset(o,0,sizeof *o);
    o->raw[0]=d0; o->raw[1]=d1; o->raw[2]=d2; o->raw[3]=d3;
    o->nopersp=(uint8_t)(d3>>31);
    o->end       = d0&1;
    o->dest_idx  =(d0>>1)&0x3f;
    o->dest_fp16 =(d0>>7)&1;
    o->set_cond  =(d0>>8)&1;
    o->mask      =(d0>>9)&0xf;
    o->input_attr=(d0>>13)&0xf;
    o->tex_unit  =(d0>>17)&0xf;
    o->prec      =(d0>>22)&3;
    o->opcode    =(uint8_t)(((d0>>24)&0x3f)|(((d2>>31)&1)<<6));
    o->no_dest   =(d0>>30)&1;
    o->saturate  =(d0>>31)&1;
    unpack_src(d1,&o->src[0]);
    unpack_src(d2,&o->src[1]);
    unpack_src(d3,&o->src[2]);
    o->src[0].abs=(d1>>29)&1;
    o->exec_lt=(d1>>18)&1; o->exec_eq=(d1>>19)&1; o->exec_gt=(d1>>20)&1;
    o->cond_swz[0]=(d1>>21)&3; o->cond_swz[1]=(d1>>23)&3;
    o->cond_swz[2]=(d1>>25)&3; o->cond_swz[3]=(d1>>27)&3;
    o->cond_mod_reg1=(d1>>30)&1;
    o->cond_reg1=(d1>>31)&1;
    o->scale=(d2>>28)&7;
    o->in_prec=(d2>>19)&7;
    if(o->opcode>=FP_BRK){
        o->else_off=(d2&0x7fffffff)*4;
        o->end_off =(d3&0x7fffffff)*4;
        if(o->opcode==FP_LOOP||o->opcode==FP_REP){
            o->loop_count=(uint8_t)((d2>>2)&0xff);
            o->loop_init =(uint8_t)((d2>>10)&0xff);
            o->loop_incr =(uint8_t)((d2>>19)&0xff);
            o->else_off=0;
        }
        o->nopersp=0;
        o->scale=0;
        o->in_prec=0;
        for(int i=0;i<3;i++) o->src[i].reg_type=FP_REG_TEMP;
        o->src[1].abs=o->src[2].abs=0;
        o->src[1].neg=o->src[2].neg=0;
        return 1;
    }
    int has_imm = (o->src[0].reg_type==FP_REG_CONST) ||
                  (o->src[1].reg_type==FP_REG_CONST) ||
                  (o->src[2].reg_type==FP_REG_CONST);
    if(has_imm){
        o->has_imm=1;
        for(int i=0;i<4;i++){ uint32_t c=w[4+i]; memcpy(&o->imm[i],&c,4); }
        return 2;
    }
    return 1;
}

static const char* OP_NM[0x46]={
 "NOP","MOV","MUL","ADD","MAD","DP3","DP4","DST","MIN","MAX","SLT","SGE",
 "SLE","SGT","SNE","SEQ","FRC","FLR","KIL","PK4","UP4","DDX","DDY","TEX",
 "TXP","TXD","RCP","RSQ","EX2","LG2","LIT","LRP","STR","SFL","COS","SIN",
 "PK2","UP2","POW","PKB","UPB","PK16","UP16","BEM","PKG","UPG","DP2A","TXL",
 "?30","TXB","?32","TEXBEM","TXPBEM","BEMLUM","REFL","TIMESWTEX","DP2","NRM",
 "DIV","DIVSQ","LIF","FENCT","FENCB","?3f","BRK","CAL","IFE","LOOP","REP","RET"};
static const char* ATTR_NM[16]={"WPOS","COL0","COL1","FOGC","TEX0","TEX1",
 "TEX2","TEX3","TEX4","TEX5","TEX6","TEX7","TEX8","TEX9","SSA","?15"};

static const uint8_t NSRC[0x46]={
 0,1,2,2,3,2,2,2,2,2,2,2,2,2,2,2,1,1,0,1,1,1,1,1,1,3,1,1,1,1,1,3,0,0,1,1,
 1,1,2,1,1,1,1,2,1,1,3,1,0,1,0,2,2,2,2,2,2,1,2,2,1,0,0,0,0,0,1,0,0,0};

static void swz_str(const uint8_t s[4], char* out){
    static const char C[4]={'x','y','z','w'};
    if(s[0]==0&&s[1]==1&&s[2]==2&&s[3]==3){ out[0]=0; return; }
    out[0]='.';
    for(int i=0;i<4;i++) out[1+i]=C[s[i]];
    out[5]=0;
    if(s[0]==s[1]&&s[1]==s[2]&&s[2]==s[3]) out[2]=0;
}
static void mask_str(uint8_t m, char* out){
    static const char C[4]={'x','y','z','w'};
    if(m==0xf){ out[0]=0; return; }
    int n=0; out[n++]='.';
    for(int i=0;i<4;i++) if(m&(1<<i)) out[n++]=C[i];
    out[n]=0;
}
static void src_str(const FpInstr* in, int i, char* out, int outlen){
    const FpSrc* s=&in->src[i];
    char sw[8]; swz_str(s->swz,sw);
    char body[128];
    switch(s->reg_type){
    case FP_REG_TEMP:
        snprintf(body,sizeof body,"%s%u",s->fp16?"H":"R",s->tmp_idx); break;
    case FP_REG_INPUT:
        snprintf(body,sizeof body,"%c[%s]",
                 (in->raw[3]>>31)?'g':'f',ATTR_NM[in->input_attr]); break;
    case FP_REG_CONST:
        snprintf(body,sizeof body,"{0x%08x(%g), 0x%08x(%g), 0x%08x(%g), 0x%08x(%g)}",
            *(const uint32_t*)&in->imm[0],in->imm[0],
            *(const uint32_t*)&in->imm[1],in->imm[1],
            *(const uint32_t*)&in->imm[2],in->imm[2],
            *(const uint32_t*)&in->imm[3],in->imm[3]);
        break;
    default: snprintf(body,sizeof body,"?src"); break;
    }
    static const char* IPM[8]={"","_h","_x","_b","_s","_n","",""};
    snprintf(out,outlen,"%s%s%s%s%s%s",s->neg?"-":"",s->abs?"|":"",body,
             s->abs?"|":"",IPM[in->in_prec],sw);
}

void fp_disasm_instr(const FpInstr* in, char* buf, int buflen){
    static const char PRE[4]={'R','H','X','B'};
    char m[8], cond[40]="";
    mask_str(in->mask,m);
    if(!(in->exec_lt&&in->exec_eq&&in->exec_gt)){
        const char* cc="??";
        uint8_t l=in->exec_lt,e=in->exec_eq,g=in->exec_gt;
        if(l&&e&&!g)cc="LE"; else if(l&&!e&&!g)cc="LT"; else if(!l&&e&&!g)cc="EQ";
        else if(!l&&!e&&g)cc="GT"; else if(!l&&e&&g)cc="GE"; else if(l&&!e&&g)cc="NE";
        else if(!l&&!e&&!g)cc="FL";
        char csw[8]; swz_str(in->cond_swz,csw);
        snprintf(cond,sizeof cond,"(%s%s)",cc,csw);
    }
    int n=snprintf(buf,buflen,"%s%c%s",OP_NM[in->opcode],PRE[in->prec],
                   in->set_cond?"C":"");
    { static const char* SC[8]={"","_m2","_m4","_m8","","_d2","_d4","_d8"};
      if(SC[in->scale][0]) n+=snprintf(buf+n,buflen-n,"%s",SC[in->scale]); }
    if(in->saturate) n+=snprintf(buf+n,buflen-n,"_sat");
    if(in->opcode==FP_LOOP||in->opcode==FP_REP){
        snprintf(buf+n,buflen-n," { %u, %u, %u };",
                 in->loop_count,in->loop_init,in->loop_incr); return; }
    if(in->opcode>=FP_BRK){
        snprintf(buf+n,buflen-n,"%s%s;",cond[0]?" ":"",cond); return; }
    if(in->opcode==FP_KIL){ snprintf(buf+n,buflen-n," %s;",cond); return; }
    if(in->opcode==FP_FENCT||in->opcode==FP_FENCB){ snprintf(buf+n,buflen-n," ;"); return; }
    char dst[64];
    if(!in->mask) dst[0]=0;
    else if(in->no_dest) snprintf(dst,sizeof dst,"RC%s",m[0]?m:".x");
    else snprintf(dst,sizeof dst,"%s%u%s",in->dest_fp16?"H":"R",in->dest_idx,m);
    n+=snprintf(buf+n,buflen-n," %s%s",dst,cond);
    int nsrc=NSRC[in->opcode];
    if(in->opcode==FP_TXB) nsrc=3;
    for(int i=0;i<nsrc;i++){
        char s[192]; src_str(in,i,s,sizeof s);
        n+=snprintf(buf+n,buflen-n,", %s",s);
    }
    if(in->opcode==FP_TEX||in->opcode==FP_TXP||in->opcode==FP_TXD||
       in->opcode==FP_TXL||in->opcode==FP_TXB)
        n+=snprintf(buf+n,buflen-n,", TEX%u",in->tex_unit);
    snprintf(buf+n,buflen-n,";");
}
