#include "fp_spirv.h"
#include "fp_decode.h"
#include "spv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    SpvMod m;
    uint32_t p_fn_v4;
    uint32_t v_r[64];
    uint32_t v_h[64];
    uint32_t v_scratch;
    uint64_t use_r, use_h;
    int wrote_r0, wrote_h0;
    uint32_t v_cc[2];
    uint32_t in_var[16];
    uint32_t nopersp_attrs;
    uint32_t v_fragcoord, v_frontfacing;
    uint32_t v_pointcoord;
    uint32_t point_sprite;
    uint32_t v_out;
    uint32_t img_var[16], t_img[3], t_simg[3];
    uint8_t  tex_type[16];
    uint32_t p_uc_simg[3];
    uint32_t zero4, one4;
    uint32_t tex_used;
    uint32_t remap[16];
    uint8_t  shadow[16];
    uint8_t  shadow_lin[16];
    uint32_t t_v2i;
    uint32_t fpc_var, fpc_pv4;
    int      cur_imm;
    uint32_t entry;
    int      kil;
    struct { uint32_t cond; uint32_t else_off, end_off; int in_else; } fr[8];
    int      nfr;
    uint32_t v_exec;
    uint32_t c_true, c_false;
    uint32_t v_brk, v_iter;
    uint32_t lp_end, lp_head, lp_cont, lp_merge, lp_count;
    int      in_loop;
    uint32_t v_kilvis;
    uint32_t last_shadow, last_uv, last_ref, last_d;
    int      pt_live;
    uint32_t pt_var, pt_pv4, pt_act, pt_base;
} FpCtx;

static uint32_t const_true(FpCtx* c){
    if(!c->c_true){ c->c_true=spvm_id(&c->m);
        uint32_t a[]={c->m.t_bool,c->c_true}; spvm_g(&c->m,SpvOpConstantTrue,a,2); }
    return c->c_true;
}
static uint32_t const_false(FpCtx* c){
    if(!c->c_false){ c->c_false=spvm_id(&c->m);
        uint32_t a[]={c->m.t_bool,c->c_false}; spvm_g(&c->m,SpvOpConstantFalse,a,2); }
    return c->c_false;
}
static uint32_t blk_pred(FpCtx* c){
    SpvMod* m=&c->m;
    uint32_t p=0;
    for(int i=0;i<c->nfr;i++){
        uint32_t t=c->fr[i].cond;
        if(c->fr[i].in_else) t=spvb_un(m,SpvOpLogicalNot,m->t_bool,t);
        p=p?spvb_bin(m,SpvOpLogicalAnd,m->t_bool,p,t):t;
    }
    if(c->v_exec){
        uint32_t e=spvb_load(m,m->t_bool,c->v_exec);
        p=p?spvb_bin(m,SpvOpLogicalAnd,m->t_bool,p,e):e;
    }
    if(c->in_loop&&c->v_brk){
        uint32_t nb=spvb_un(m,SpvOpLogicalNot,m->t_bool,
                            spvb_load(m,m->t_bool,c->v_brk));
        p=p?spvb_bin(m,SpvOpLogicalAnd,m->t_bool,p,nb):nb;
    }
    return p;
}
static void loop_close(FpCtx* c){
    SpvMod* m=&c->m;
    { uint32_t a[]={c->lp_cont}; spvm_b(m,SpvOpBranch,a,1); }
    { uint32_t a[]={c->lp_cont}; spvm_b(m,SpvOpLabel,a,1); }
    uint32_t it=spvb_bin(m,SpvOpIAdd,m->t_i32,
                         spvb_load(m,m->t_i32,c->v_iter),spvm_ci(m,1));
    spvb_store(m,c->v_iter,it);
    uint32_t again=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,
        spvb_un(m,SpvOpLogicalNot,m->t_bool,spvb_load(m,m->t_bool,c->v_brk)),
        spvb_bin(m,SpvOpSLessThan,m->t_bool,it,spvm_ci(m,(int32_t)c->lp_count)));
    { uint32_t a[]={again,c->lp_head,c->lp_merge};
      spvm_b(m,SpvOpBranchConditional,a,3); }
    { uint32_t a[]={c->lp_merge}; spvm_b(m,SpvOpLabel,a,1); }
    c->in_loop=0;
}
static uint32_t reg_var(FpCtx* c, int fp16, uint32_t idx){
    uint32_t v = fp16 ? c->v_h[idx&63] : c->v_r[idx&63];
    return v ? v : c->v_scratch;
}
static uint32_t bsplat4(FpCtx* c, uint32_t b){
    SpvMod* m=&c->m; uint32_t id=spvm_id(m);
    uint32_t a[]={m->t_bv4,id,b,b,b,b}; spvm_b(m,SpvOpCompositeConstruct,a,6);
    return id;
}

static int g_no_scale=-1, g_no_cond=-1, g_no_sat=-1, g_no_shadow=-1, g_no_clamp=-1,
           g_no_fp16=0, g_killvis=0, g_nan_keep=0, g_no_flrnudge=0;
static void dbg_env(void){
    if(g_no_scale>=0) return;
    { const char* kv=getenv("PS3_RSX_KILLVIS");
      g_killvis=kv?atoi(kv):0; if(kv&&!g_killvis) g_killvis=1; }
    g_no_fp16 =getenv("PS3_FP_NOFP16")?1:0;
    g_no_scale=getenv("PS3_FP_NOSCALE")?1:0;
    g_no_cond =getenv("PS3_FP_NOCOND")?1:0;
    g_no_sat  =getenv("PS3_FP_NOSAT")?1:0;
    g_no_shadow=getenv("PS3_RSX_NOSHADOW")?1:0;
    g_no_clamp=getenv("PS3_FP_NOCLAMP")?1:0;
    g_nan_keep=getenv("PS3_FP_NANKEEP")?1:0;
    g_no_flrnudge=getenv("PS3_FP_NOFLRNUDGE")?1:0;
}

static uint32_t attr_load(FpCtx* c, uint32_t attr, int np){
    SpvMod* m=&c->m;
    if(attr==0){
        return spvb_load(m,m->t_vf[4],c->v_fragcoord);
    }
    if(attr==14&&c->v_frontfacing){
        uint32_t ff=spvb_load(m,m->t_bool,c->v_frontfacing);
        uint32_t s=spvm_id(m);
        { uint32_t ar[]={m->t_f32,s,ff,spvm_cf(m,1.0f),spvm_cf(m,-1.0f)};
          spvm_b(m,SpvOpSelect,ar,5); }
        return spvb_splat4(m,s);
    }
    if((c->point_sprite&1)&&attr>=4&&attr<=13&&
       (c->point_sprite&(1u<<(8+(attr-4))))&&c->v_pointcoord){
        uint32_t pc=spvb_load(m,m->t_vf[2],c->v_pointcoord);
        uint32_t s2=spvb_extract(m,m->t_f32,pc,0);
        uint32_t t2=spvb_extract(m,m->t_f32,pc,1);
        uint32_t rmode=(c->point_sprite>>1)&3;
        uint32_t r2 = rmode==2 ? s2 : (rmode==1 ? t2 : spvm_cf(m,0.0f));
        return spvb_construct4(m,s2,t2,r2,spvm_cf(m,1.0f));
    }
    if(attr<16&&c->in_var[attr]){
        uint32_t v=spvb_load(m,m->t_vf[4],c->in_var[attr]);
        if(np){
            uint32_t fc=spvb_load(m,m->t_vf[4],c->v_fragcoord);
            uint32_t rw=spvb_splat4(m,spvb_extract(m,m->t_f32,fc,3));
            v=spvb_bin(m,SpvOpFMul,m->t_vf[4],v,rw);
        }
        return v;
    }
    return c->zero4;
}

enum { CLAMP_NONE=0, CLAMP_FP16, CLAMP_FX12, CLAMP_FX9, CLAMP_UB08 };
static uint32_t clamp_prec(FpCtx* c, uint32_t v, int mode){
    dbg_env();
    if(mode==CLAMP_NONE||g_no_clamp) return v;
    SpvMod* m=&c->m;
    float lo,hi;
    switch(mode){
    case CLAMP_FP16: lo=-65504.0f; hi=65504.0f; break;
    case CLAMP_FX12: lo=-2.0f;     hi=2.0f;     break;
    case CLAMP_FX9:  lo=-1.0f;     hi=1.0f;     break;
    default:         lo=0.0f;      hi=1.0f;     break;
    }
    return spvb_ext3(m,m->t_vf[4],GlslFClamp,v,
                     spvm_cf4(m,lo,lo,lo,lo),spvm_cf4(m,hi,hi,hi,hi));
}
static int prec_clamp_mode(uint8_t prec){
    static const uint8_t T[4]={CLAMP_NONE,CLAMP_FP16,CLAMP_FX12,CLAMP_FX9};
    return T[prec&3];
}
static int in_clamp_mode(const FpInstr* in){
    switch(in->in_prec){
    case 0: return prec_clamp_mode(in->prec);
    case 1: return CLAMP_FP16;
    case 2: return CLAMP_FX12;
    case 3: return CLAMP_FX9;
    case 4: return CLAMP_UB08;
    case 5: return CLAMP_NONE;
    default:{ static int wn; if(wn++<4)
        fprintf(stderr,"[FP] unknown input clamp modifier %u - no clamp\n",in->in_prec);
        return CLAMP_NONE; }
    }
}

static uint32_t load_src(FpCtx* c, const FpInstr* in, int slot){
    SpvMod* m=&c->m;
    const FpSrc* s=&in->src[slot];
    uint32_t v;
    switch(s->reg_type){
    case FP_REG_TEMP:{
        v=spvb_load(m,m->t_vf[4],reg_var(c,s->fp16,s->tmp_idx));
        break; }
    case FP_REG_INPUT:
        v=attr_load(c,in->input_attr&15,in->nopersp);
        break;
    case FP_REG_CONST:
        if(c->fpc_var&&c->cur_imm>=0){
            uint32_t ptr=spvm_id(m);
            uint32_t a[]={c->fpc_pv4,ptr,c->fpc_var,spvm_ci(m,0),
                          spvm_ci(m,c->cur_imm)};
            spvm_b(m,SpvOpAccessChain,a,5);
            v=spvb_load(m,m->t_vf[4],ptr);
        } else v=spvm_cf4(m,in->imm[0],in->imm[1],in->imm[2],in->imm[3]);
        break;
    default: v=c->zero4; break;
    }
    v=spvb_shuffle4(m,v,s->swz);
    if(s->abs) v=spvb_ext1(m,m->t_vf[4],GlslFAbs,v);
    if(s->neg) v=spvb_un(m,SpvOpFNegate,m->t_vf[4],v);
    return clamp_prec(c,v,in_clamp_mode(in));
}

static struct { int n, file[3], idx[3], comp[3], at[3]; } g_visreg={-1};
static uint32_t g_visfp=0, g_cur_fphash=0;
static void visreg_parse(void){
    if(g_visreg.n>=0) return;
    g_visreg.n=0;
    const char* e=getenv("PS3_RSX_VISREG");
    while(e&&*e&&g_visreg.n<3){
        int k=g_visreg.n, h=0;
        if(*e=='h'||*e=='H'){ h=1; e++; } else if(*e=='r'||*e=='R') e++;
        int idx=0; while(*e>='0'&&*e<='9'){ idx=idx*10+(*e-'0'); e++; }
        int comp=0;
        if(*e=='x') comp=0; else if(*e=='y') comp=1;
        else if(*e=='z') comp=2; else if(*e=='w') comp=3;
        if(*e&&*e!='@'&&*e!=',') e++;
        int at=-1;
        if(*e=='@'){ e++; at=0; while(*e>='0'&&*e<='9'){ at=at*10+(*e-'0'); e++; } }
        g_visreg.file[k]=h; g_visreg.idx[k]=idx&47; g_visreg.comp[k]=comp;
        g_visreg.at[k]=at; g_visreg.n++;
        while(*e==','||*e==' ') e++;
    }
}
static uint32_t g_visreg_cap[3];
static uint32_t visreg_read(FpCtx* c, int k){
    SpvMod* m=&c->m;
    uint32_t rv=spvb_load(m,m->t_vf[4],
                          reg_var(c,g_visreg.file[k],(uint32_t)g_visreg.idx[k]));
    return spvb_extract(m,m->t_f32,rv,(uint32_t)g_visreg.comp[k]);
}
static void visreg_capture(FpCtx* c, int instr){
    visreg_parse();
    for(int k=0;k<g_visreg.n;k++)
        if(g_visreg.at[k]==instr) g_visreg_cap[k]=visreg_read(c,k);
}

#define PT_SLOT  544
#define PT_CC    273
#define PT_JUNK  (4*PT_SLOT)
#define PT_TOTAL (PT_JUNK+16)
static int g_pt_on=-2; static float g_pt_x, g_pt_y;
static void pt_parse(void){
    if(g_pt_on!=-2) return;
    g_pt_on=0;
    const char* e=getenv("PS3_RSX_PIXTRACE");
    if(e&&sscanf(e,"%f,%f",&g_pt_x,&g_pt_y)==2) g_pt_on=1;
}
static uint32_t pt_ptr(FpCtx* c, int rel){
    SpvMod* m=&c->m;
    uint32_t tgt=spvb_bin(m,SpvOpIAdd,m->t_i32,c->pt_base,spvm_ci(m,rel));
    uint32_t idx=spvm_id(m);
    { uint32_t a[]={m->t_i32,idx,c->pt_act,tgt,spvm_ci(m,PT_JUNK)};
      spvm_b(m,SpvOpSelect,a,5); }
    uint32_t ptr=spvm_id(m);
    { uint32_t a[]={c->pt_pv4,ptr,c->pt_var,spvm_ci(m,0),idx};
      spvm_b(m,SpvOpAccessChain,a,5); }
    return ptr;
}
static void pt_store(FpCtx* c, int rel, uint32_t val){
    if(!c->pt_live) return;
    spvb_store(&c->m,pt_ptr(c,rel),val);
}

static uint32_t mask_merge(FpCtx* c, uint32_t oldv, uint32_t newv, uint8_t mask){
    if((mask&0xf)==0xf) return newv;
    SpvMod* m=&c->m;
    uint32_t id=spvm_id(m);
    uint32_t a[8]={m->t_vf[4],id,oldv,newv,
        (mask&1)?4u:0u,(mask&2)?5u:1u,(mask&4)?6u:2u,(mask&8)?7u:3u};
    spvm_b(m,SpvOpVectorShuffle,a,8);
    return id;
}

static uint32_t cc_load(FpCtx* c, int reg1){
    SpvMod* m=&c->m;
    uint32_t cc=spvb_load(m,m->t_vf[4],c->v_cc[reg1]);
    if(!reg1) return cc;
    return spvb_construct4(m,spvb_extract(m,m->t_f32,cc,0),
                           spvm_cf(m,0.0f),spvm_cf(m,0.0f),spvm_cf(m,0.0f));
}

static uint32_t cond_gate(FpCtx* c, const FpInstr* in){
    dbg_env();
    if(g_no_cond) return 0;
    if(in->exec_lt&&in->exec_eq&&in->exec_gt) return 0;
    SpvMod* m=&c->m;
    uint32_t cc=cc_load(c,in->cond_reg1);
    uint8_t sw[4]={in->cond_swz[0],in->cond_swz[1],in->cond_swz[2],in->cond_swz[3]};
    cc=spvb_shuffle4(m,cc,sw);
    uint32_t acc=0;
    if(in->exec_lt){ acc=spvb_bin(m,SpvOpFOrdLessThan,m->t_bv4,cc,c->zero4); }
    if(in->exec_eq){ uint32_t e=spvb_bin(m,SpvOpFOrdEqual,m->t_bv4,cc,c->zero4);
        acc=acc?spvb_bin(m,166 ,m->t_bv4,acc,e):e; }
    if(in->exec_gt){ uint32_t g=spvb_bin(m,SpvOpFOrdGreaterThan,m->t_bv4,cc,c->zero4);
        acc=acc?spvb_bin(m,166,m->t_bv4,acc,g):g; }
    if(!acc){
        acc=spvb_bin(m,SpvOpFUnordNotEqual,m->t_bv4,c->zero4,c->zero4);
    }
    return acc;
}

static void write_dst(FpCtx* c, const FpInstr* in, uint32_t val){
    SpvMod* m=&c->m;
    dbg_env();
    static const float SCALE[8]={1,2,4,8,1,0.5f,0.25f,0.125f};
    if(!g_no_scale&&in->scale&&SCALE[in->scale]!=1.0f)
        val=spvb_bin(m,SpvOpFMul,m->t_vf[4],val,
            spvm_cf4(m,SCALE[in->scale],SCALE[in->scale],SCALE[in->scale],SCALE[in->scale]));
    if(!g_nan_keep){
        uint32_t nan=spvb_un(m,SpvOpIsNan,m->t_bv4,val);
        uint32_t fl=spvm_id(m);
        { uint32_t ar[]={m->t_vf[4],fl,nan,c->zero4,val};
          spvm_b(m,SpvOpSelect,ar,5); }
        val=fl;
    }
    if(in->saturate&&!g_no_sat)
        val=spvb_ext3(m,m->t_vf[4],GlslFClamp,val,c->zero4,c->one4);
    else
        val=clamp_prec(c,val,prec_clamp_mode(in->prec));
    uint32_t gate=cond_gate(c,in);
    { uint32_t bp=blk_pred(c);
      if(bp){ uint32_t b4=bsplat4(c,bp);
              gate=gate?spvb_bin(m,SpvOpLogicalAnd,m->t_bv4,gate,b4):b4; } }
    if(in->set_cond){
        uint32_t oldc=spvb_load(m,m->t_vf[4],c->v_cc[in->cond_mod_reg1]);
        uint32_t nv=val;
        if(gate) nv=spvb_select4(m,gate,val,oldc);
        uint8_t cmask=in->cond_mod_reg1? (uint8_t)(in->mask&1) : in->mask;
        spvb_store(m,c->v_cc[in->cond_mod_reg1],mask_merge(c,oldc,nv,cmask));
    }
    if(in->no_dest) return;
    uint32_t didx=in->dest_idx&63;
    uint32_t var=reg_var(c,in->dest_fp16,didx);
    if(didx==0){ if(in->dest_fp16) c->wrote_h0=1; else c->wrote_r0=1; }
    if(in->dest_fp16&&!g_no_fp16) val=spvb_un(m,SpvOpQuantizeToF16,m->t_vf[4],val);
    uint32_t oldv=spvb_load(m,m->t_vf[4],var);
    if(gate) val=spvb_select4(m,gate,val,oldv);
    spvb_store(m,var,mask_merge(c,oldv,val,in->mask));
}

static uint32_t dot_h(SpvMod* m, uint32_t a, uint32_t b, int nc){
    if(nc==4){ uint32_t d=spvm_id(m);
        uint32_t ar[]={m->t_f32,d,a,b}; spvm_b(m,SpvOpDot,ar,4); return d; }
    uint32_t an=spvm_id(m),bn=spvm_id(m);
    { uint32_t ar[7]={m->t_vf[nc],an,a,a,0,1,2}; spvm_b(m,SpvOpVectorShuffle,ar,4+nc); }
    { uint32_t ar[7]={m->t_vf[nc],bn,b,b,0,1,2}; spvm_b(m,SpvOpVectorShuffle,ar,4+nc); }
    uint32_t d=spvm_id(m);
    { uint32_t ar[]={m->t_f32,d,an,bn}; spvm_b(m,SpvOpDot,ar,4); }
    return d;
}
static uint32_t splat(FpCtx* c, uint32_t f){ return spvb_splat4(&c->m,f); }
static uint32_t cmp_set(FpCtx* c, uint16_t op, uint32_t a, uint32_t b){
    SpvMod* m=&c->m;
    return spvb_select4(m,spvb_bin(m,op,m->t_bv4,a,b),c->one4,c->zero4);
}

static uint32_t apply_remap(FpCtx* c, uint32_t s, uint32_t rw){
    rw&=0xffff;
    if(rw==0||rw==0xAAE4) return s;
    SpvMod* m=&c->m;
    static const int IN2COMP[4]={3,0,1,2};
    uint32_t comp[4];
    const int in_off[4]={2,4,6,0};
    const int md_off[4]={10,12,14,8};
    for(int k=0;k<4;k++){
        uint32_t mode=(rw>>md_off[k])&3;
        if(mode==0) comp[k]=spvm_cf(m,0.0f);
        else if(mode==1) comp[k]=spvm_cf(m,1.0f);
        else {
            uint32_t insel=(rw>>in_off[k])&3;
            comp[k]=spvb_extract(m,m->t_f32,s,(uint32_t)IN2COMP[insel]);
        }
    }
    uint32_t id=spvm_id(m);
    uint32_t a[]={m->t_vf[4],id,comp[0],comp[1],comp[2],comp[3]};
    spvm_b(m,SpvOpCompositeConstruct,a,6);
    return id;
}

static uint32_t v2i_type(FpCtx* c){
    if(!c->t_v2i){ SpvMod* m=&c->m; c->t_v2i=spvm_id(m);
        uint32_t a[]={c->t_v2i,m->t_i32,2}; spvm_g(m,SpvOpTypeVector,a,3); }
    return c->t_v2i;
}
static uint32_t v2(FpCtx* c, uint32_t x, uint32_t y){
    SpvMod* m=&c->m; uint32_t id=spvm_id(m);
    uint32_t a[]={m->t_vf[2],id,x,y}; spvm_b(m,SpvOpCompositeConstruct,a,4);
    return id;
}
static uint32_t tex_lod(FpCtx* c, uint32_t img, uint32_t uv, uint32_t lod){
    SpvMod* m=&c->m; uint32_t id=spvm_id(m);
    uint32_t a[]={m->t_vf[4],id,img,uv,2 ,lod};
    spvm_b(m,SpvOpImageSampleExplicitLod,a,6);
    return id;
}
static uint32_t shadow_cmp_d(FpCtx* c, uint32_t d, uint32_t ref, uint16_t op){
    SpvMod* m=&c->m;
    c->last_d=d;
    { static int sbi=0; static float sb=0;
      if(!sbi){ sbi=1; const char* e=getenv("PS3_FP_SHADOWBIAS");
                if(e) sb=(float)atof(e); }
      if(sb!=0.0f) ref=spvb_bin(m,SpvOpFSub,m->t_f32,ref,spvm_cf(m,sb)); }
    uint32_t pass=spvb_bin(m,op,m->t_bool,d,ref);
    uint32_t sel=spvm_id(m);
    uint32_t a[]={m->t_f32,sel,pass,spvm_cf(m,1.0f),spvm_cf(m,0.0f)};
    spvm_b(m,SpvOpSelect,a,5);
    return sel;
}
static uint32_t shadow_cmp(FpCtx* c, uint32_t tap, uint32_t ref, uint16_t op){
    SpvMod* m=&c->m;
    uint32_t sr=spvb_extract(m,m->t_f32,tap,0);
    uint32_t sg=spvb_extract(m,m->t_f32,tap,1);
    uint32_t sa=spvb_extract(m,m->t_f32,tap,3);
    uint32_t d=spvb_bin(m,SpvOpFAdd,m->t_f32,
        spvb_bin(m,SpvOpFAdd,m->t_f32,
            spvb_bin(m,SpvOpFMul,m->t_f32,sa,spvm_cf(m,65536.0f)),
            spvb_bin(m,SpvOpFMul,m->t_f32,sr,spvm_cf(m,256.0f))),sg);
    d=spvb_bin(m,SpvOpFMul,m->t_f32,d,spvm_cf(m,1.0f/65793.0f));
    return shadow_cmp_d(c,d,ref,op);
}
static uint32_t shadow_pcf(FpCtx* c, uint32_t img, uint32_t uv, uint32_t ref,
                           uint16_t op, uint32_t lod){
    SpvMod* m=&c->m;
    spvm_cap(m,SpvCapImageQuery);
    uint32_t im=spvm_id(m);
    { uint32_t a[]={c->t_img[FP_TEX_2D],im,img}; spvm_b(m,SpvOpImage,a,3); }
    uint32_t szi=spvm_id(m);
    { uint32_t a[]={v2i_type(c),szi,im,spvm_ci(m,0)};
      spvm_b(m,SpvOpImageQuerySizeLod,a,4); }
    uint32_t sz=spvb_un(m,SpvOpConvertSToF,m->t_vf[2],szi);
    uint32_t half=v2(c,spvm_cf(m,0.5f),spvm_cf(m,0.5f));
    uint32_t one =v2(c,spvm_cf(m,1.0f),spvm_cf(m,1.0f));
    uint32_t t =spvb_bin(m,SpvOpFSub,m->t_vf[2],
                         spvb_bin(m,SpvOpFMul,m->t_vf[2],uv,sz),half);
    uint32_t f =spvb_ext1(m,m->t_vf[2],GlslFract,t);
    uint32_t fl=spvb_ext1(m,m->t_vf[2],GlslFloor,t);
    uint32_t texel=spvb_bin(m,SpvOpFDiv,m->t_vf[2],one,sz);
    uint32_t base =spvb_bin(m,SpvOpFMul,m->t_vf[2],
                            spvb_bin(m,SpvOpFAdd,m->t_vf[2],fl,half),texel);
    uint32_t dx=v2(c,spvb_extract(m,m->t_f32,texel,0),spvm_cf(m,0.0f));
    uint32_t dy=v2(c,spvm_cf(m,0.0f),spvb_extract(m,m->t_f32,texel,1));
    uint32_t s00=shadow_cmp(c,tex_lod(c,img,base,lod),ref,op);
    uint32_t s10=shadow_cmp(c,tex_lod(c,img,
                     spvb_bin(m,SpvOpFAdd,m->t_vf[2],base,dx),lod),ref,op);
    uint32_t s01=shadow_cmp(c,tex_lod(c,img,
                     spvb_bin(m,SpvOpFAdd,m->t_vf[2],base,dy),lod),ref,op);
    uint32_t s11=shadow_cmp(c,tex_lod(c,img,
                     spvb_bin(m,SpvOpFAdd,m->t_vf[2],base,texel),lod),ref,op);
    uint32_t fx=spvb_extract(m,m->t_f32,f,0);
    uint32_t fy=spvb_extract(m,m->t_f32,f,1);
    uint32_t a0=spvb_ext3(m,m->t_f32,GlslFMix,s00,s10,fx);
    uint32_t a1=spvb_ext3(m,m->t_f32,GlslFMix,s01,s11,fx);
    return spvb_ext3(m,m->t_f32,GlslFMix,a0,a1,fy);
}

static uint32_t srgb_curve(FpCtx* c, uint32_t v, int to_srgb){
    SpvMod* m=&c->m;
    uint32_t comp[4];
    for(int k=0;k<4;k++){
        uint32_t x=spvb_extract(m,m->t_f32,v,(uint32_t)k);
        if(k==3){ comp[k]=x; continue; }
        uint32_t lo,hi,cut,sel;
        if(to_srgb){
            lo=spvb_bin(m,SpvOpFMul,m->t_f32,x,spvm_cf(m,12.92f));
            hi=spvb_bin(m,SpvOpFSub,m->t_f32,
                 spvb_bin(m,SpvOpFMul,m->t_f32,spvm_cf(m,1.055f),
                   spvb_ext2(m,m->t_f32,GlslPow,x,spvm_cf(m,1.0f/2.4f))),
                 spvm_cf(m,0.055f));
            cut=spvb_bin(m,SpvOpFOrdLessThanEqual,m->t_bool,x,spvm_cf(m,0.0031308f));
        } else {
            lo=spvb_bin(m,SpvOpFDiv,m->t_f32,x,spvm_cf(m,12.92f));
            hi=spvb_ext2(m,m->t_f32,GlslPow,
                 spvb_bin(m,SpvOpFDiv,m->t_f32,
                   spvb_bin(m,SpvOpFAdd,m->t_f32,x,spvm_cf(m,0.055f)),
                   spvm_cf(m,1.055f)), spvm_cf(m,2.4f));
            cut=spvb_bin(m,SpvOpFOrdLessThanEqual,m->t_bool,x,spvm_cf(m,0.04045f));
        }
        sel=spvm_id(m);
        { uint32_t a[]={m->t_f32,sel,cut,lo,hi}; spvm_b(m,SpvOpSelect,a,5); }
        comp[k]=sel;
    }
    return spvb_construct4(m,comp[0],comp[1],comp[2],comp[3]);
}
static uint32_t pack_op(FpCtx* c, uint32_t src, uint8_t op){
    SpvMod* m=&c->m;
    uint32_t v=src, inst, two=0;
    switch(op){
    case FP_PK2:  inst=GlslPackHalf2x16;  two=1; break;
    case FP_PK16: inst=GlslPackUnorm2x16; two=1; break;
    case FP_PK4:  inst=GlslPackSnorm4x8;  break;
    case FP_PKG:  v=srgb_curve(c,src,1);
    default:      inst=GlslPackUnorm4x8;  break;
    }
    uint32_t arg=two? v2(c,spvb_extract(m,m->t_f32,v,0),
                          spvb_extract(m,m->t_f32,v,1)) : v;
    uint32_t bits=spvb_ext1(m,m->t_u32,inst,arg);
    return spvb_splat4(m,spvb_un(m,SpvOpBitcast,m->t_f32,bits));
}
static uint32_t unpack_op(FpCtx* c, uint32_t src, uint8_t op){
    SpvMod* m=&c->m;
    uint32_t bits=spvb_un(m,SpvOpBitcast,m->t_u32,
                          spvb_extract(m,m->t_f32,src,0));
    uint32_t inst, two=0;
    switch(op){
    case FP_UP2:  inst=GlslUnpackHalf2x16;  two=1; break;
    case FP_UP16: inst=GlslUnpackUnorm2x16; two=1; break;
    case FP_UP4:  inst=GlslUnpackSnorm4x8;  break;
    default:      inst=GlslUnpackUnorm4x8;  break;
    }
    if(two){
        uint32_t p=spvb_ext1(m,m->t_vf[2],inst,bits);
        uint32_t x=spvb_extract(m,m->t_f32,p,0), y=spvb_extract(m,m->t_f32,p,1);
        return spvb_construct4(m,x,y,x,y);
    }
    uint32_t r=spvb_ext1(m,m->t_vf[4],inst,bits);
    return op==FP_UPG? srgb_curve(c,r,0) : r;
}

static uint32_t sample(FpCtx* c, const FpInstr* in, uint32_t coord, int proj,
                       int explicit_lod, uint32_t lod, uint32_t bias,
                       uint32_t gx, uint32_t gy){
    SpvMod* m=&c->m;
    uint32_t u=in->tex_unit&15;
    int ty=c->tex_type[u];
    c->tex_used|=1u<<u;
    uint32_t img=spvb_load(m,c->t_simg[ty],c->img_var[u]);
    if(proj){
        uint32_t w=spvb_extract(m,m->t_f32,coord,3);
        uint32_t inv=spvb_bin(m,SpvOpFDiv,m->t_f32,spvm_cf(m,1.0f),w);
        coord=spvb_bin(m,SpvOpFMul,m->t_vf[4],coord,splat(c,inv));
    }
    uint32_t cx=spvb_extract(m,m->t_f32,coord,0);
    uint32_t cy=spvb_extract(m,m->t_f32,coord,1);
    uint32_t uv;
    if(ty==FP_TEX_2D) uv=v2(c,cx,cy);
    else { uv=spvm_id(m);
        uint32_t a[]={m->t_vf[3],uv,cx,cy,spvb_extract(m,m->t_f32,coord,2)};
        spvm_b(m,SpvOpCompositeConstruct,a,5); }
    dbg_env();
    if(c->shadow[u]){
        uint16_t op; int never=0, always=0;
        switch(c->shadow[u]-1){
        case 0: never=1;  op=SpvOpFOrdLessThan; break;
        case 1: op=SpvOpFOrdLessThan; break;
        case 2: op=SpvOpFOrdEqual; break;
        case 3: op=SpvOpFOrdLessThanEqual; break;
        case 4: op=SpvOpFOrdGreaterThan; break;
        case 5: op=SpvOpFUnordNotEqual; break;
        case 6: op=SpvOpFOrdGreaterThanEqual; break;
        default: always=1; op=SpvOpFOrdLessThan; break;
        }
        if(always) return splat(c,spvm_cf(m,1.0f));
        if(never)  return splat(c,spvm_cf(m,0.0f));
        uint32_t ref=spvb_extract(m,m->t_f32,coord,2);
        uint32_t l=explicit_lod?lod:spvm_cf(m,0.0f);
        uint32_t sh=g_no_shadow
            ? shadow_cmp_d(c,spvm_cf(m,1.0f),ref,op)
            : (c->shadow_lin[u]?shadow_pcf(c,img,uv,ref,op,l)
                               :shadow_cmp(c,tex_lod(c,img,uv,l),ref,op));
        c->last_shadow=sh; c->last_uv=uv; c->last_ref=ref;
        return splat(c,sh);
    }
    uint32_t id=spvm_id(m);
    if(explicit_lod){
        uint32_t a[]={m->t_vf[4],id,img,uv,SpvImgLod,lod};
        spvm_b(m,SpvOpImageSampleExplicitLod,a,6);
    } else if(gx&&gy){
        uint32_t a[]={m->t_vf[4],id,img,uv,SpvImgGrad,gx,gy};
        spvm_b(m,SpvOpImageSampleExplicitLod,a,7);
    } else if(bias){
        uint32_t a[]={m->t_vf[4],id,img,uv,SpvImgBias,bias};
        spvm_b(m,SpvOpImageSampleImplicitLod,a,6);
    } else {
        uint32_t a[]={m->t_vf[4],id,img,uv};
        spvm_b(m,SpvOpImageSampleImplicitLod,a,4);
    }
    return apply_remap(c,id,c->remap[u]);
}

int fp_translate(const FpProgramSrc* p, uint32_t* out, int cap, FpMeta* meta){
    static FpCtx ctx;
    FpCtx* c=&ctx;
    memset(c,0,sizeof *c);
    memset(g_visreg_cap,0,sizeof g_visreg_cap);
    dbg_env();
    { const char* e=getenv("PS3_RSX_VISFP");
      g_visfp=e?(uint32_t)strtoul(e,NULL,16):0;
      uint64_t h=0xcbf29ce484222325ull; const uint8_t* b=(const uint8_t*)p->words;
      for(size_t i=0;i<(size_t)p->nwords*4;i++){ h^=b[i]; h*=0x100000001b3ull; }
      g_cur_fphash=(uint32_t)h; }
    SpvMod* m=&c->m;
    spvm_init(m);
    c->p_fn_v4=spvm_ptr(m,SpvSCFunction,m->t_vf[4]);
    c->point_sprite=p->point_sprite;
    for(int i=0;i<16;i++){ c->remap[i]=p->remap[i]; c->shadow[i]=p->shadow[i];
                           c->shadow_lin[i]=p->shadow_linear[i];
                           c->tex_type[i]=p->tex_type[i]<3?p->tex_type[i]:0;
                           if(c->shadow[i]) c->tex_type[i]=FP_TEX_2D; }

    FpInstr dec[1024]; static uint32_t ioff[1024]; int nin=0;
    static int immidx[1024]; int nimm=0;
    uint32_t attrs=0;
    uint32_t iw=0;
    int nret=0, nloop=0, nkil=0;
    while(iw+4<=p->nwords&&nin<1024){
        int used=fp_decode_instr(p->words+iw,&dec[nin]);
        FpInstr* in=&dec[nin];
        ioff[nin]=iw*4;
        immidx[nin]=in->has_imm?nimm++:-1;
        switch(in->opcode){
        case FP_RET: nret++; break;
        case FP_KIL: nkil++; break;
        case FP_IFE: break;
        case FP_LOOP: case FP_REP: nloop++; break;
        case FP_BRK: break;
        case FP_CAL:
            fprintf(stderr,"[FP] unsupported flow-control op 0x%x - skip program\n",in->opcode);
            return 0;
        case FP_BEM: case FP_TEXBEM: case FP_TXPBEM: case FP_BEMLUM:
            fprintf(stderr,"[FP] unsupported op 0x%x - skip program\n",in->opcode);
            return 0;
        }
        if(in->scale) switch(in->opcode){
            case FP_TEX: case FP_TXP: case FP_TXD: case FP_TXL: case FP_TXB:{
                static int wn; if(wn++<4)
                    fprintf(stderr,"[FP] texture op 0x%x with scale field %u - "
                            "_bx2 encoding not pinned down, applying the "
                            "arithmetic scale\n",in->opcode,in->scale);
                break; }
        }
        if(in->opcode<FP_BRK){
            for(int s2=0;s2<3;s2++){
                if(in->src[s2].reg_type==FP_REG_INPUT){
                    attrs|=1u<<(in->input_attr&15);
                    if(in->nopersp) c->nopersp_attrs|=1u<<(in->input_attr&15);
                } else if(in->src[s2].reg_type==FP_REG_TEMP){
                    uint64_t bit=1ull<<(in->src[s2].tmp_idx&63);
                    if(in->src[s2].fp16) c->use_h|=bit; else c->use_r|=bit;
                }
            }
            if(!in->no_dest){
                uint64_t bit=1ull<<(in->dest_idx&63);
                if(in->dest_fp16) c->use_h|=bit; else c->use_r|=bit;
            }
        }
        nin++;
        iw+=(uint32_t)used*4;
        if(in->end) break;
    }
    if(!nin) return 0;
    meta->ninstr=iw/4;
    for(int i=0;i<nin;i++) if(dec[i].opcode==FP_IFE){
        int oke=0, okn=0;
        for(int j=0;j<nin;j++){ if(ioff[j]==dec[i].else_off) oke=1;
                                if(ioff[j]==dec[i].end_off)  okn=1; }
        if(dec[i].else_off==dec[i].end_off) oke=okn;
        if(!oke||!okn){
            fprintf(stderr,"[FP] IFE at +0x%x targets else=+0x%x end=+0x%x, not "
                    "instruction boundaries - skip program\n",
                    ioff[i],dec[i].else_off,dec[i].end_off);
            return 0;
        }
    }
    for(int i=0;i<nin;i++) if(dec[i].opcode==FP_LOOP||dec[i].opcode==FP_REP){
        int ok=(dec[i].end_off>=iw*4);
        for(int j=0;j<nin&&!ok;j++) if(ioff[j]==dec[i].end_off) ok=1;
        if(!ok){
            fprintf(stderr,"[FP] LOOP at +0x%x ends at +0x%x, not an instruction "
                    "boundary - skip program\n",ioff[i],dec[i].end_off);
            return 0;
        }
    }

    uint32_t iface[40]; int nif=0;
    uint32_t p_in_v4=spvm_ptr(m,SpvSCInput,m->t_vf[4]);
    uint32_t p_out_v4=spvm_ptr(m,SpvSCOutput,m->t_vf[4]);
    c->v_fragcoord=spvm_id(m);
    { uint32_t a[]={p_in_v4,c->v_fragcoord,SpvSCInput}; spvm_g(m,SpvOpVariable,a,3); }
    { uint32_t a[]={c->v_fragcoord,SpvDecBuiltIn,SpvBIFragCoord}; spvm_d(m,SpvOpDecorate,a,3); }
    iface[nif++]=c->v_fragcoord;
    if(c->point_sprite&1){
        uint32_t p_in_v2=spvm_ptr(m,SpvSCInput,m->t_vf[2]);
        c->v_pointcoord=spvm_id(m);
        { uint32_t a[]={p_in_v2,c->v_pointcoord,SpvSCInput}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={c->v_pointcoord,SpvDecBuiltIn,SpvBIPointCoord};
          spvm_d(m,SpvOpDecorate,a,3); }
        iface[nif++]=c->v_pointcoord;
    }
    static const int8_t ATTR_LOC[16]={-1,0,1,2,3,4,5,6,7,8,9,10,11,12,-1,-1};
    if(attrs&(1u<<14)){
        uint32_t p_in_b=spvm_ptr(m,SpvSCInput,m->t_bool);
        c->v_frontfacing=spvm_id(m);
        { uint32_t a[]={p_in_b,c->v_frontfacing,SpvSCInput}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={c->v_frontfacing,SpvDecBuiltIn,SpvBIFrontFacing}; spvm_d(m,SpvOpDecorate,a,3); }
        iface[nif++]=c->v_frontfacing;
        attrs&=~(1u<<14);
    }
    for(int a2=1;a2<16;a2++) if(attrs&(1u<<a2)){
        int loc=ATTR_LOC[a2];
        if(loc<0){ fprintf(stderr,"[FP] unsupported input attr %d - skip\n",a2); return 0; }
        uint32_t v=spvm_id(m);
        { uint32_t a[]={p_in_v4,v,SpvSCInput}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={v,SpvDecLocation,(uint32_t)loc}; spvm_d(m,SpvOpDecorate,a,3); }
        c->in_var[a2]=v; iface[nif++]=v;
    }
    c->v_out=spvm_id(m);
    { uint32_t a[]={p_out_v4,c->v_out,SpvSCOutput}; spvm_g(m,SpvOpVariable,a,3); }
    { uint32_t a[]={c->v_out,SpvDecLocation,0}; spvm_d(m,SpvOpDecorate,a,3); }
    iface[nif++]=c->v_out;
    uint32_t v_depth=0;
    if(p->ctrl&0xe){
        uint32_t p_out_f=spvm_ptr(m,SpvSCOutput,m->t_f32);
        v_depth=spvm_id(m);
        { uint32_t a[]={p_out_f,v_depth,SpvSCOutput}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={v_depth,SpvDecBuiltIn,22 };
          spvm_d(m,SpvOpDecorate,a,3); }
        iface[nif++]=v_depth;
    }
    if(nimm){
        uint32_t t_arr=spvm_id(m);
        { uint32_t a[]={t_arr,m->t_vf[4],spvm_cu(m,(uint32_t)nimm)};
          spvm_g(m,SpvOpTypeArray,a,3); }
        { uint32_t a[]={t_arr,SpvDecArrayStride,16}; spvm_d(m,SpvOpDecorate,a,3); }
        uint32_t t_blk=spvm_id(m);
        { uint32_t a[]={t_blk,t_arr}; spvm_g(m,SpvOpTypeStruct,a,2); }
        { uint32_t a[]={t_blk,SpvDecBlock}; spvm_d(m,SpvOpDecorate,a,2); }
        { uint32_t a[]={t_blk,0,SpvDecOffset,0}; spvm_d(m,SpvOpMemberDecorate,a,4); }
        uint32_t p_blk=spvm_ptr(m,SpvSCUniform,t_blk);
        c->fpc_var=spvm_id(m);
        { uint32_t a[]={p_blk,c->fpc_var,SpvSCUniform}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={c->fpc_var,SpvDecDescriptorSet,0}; spvm_d(m,SpvOpDecorate,a,3); }
        { uint32_t a[]={c->fpc_var,SpvDecBinding,1}; spvm_d(m,SpvOpDecorate,a,3); }
        c->fpc_pv4=spvm_ptr(m,SpvSCUniform,m->t_vf[4]);
    }

    uint32_t tex_ref=0;
    for(int i=0;i<nin;i++){
        switch(dec[i].opcode){
        case FP_TEX: case FP_TXP: case FP_TXL: case FP_TXB: case FP_TXD:
            tex_ref|=1u<<(dec[i].tex_unit&15); break;
        }
    }
    if(tex_ref){
        static const uint32_t DIM[3]={1,2,3};
        for(int k=0;k<3;k++){
            int any=0;
            for(int u=0;u<16;u++) if((tex_ref&(1u<<u))&&c->tex_type[u]==k) any=1;
            if(!any) continue;
            c->t_img[k]=spvm_id(m);
            { uint32_t a[]={c->t_img[k],m->t_f32,DIM[k],0,0,0,1,0 };
              spvm_g(m,SpvOpTypeImage,a,8); }
            c->t_simg[k]=spvm_id(m);
            { uint32_t a[]={c->t_simg[k],c->t_img[k]}; spvm_g(m,SpvOpTypeSampledImage,a,2); }
            c->p_uc_simg[k]=spvm_ptr(m,SpvSCUniformConstant,c->t_simg[k]);
        }
        for(int u=0;u<16;u++) if(tex_ref&(1u<<u)){
            uint32_t v=spvm_id(m);
            { uint32_t a[]={c->p_uc_simg[c->tex_type[u]],v,SpvSCUniformConstant};
              spvm_g(m,SpvOpVariable,a,3); }
            { uint32_t a[]={v,SpvDecDescriptorSet,0}; spvm_d(m,SpvOpDecorate,a,3); }
            { uint32_t a[]={v,SpvDecBinding,8u+(uint32_t)u}; spvm_d(m,SpvOpDecorate,a,3); }
            c->img_var[u]=v;
        }
    }

    c->entry=spvm_id(m);
    { uint32_t a[]={m->t_void,c->entry,0,m->t_fnvoid}; spvm_b(m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(m); uint32_t a[]={lbl}; spvm_b(m,SpvOpLabel,a,1); }
    c->use_r|=1; c->use_h|=1;
    if(p->ctrl&0xe) c->use_r|=2;
    c->v_scratch=spvm_id(m);
    { uint32_t a[]={c->p_fn_v4,c->v_scratch,SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    for(int r=0;r<64;r++) if(c->use_r>>r&1){ c->v_r[r]=spvm_id(m);
        uint32_t a[]={c->p_fn_v4,c->v_r[r],SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    for(int r=0;r<64;r++) if(c->use_h>>r&1){ c->v_h[r]=spvm_id(m);
        uint32_t a[]={c->p_fn_v4,c->v_h[r],SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    for(int i=0;i<2;i++){ c->v_cc[i]=spvm_id(m);
        uint32_t a[]={c->p_fn_v4,c->v_cc[i],SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    if(nret){ c->v_exec=spvm_id(m);
        uint32_t p_fn_b=spvm_ptr(m,SpvSCFunction,m->t_bool);
        uint32_t a[]={p_fn_b,c->v_exec,SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    c->v_kilvis=0;
    if(nkil&&g_killvis){ c->v_kilvis=spvm_id(m);
        uint32_t p_fn_b=spvm_ptr(m,SpvSCFunction,m->t_bool);
        uint32_t a[]={p_fn_b,c->v_kilvis,SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    if(nloop){
        uint32_t p_fn_b=spvm_ptr(m,SpvSCFunction,m->t_bool);
        uint32_t p_fn_i=spvm_ptr(m,SpvSCFunction,m->t_i32);
        c->v_brk=spvm_id(m);
        { uint32_t a[]={p_fn_b,c->v_brk,SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
        c->v_iter=spvm_id(m);
        { uint32_t a[]={p_fn_i,c->v_iter,SpvSCFunction}; spvm_b(m,SpvOpVariable,a,3); }
    }
    c->zero4=spvm_cf4(m,0,0,0,0);
    c->one4=spvm_cf4(m,1,1,1,1);
    spvb_store(m,c->v_scratch,c->zero4);
    for(int r=0;r<64;r++){ if(c->v_r[r]) spvb_store(m,c->v_r[r],c->zero4);
                           if(c->v_h[r]) spvb_store(m,c->v_h[r],c->zero4); }
    spvb_store(m,c->v_cc[0],c->zero4); spvb_store(m,c->v_cc[1],c->zero4);
    if(c->v_exec) spvb_store(m,c->v_exec,const_true(c));
    if(c->v_kilvis) spvb_store(m,c->v_kilvis,spvb_un(m,SpvOpLogicalNot,m->t_bool,const_true(c)));

    pt_parse();
    c->pt_live=0;
    if(g_pt_on&&(!g_visfp||g_visfp==g_cur_fphash)){
        uint32_t t_arr=spvm_id(m);
        { uint32_t a[]={t_arr,m->t_vf[4],spvm_cu(m,PT_TOTAL)}; spvm_g(m,SpvOpTypeArray,a,3); }
        { uint32_t a[]={t_arr,SpvDecArrayStride,16}; spvm_d(m,SpvOpDecorate,a,3); }
        uint32_t t_blk=spvm_id(m);
        { uint32_t a[]={t_blk,t_arr}; spvm_g(m,SpvOpTypeStruct,a,2); }
        { uint32_t a[]={t_blk,SpvDecBufferBlock}; spvm_d(m,SpvOpDecorate,a,2); }
        { uint32_t a[]={t_blk,0,SpvDecOffset,0}; spvm_d(m,SpvOpMemberDecorate,a,4); }
        uint32_t p_blk=spvm_ptr(m,SpvSCUniform,t_blk);
        c->pt_var=spvm_id(m);
        { uint32_t a[]={p_blk,c->pt_var,SpvSCUniform}; spvm_g(m,SpvOpVariable,a,3); }
        { uint32_t a[]={c->pt_var,SpvDecDescriptorSet,0}; spvm_d(m,SpvOpDecorate,a,3); }
        { uint32_t a[]={c->pt_var,SpvDecBinding,24}; spvm_d(m,SpvOpDecorate,a,3); }
        c->pt_pv4=spvm_ptr(m,SpvSCUniform,m->t_vf[4]);
        uint32_t fc=spvb_load(m,m->t_vf[4],c->v_fragcoord);
        uint32_t fx=spvb_extract(m,m->t_f32,fc,0), fy=spvb_extract(m,m->t_f32,fc,1);
        uint32_t ax=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,
            spvb_bin(m,SpvOpFOrdGreaterThanEqual,m->t_bool,fx,spvm_cf(m,g_pt_x)),
            spvb_bin(m,SpvOpFOrdLessThan,m->t_bool,fx,spvm_cf(m,g_pt_x+2.0f)));
        uint32_t ay=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,
            spvb_bin(m,SpvOpFOrdGreaterThanEqual,m->t_bool,fy,spvm_cf(m,g_pt_y)),
            spvb_bin(m,SpvOpFOrdLessThan,m->t_bool,fy,spvm_cf(m,g_pt_y+2.0f)));
        c->pt_act=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,ax,ay);
        uint32_t dx=spvb_un(m,SpvOpConvertFToS,m->t_i32,
                            spvb_bin(m,SpvOpFSub,m->t_f32,fx,spvm_cf(m,g_pt_x)));
        uint32_t dy=spvb_un(m,SpvOpConvertFToS,m->t_i32,
                            spvb_bin(m,SpvOpFSub,m->t_f32,fy,spvm_cf(m,g_pt_y)));
        uint32_t slot=spvb_bin(m,SpvOpIAdd,m->t_i32,dx,
                               spvb_bin(m,SpvOpIMul,m->t_i32,dy,spvm_ci(m,2)));
        c->pt_base=spvb_bin(m,SpvOpIMul,m->t_i32,slot,spvm_ci(m,PT_SLOT));
        c->pt_live=1;
        { uint32_t ptr=pt_ptr(c,0);
          uint32_t old=spvb_load(m,m->t_vf[4],ptr);
          uint32_t hits=spvb_bin(m,SpvOpFAdd,m->t_f32,
                                 spvb_extract(m,m->t_f32,old,0),spvm_cf(m,1.0f));
          spvb_store(m,ptr,spvb_construct4(m,hits,fx,fy,
                                           spvb_extract(m,m->t_f32,fc,2))); }
        pt_store(c,1,fc);
        for(int a2=1;a2<16;a2++) if(c->in_var[a2])
            pt_store(c,1+a2,spvb_load(m,m->t_vf[4],c->in_var[a2]));
    }

    for(int i=0;i<nin;i++){
        const FpInstr* in=&dec[i];
        c->cur_imm=immidx[i];
        uint32_t r=0,a,b,d;
        while(c->nfr&&c->fr[c->nfr-1].end_off==ioff[i]) c->nfr--;
        for(int f=0;f<c->nfr;f++)
            if(c->fr[f].else_off==ioff[i]) c->fr[f].in_else=1;
        if(c->in_loop&&ioff[i]==c->lp_end) loop_close(c);
        switch(in->opcode){
        case FP_LOOP: case FP_REP:{
            if(c->in_loop){
                fprintf(stderr,"[FP] nested LOOP - skip program\n"); return 0; }
            spvb_store(m,c->v_brk,const_false(c));
            spvb_store(m,c->v_iter,spvm_ci(m,0));
            c->lp_head=spvm_id(m); c->lp_merge=spvm_id(m); c->lp_cont=spvm_id(m);
            uint32_t body=spvm_id(m);
            { uint32_t a[]={c->lp_head}; spvm_b(m,SpvOpBranch,a,1); }
            { uint32_t a[]={c->lp_head}; spvm_b(m,SpvOpLabel,a,1); }
            { uint32_t a[]={c->lp_merge,c->lp_cont,0}; spvm_b(m,SpvOpLoopMerge,a,3); }
            { uint32_t a[]={body}; spvm_b(m,SpvOpBranch,a,1); }
            { uint32_t a[]={body}; spvm_b(m,SpvOpLabel,a,1); }
            c->lp_end=in->end_off;
            c->lp_count=in->loop_count?in->loop_count:1u;
            c->in_loop=1;
            goto next; }
        case FP_BRK:{
            if(!c->in_loop){
                fprintf(stderr,"[FP] BRK outside a LOOP - skip program\n"); return 0; }
            uint32_t g=cond_gate(c,in);
            uint32_t cnd=g?spvb_un(m,SpvOpAny,m->t_bool,g):const_true(c);
            uint32_t bp=blk_pred(c);
            if(bp) cnd=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,cnd,bp);
            spvb_store(m,c->v_brk,spvb_bin(m,SpvOpLogicalOr,m->t_bool,
                spvb_load(m,m->t_bool,c->v_brk),cnd));
            goto next; }
        case FP_NOP: case FP_FENCT: case FP_FENCB: goto next;
        case FP_IFE:{
            uint32_t g=cond_gate(c,in);
            uint32_t cnd=g?spvb_extract(m,m->t_bool,g,0):const_true(c);
            if(c->nfr<8){ c->fr[c->nfr].cond=cnd; c->fr[c->nfr].else_off=in->else_off;
                          c->fr[c->nfr].end_off=in->end_off;
                          c->fr[c->nfr].in_else=0; c->nfr++; }
            else { fprintf(stderr,"[FP] IFE nesting > 8 - skip program\n"); return 0; }
            goto next; }
        case FP_RET:{
            uint32_t g=cond_gate(c,in);
            uint32_t cnd=g?spvb_un(m,SpvOpAny,m->t_bool,g):const_true(c);
            uint32_t bp=blk_pred(c);
            if(bp) cnd=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,cnd,bp);
            if(c->v_exec){
                uint32_t cur=spvb_load(m,m->t_bool,c->v_exec);
                spvb_store(m,c->v_exec,spvb_bin(m,SpvOpLogicalAnd,m->t_bool,cur,
                    spvb_un(m,SpvOpLogicalNot,m->t_bool,cnd)));
            }
            goto next; }
        case FP_KIL:{
            c->kil=1;
            uint32_t gate=cond_gate(c,in);
            { uint32_t bp=blk_pred(c);
              if(bp){ uint32_t b4=bsplat4(c,bp);
                      gate=gate?spvb_bin(m,SpvOpLogicalAnd,m->t_bv4,gate,b4):b4; } }
            uint32_t cond;
            if(gate) cond=spvb_un(m,SpvOpAny,m->t_bool,gate);
            else cond=const_true(c);
            if(c->v_kilvis){
                uint32_t cur=spvb_load(m,m->t_bool,c->v_kilvis);
                spvb_store(m,c->v_kilvis,
                    spvb_bin(m,SpvOpLogicalOr,m->t_bool,cur,cond));
                goto next; }
            uint32_t killb=spvm_id(m), contb=spvm_id(m);
            { uint32_t ar[]={contb,0}; spvm_b(m,SpvOpSelectionMerge,ar,2); }
            { uint32_t ar[]={cond,killb,contb}; spvm_b(m,SpvOpBranchConditional,ar,3); }
            { uint32_t ar[]={killb}; spvm_b(m,SpvOpLabel,ar,1); }
            { uint32_t ar[1]; spvm_b(m,SpvOpKill,ar,0); }
            { uint32_t ar[]={contb}; spvm_b(m,SpvOpLabel,ar,1); }
            goto next; }
        case FP_MOV: r=load_src(c,in,0); break;
        case FP_MUL: a=load_src(c,in,0); b=load_src(c,in,1);
            r=spvb_bin(m,SpvOpFMul,m->t_vf[4],a,b); break;
        case FP_ADD: a=load_src(c,in,0); b=load_src(c,in,1);
            r=spvb_bin(m,SpvOpFAdd,m->t_vf[4],a,b); break;
        case FP_MAD: a=load_src(c,in,0); b=load_src(c,in,1); d=load_src(c,in,2);
            r=spvb_bin(m,SpvOpFAdd,m->t_vf[4],
                       spvb_bin(m,SpvOpFMul,m->t_vf[4],a,b),d); break;
        case FP_DP2: a=load_src(c,in,0); b=load_src(c,in,1);
            r=splat(c,dot_h(m,a,b,2)); break;
        case FP_DP3: a=load_src(c,in,0); b=load_src(c,in,1);
            r=splat(c,dot_h(m,a,b,3)); break;
        case FP_DP4: a=load_src(c,in,0); b=load_src(c,in,1);
            r=splat(c,dot_h(m,a,b,4)); break;
        case FP_DP2A:{ a=load_src(c,in,0); b=load_src(c,in,1); d=load_src(c,in,2);
            uint32_t d2=dot_h(m,a,b,2);
            uint32_t dx=spvb_extract(m,m->t_f32,d,0);
            r=splat(c,spvb_bin(m,SpvOpFAdd,m->t_f32,d2,dx)); break; }
        case FP_DST:{ a=load_src(c,in,0); b=load_src(c,in,1);
            uint32_t ay=spvb_extract(m,m->t_f32,a,1), by=spvb_extract(m,m->t_f32,b,1);
            uint32_t az=spvb_extract(m,m->t_f32,a,2), bw=spvb_extract(m,m->t_f32,b,3);
            r=spvb_construct4(m,spvm_cf(m,1.0f),
                              spvb_bin(m,SpvOpFMul,m->t_f32,ay,by),az,bw); break; }
        case FP_MIN: a=load_src(c,in,0); b=load_src(c,in,1);
            r=spvb_ext2(m,m->t_vf[4],GlslFMin,a,b); break;
        case FP_MAX: a=load_src(c,in,0); b=load_src(c,in,1);
            r=spvb_ext2(m,m->t_vf[4],GlslFMax,a,b); break;
        case FP_SLT: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFOrdLessThan,a,b); break;
        case FP_SGE: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFOrdGreaterThanEqual,a,b); break;
        case FP_SLE: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFOrdLessThanEqual,a,b); break;
        case FP_SGT: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFOrdGreaterThan,a,b); break;
        case FP_SNE: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFUnordNotEqual,a,b); break;
        case FP_SEQ: a=load_src(c,in,0); b=load_src(c,in,1);
            r=cmp_set(c,SpvOpFOrdEqual,a,b); break;
        case FP_STR: r=c->one4; break;
        case FP_SFL: r=c->zero4; break;
        case FP_FRC: r=spvb_ext1(m,m->t_vf[4],GlslFract,load_src(c,in,0)); break;
        case FP_FLR:{ a=load_src(c,in,0);
            dbg_env();
            if(!g_no_flrnudge){
                uint32_t ab=spvb_ext1(m,m->t_vf[4],GlslFAbs,a);
                const float e=1.0f/4194304.0f;
                a=spvb_bin(m,SpvOpFAdd,m->t_vf[4],a,
                    spvb_bin(m,SpvOpFMul,m->t_vf[4],ab,spvm_cf4(m,e,e,e,e)));
            }
            r=spvb_ext1(m,m->t_vf[4],GlslFloor,a); break; }
        case FP_RCP:{ a=load_src(c,in,0);
            uint32_t x=spvb_extract(m,m->t_f32,a,0);
            r=splat(c,spvb_bin(m,SpvOpFDiv,m->t_f32,spvm_cf(m,1.0f),x)); break; }
        case FP_RSQ:{ a=load_src(c,in,0);
            uint32_t x=spvb_extract(m,m->t_f32,a,0);
            r=splat(c,spvb_ext1(m,m->t_f32,GlslInverseSqrt,
                     spvb_ext1(m,m->t_f32,GlslFAbs,x))); break; }
        case FP_EX2:{ a=load_src(c,in,0);
            r=splat(c,spvb_ext1(m,m->t_f32,GlslExp2,spvb_extract(m,m->t_f32,a,0))); break; }
        case FP_LG2:{ a=load_src(c,in,0);
            uint32_t x=spvb_extract(m,m->t_f32,a,0);
            r=splat(c,spvb_ext1(m,m->t_f32,GlslLog2,
                     spvb_ext1(m,m->t_f32,GlslFAbs,x))); break; }
        case FP_SIN:{ a=load_src(c,in,0);
            r=splat(c,spvb_ext1(m,m->t_f32,GlslSin,spvb_extract(m,m->t_f32,a,0))); break; }
        case FP_COS:{ a=load_src(c,in,0);
            r=splat(c,spvb_ext1(m,m->t_f32,GlslCos,spvb_extract(m,m->t_f32,a,0))); break; }
        case FP_POW:{ a=load_src(c,in,0); b=load_src(c,in,1);
            uint32_t x=spvb_extract(m,m->t_f32,a,0), y=spvb_extract(m,m->t_f32,b,0);
            r=splat(c,spvb_ext2(m,m->t_f32,GlslPow,x,y)); break; }
        case FP_LRP: a=load_src(c,in,0); b=load_src(c,in,1); d=load_src(c,in,2);
            r=spvb_ext3(m,m->t_vf[4],GlslFMix,d,b,a); break;
        case FP_LIT:{
            a=load_src(c,in,0);
            uint32_t tx=spvb_extract(m,m->t_f32,a,0);
            uint32_t ty=spvb_extract(m,m->t_f32,a,1);
            uint32_t tw=spvb_extract(m,m->t_f32,a,3);
            uint32_t mx=spvb_ext2(m,m->t_f32,GlslFMax,tx,spvm_cf(m,0.0f));
            uint32_t my=spvb_ext2(m,m->t_f32,GlslFMax,ty,spvm_cf(m,0.0f));
            uint32_t lg=spvb_ext1(m,m->t_f32,GlslLog2,my);
            uint32_t pw=spvb_ext1(m,m->t_f32,GlslExp2,spvb_bin(m,SpvOpFMul,m->t_f32,tw,lg));
            uint32_t gt=spvb_bin(m,SpvOpFOrdGreaterThan,m->t_bool,tx,spvm_cf(m,0.0f));
            uint32_t sel=spvm_id(m);
            { uint32_t ar[]={m->t_f32,sel,gt,pw,spvm_cf(m,0.0f)}; spvm_b(m,SpvOpSelect,ar,5); }
            r=spvb_construct4(m,spvm_cf(m,1.0f),mx,sel,spvm_cf(m,1.0f)); break; }
        case FP_DDX: r=spvb_un(m,SpvOpDPdx,m->t_vf[4],load_src(c,in,0)); break;
        case FP_DDY: r=spvb_un(m,SpvOpDPdy,m->t_vf[4],load_src(c,in,0)); break;
        case FP_NRM:{ a=load_src(c,in,0);
            uint32_t d3=dot_h(m,a,a,3);
            uint32_t inv=spvb_ext1(m,m->t_f32,GlslInverseSqrt,d3);
            r=spvb_bin(m,SpvOpFMul,m->t_vf[4],a,splat(c,inv)); break; }
        case FP_DIV:{ a=load_src(c,in,0); b=load_src(c,in,1);
            uint32_t bx=spvb_extract(m,m->t_f32,b,0);
            r=spvb_bin(m,SpvOpFMul,m->t_vf[4],a,
                splat(c,spvb_bin(m,SpvOpFDiv,m->t_f32,spvm_cf(m,1.0f),bx))); break; }
        case FP_DIVSQ:{ a=load_src(c,in,0); b=load_src(c,in,1);
            uint32_t bx=spvb_extract(m,m->t_f32,b,0);
            uint32_t is=spvb_ext1(m,m->t_f32,GlslInverseSqrt,
                        spvb_ext1(m,m->t_f32,GlslFAbs,bx));
            r=spvb_bin(m,SpvOpFMul,m->t_vf[4],a,splat(c,is)); break; }
        case FP_TEX: r=sample(c,in,load_src(c,in,0),0,0,0,0,0,0); break;
        case FP_TXP: r=sample(c,in,load_src(c,in,0),1,0,0,0,0,0); break;
        case FP_TXL:{ a=load_src(c,in,0);
            uint32_t lod=spvb_extract(m,m->t_f32,a,3);
            r=sample(c,in,a,0,1,lod,0,0,0); break; }
        case FP_TXB:{ a=load_src(c,in,0); b=load_src(c,in,1);
            r=sample(c,in,a,0,0,0,spvb_extract(m,m->t_f32,b,0),0,0); break; }
        case FP_TXD:{ a=load_src(c,in,0); b=load_src(c,in,1); d=load_src(c,in,2);
            int nc=c->tex_type[in->tex_unit&15]==FP_TEX_2D?2:3;
            uint32_t gx,gy;
            if(nc==2){ gx=v2(c,spvb_extract(m,m->t_f32,b,0),
                               spvb_extract(m,m->t_f32,b,1));
                       gy=v2(c,spvb_extract(m,m->t_f32,d,0),
                               spvb_extract(m,m->t_f32,d,1)); }
            else { gx=spvm_id(m);
                   { uint32_t ar[]={m->t_vf[3],gx,spvb_extract(m,m->t_f32,b,0),
                       spvb_extract(m,m->t_f32,b,1),spvb_extract(m,m->t_f32,b,2)};
                     spvm_b(m,SpvOpCompositeConstruct,ar,5); }
                   gy=spvm_id(m);
                   { uint32_t ar[]={m->t_vf[3],gy,spvb_extract(m,m->t_f32,d,0),
                       spvb_extract(m,m->t_f32,d,1),spvb_extract(m,m->t_f32,d,2)};
                     spvm_b(m,SpvOpCompositeConstruct,ar,5); } }
            r=sample(c,in,a,0,0,0,0,gx,gy); break; }
        case FP_PK2: case FP_PK4: case FP_PK16: case FP_PKB: case FP_PKG:
            r=pack_op(c,load_src(c,in,0),in->opcode); break;
        case FP_UP2: case FP_UP4: case FP_UP16: case FP_UPB: case FP_UPG:
            r=unpack_op(c,load_src(c,in,0),in->opcode); break;
        case FP_LIF:{
            a=load_src(c,in,0);
            uint32_t ty=spvb_extract(m,m->t_f32,a,1);
            uint32_t tw=spvb_extract(m,m->t_f32,a,3);
            uint32_t pw=spvb_ext1(m,m->t_f32,GlslExp2,tw);
            uint32_t gt=spvb_bin(m,SpvOpFOrdGreaterThan,m->t_bool,ty,spvm_cf(m,0.0f));
            uint32_t sel=spvm_id(m);
            { uint32_t ar[]={m->t_f32,sel,gt,pw,spvm_cf(m,0.0f)}; spvm_b(m,SpvOpSelect,ar,5); }
            r=spvb_construct4(m,spvm_cf(m,1.0f),ty,sel,spvm_cf(m,1.0f)); break; }
        default:
            fprintf(stderr,"[FP] unsupported op 0x%x - skip program\n",in->opcode);
            return 0;
        }
        write_dst(c,in,r);
        if(c->pt_live&&i<256){
            if(!in->no_dest)
                pt_store(c,17+i,spvb_load(m,m->t_vf[4],
                         reg_var(c,in->dest_fp16,in->dest_idx&63)));
            if(in->set_cond)
                pt_store(c,PT_CC+i,spvb_load(m,m->t_vf[4],
                         c->v_cc[in->cond_mod_reg1]));
        }
        next:;
        visreg_capture(c,i);
        if(in->end) break;
    }
    if(c->in_loop) loop_close(c);

    { int from_h0 = ((p->ctrl>>10)&1) ? !((p->ctrl>>6)&1)
                                      : (!c->wrote_r0&&c->wrote_h0);
      uint32_t col=spvb_load(m,m->t_vf[4],reg_var(c,from_h0,0));
      { static int va=-2, vg=0;
        if(va==-2){ const char* e=getenv("PS3_RSX_VISATTR"); va=e?atoi(e):-1;
                    vg=getenv("PS3_RSX_VISG")?1:0; }
        if(va>=0&&va<16){
            uint32_t v=attr_load(c,(uint32_t)va,vg);
            uint32_t x=spvb_ext1(m,m->t_f32,GlslFAbs,
                                 spvb_extract(m,m->t_f32,v,0));
            col=spvb_construct4(m,x,
                spvb_bin(m,SpvOpFMul,m->t_f32,x,spvm_cf(m,1e-3f)),
                spvb_bin(m,SpvOpFMul,m->t_f32,x,spvm_cf(m,1e-6f)),
                spvm_cf(m,1.0f));
        } }
      visreg_parse();
      if(g_visreg.n>0&&(!g_visfp||g_visfp==g_cur_fphash)){
          uint32_t ch[3];
          for(int k=0;k<3;k++){
              int s=k<g_visreg.n?k:g_visreg.n-1;
              uint32_t v=g_visreg_cap[s]?g_visreg_cap[s]:visreg_read(c,s);
              ch[k]=spvb_ext3(m,m->t_f32,GlslFClamp,v,
                              spvm_cf(m,0.0f),spvm_cf(m,1.0f));
          }
          col=spvb_construct4(m,ch[0],ch[1],ch[2],spvm_cf(m,1.0f));
      }
      if(c->v_kilvis){
          uint32_t k=spvb_load(m,m->t_bool,c->v_kilvis);
          uint32_t grn=spvm_cf4(m,0.0f,1.0f,0.0f,1.0f);
          uint32_t sel=spvm_id(m);
          { uint32_t ar[]={m->t_vf[4],sel,bsplat4(c,k),grn,col};
            spvm_b(m,SpvOpSelect,ar,5); }
          col=sel;
      }
      { static int svis=-1;
        if(svis<0){ const char* e=getenv("PS3_RSX_SHADOWVIS"); svis=e?atoi(e):0; }
        if(svis&&c->last_shadow){
            uint32_t one=spvm_cf(m,1.0f), zero=spvm_cf(m,0.0f);
            if(svis==2)      col=spvb_construct4(m,
                                   spvb_extract(m,m->t_f32,c->last_uv,0),
                                   spvb_extract(m,m->t_f32,c->last_uv,1),zero,one);
            else if(svis==3) col=spvb_construct4(m,c->last_ref,c->last_d,zero,one);
            else             col=spvb_construct4(m,c->last_shadow,c->last_shadow,
                                                 c->last_shadow,one);
        } }
      static int mixdbg=-1;
      if(mixdbg<0) mixdbg=getenv("PS3_RSX_FPMIX")?1:0;
      if(mixdbg){
          uint32_t g=spvm_cf4(m,0.0f,1.0f,0.0f,1.0f);
          col=spvb_ext3(m,m->t_vf[4],GlslFMix,col,g,spvm_cf4(m,0.5f,0.5f,0.5f,0.5f));
      }
      if(p->alpha_func>=0x200&&p->alpha_func<=0x207&&p->alpha_func!=0x207){
          uint32_t av=spvb_extract(m,m->t_f32,col,3);
          uint32_t rf=spvm_cf(m,(float)(p->alpha_ref&0xff)/255.0f);
          uint32_t pass;
          switch(p->alpha_func){
          case 0x200: { uint32_t id=spvm_id(m);
                        uint32_t ar[]={m->t_bool,id};
                        spvm_g(m,SpvOpConstantFalse,ar,2); pass=id; } break;
          case 0x201: pass=spvb_bin(m,SpvOpFOrdLessThan,m->t_bool,av,rf); break;
          case 0x202: pass=spvb_bin(m,SpvOpFOrdEqual,m->t_bool,av,rf); break;
          case 0x203: pass=spvb_bin(m,SpvOpFOrdLessThanEqual,m->t_bool,av,rf); break;
          case 0x204: pass=spvb_bin(m,SpvOpFOrdGreaterThan,m->t_bool,av,rf); break;
          case 0x205: pass=spvb_bin(m,SpvOpFUnordNotEqual,m->t_bool,av,rf); break;
          default:    pass=spvb_bin(m,SpvOpFOrdGreaterThanEqual,m->t_bool,av,rf); break;
          }
          uint32_t fail=spvb_un(m,SpvOpLogicalNot,m->t_bool,pass);
          if(g_killvis==3&&p->alpha_func==0x204&&(p->alpha_ref&0xff)==8){
              uint32_t a8=spvb_ext3(m,m->t_f32,GlslFClamp,
                    spvb_bin(m,SpvOpFMul,m->t_f32,av,spvm_cf(m,8.0f)),
                    spvm_cf(m,0.0f),spvm_cf(m,1.0f));
              uint32_t bb=spvm_id(m);
              { uint32_t ar[]={m->t_f32,bb,fail,spvm_cf(m,1.0f),spvm_cf(m,0.0f)};
                spvm_b(m,SpvOpSelect,ar,5); }
              col=spvb_construct4(m,av,a8,bb,spvm_cf(m,1.0f));
          } else if(g_killvis&&g_killvis!=3){
              uint32_t nan=spvb_un(m,SpvOpIsNan,m->t_bool,av);
              uint32_t mag=spvm_cf4(m,1.0f,0.0f,1.0f,1.0f);
              uint32_t red=spvm_cf4(m,1.0f,0.0f,0.0f,1.0f);
              uint32_t pain=spvm_id(m);
              { uint32_t ar[]={m->t_vf[4],pain,bsplat4(c,nan),red,mag};
                spvm_b(m,SpvOpSelect,ar,5); }
              uint32_t sel=spvm_id(m);
              { uint32_t ar[]={m->t_vf[4],sel,bsplat4(c,fail),pain,col};
                spvm_b(m,SpvOpSelect,ar,5); }
              col=sel;
          } else {
          uint32_t killb=spvm_id(m), contb=spvm_id(m);
          { uint32_t ar[]={contb,0}; spvm_b(m,SpvOpSelectionMerge,ar,2); }
          { uint32_t ar[]={fail,killb,contb}; spvm_b(m,SpvOpBranchConditional,ar,3); }
          { uint32_t ar[]={killb}; spvm_b(m,SpvOpLabel,ar,1); }
          { uint32_t ar[1]; spvm_b(m,SpvOpKill,ar,0); }
          { uint32_t ar[]={contb}; spvm_b(m,SpvOpLabel,ar,1); }
          }
      }
      spvb_store(m,c->v_out,col); }
    if(v_depth){
        uint32_t r1=spvb_load(m,m->t_vf[4],reg_var(c,0,1));
        spvb_store(m,v_depth,spvb_extract(m,m->t_f32,r1,2));
    }
    { uint32_t ar[1]; spvm_b(m,SpvOpReturn,ar,0); }
    { uint32_t ar[1]; spvm_b(m,SpvOpFunctionEnd,ar,0); }

    meta->tex_used=c->tex_used;
    meta->kil=c->kil;
    meta->nopersp_attrs=c->nopersp_attrs;
    meta->nconst=(uint32_t)nimm;
    return spvm_finish(m,c->entry,SpvEMFragment,iface,nif,(p->ctrl&0xe)?1:0,out,cap);
}

uint32_t fp_collect_consts(const uint32_t* words, uint32_t nwords,
                           float (*out)[4], uint32_t cap){
    uint32_t iw=0, n=0;
    while(iw+4<=nwords&&n<=cap){
        FpInstr in;
        int used=fp_decode_instr(words+iw,&in);
        if(in.has_imm){
            if(n>=cap) return n;
            out[n][0]=in.imm[0]; out[n][1]=in.imm[1];
            out[n][2]=in.imm[2]; out[n][3]=in.imm[3];
            n++;
        }
        iw+=(uint32_t)used*4;
        if(in.end) break;
    }
    return n;
}
