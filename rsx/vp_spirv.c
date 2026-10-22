#include "vp_spirv.h"
#include <stdlib.h>
#include "vp_decode.h"
#include "spv.h"
#include <stdio.h>
#include <string.h>

#define VP_MAX_PASSES 1024

typedef struct {
    SpvMod m;
    uint32_t p_fn_v4;
    uint32_t v_r[64];
    uint32_t v_o[16];
    uint32_t v_cc[2];
    uint32_t v_a[2];
    uint32_t in_var[16];
    uint32_t ubo;
    uint32_t p_uni_v4;
    uint32_t img_var[4], t_img, t_simg, p_uc_simg;
    uint32_t vtex_used;
    uint32_t entry;
    uint32_t used_attrs, written_outs;
    uint32_t zero4;
    uint32_t v_pc, v_skip, v_iter;
    uint32_t b_true, b_false;
    uint32_t pred, pred4;
    const VpProgram* prog;
} VpCtx;

static uint32_t fnvar(VpCtx* c, uint32_t* slot){
    if(*slot) return *slot;
    return *slot;
}

static uint32_t load_src(VpCtx* c, const VpInstr* in, int slot){
    SpvMod* m=&c->m;
    const VpSrc* s=&in->src[slot];
    uint32_t v;
    switch(s->reg_type){
    case VP_SRC_TEMP:
        v=spvb_load(m,m->t_vf[4],c->v_r[s->tmp_idx&63]);
        break;
    case VP_SRC_INPUT:{
        uint32_t a=in->input_idx&15;
        c->used_attrs|=1u<<a;
        v=spvb_load(m,m->t_vf[4],c->in_var[a]);
        break; }
    case VP_SRC_CONST:{
        uint32_t idx;
        if(in->index_const){
            uint32_t av=spvb_load(m,m->t_vf[4],c->v_a[in->addr_reg1]);
            uint32_t comp=spvb_extract(m,m->t_f32,av,in->addr_swz);
            uint32_t ai=spvb_un(m,SpvOpConvertFToS,m->t_i32,comp);
            idx=spvb_bin(m,SpvOpIAdd,m->t_i32,ai,spvm_ci(m,(int32_t)in->const_idx));
            idx=spvb_ext3(m,m->t_i32,GlslFClamp+2,idx,spvm_ci(m,0),
                          spvm_ci(m,(int32_t)c->prog->nconst-1));
        } else idx=spvm_ci(m,(int32_t)in->const_idx);
        uint32_t ptr=spvm_id(m);
        { uint32_t a_[]={c->p_uni_v4,ptr,c->ubo,spvm_ci(m,0),idx};
          spvm_b(m,SpvOpAccessChain,a_,5); }
        v=spvb_load(m,m->t_vf[4],ptr);
        break; }
    default:
        v=c->zero4; break;
    }
    v=spvb_shuffle4(m,v,s->swz);
    if(s->abs) v=spvb_ext1(m,m->t_vf[4],GlslFAbs,v);
    if(s->neg) v=spvb_un(m,SpvOpFNegate,m->t_vf[4],v);
    return v;
}

static uint32_t mask_merge(VpCtx* c, uint32_t oldv, uint32_t newv, uint8_t mask){
    if(mask==0xf) return newv;
    SpvMod* m=&c->m;
    uint32_t id=spvm_id(m);
    uint32_t a[8]={m->t_vf[4],id,oldv,newv,
        (mask&8)?4u:0u,(mask&4)?5u:1u,(mask&2)?6u:2u,(mask&1)?7u:3u};
    spvm_b(m,SpvOpVectorShuffle,a,8);
    return id;
}

static uint32_t cond_gate(VpCtx* c, const VpInstr* in){
    if(!in->cond_test) return 0;
    SpvMod* m=&c->m;
    uint32_t cc=spvb_load(m,m->t_vf[4],c->v_cc[in->cond_reg1]);
    uint8_t sw[4]={in->cond_swz[0],in->cond_swz[1],in->cond_swz[2],in->cond_swz[3]};
    cc=spvb_shuffle4(m,cc,sw);
    uint16_t op; int swap=0;
    switch(in->cond){
    case 1: op=SpvOpFOrdLessThan; break;
    case 2: op=SpvOpFOrdEqual; break;
    case 3: op=SpvOpFOrdLessThanEqual; break;
    case 4: op=SpvOpFOrdGreaterThan; break;
    case 5: op=SpvOpFUnordNotEqual; break;
    case 6: op=SpvOpFOrdGreaterThanEqual; break;
    case 7: return 0;
    default: op=SpvOpFOrdEqual; swap=1; break;
    }
    (void)swap;
    uint32_t bv=spvb_bin(m,op,c->m.t_bv4,cc,c->zero4);
    if(in->cond==0){
        bv=spvb_bin(m,SpvOpFUnordNotEqual,c->m.t_bv4,c->zero4,c->zero4);
    }
    return bv;
}

static uint32_t branch_cond(VpCtx* c, const VpInstr* in){
    SpvMod* m=&c->m;
    if(in->cond==7) return 0;
    if(in->cond==0) return c->b_false;
    uint32_t cc=spvb_load(m,m->t_vf[4],c->v_cc[in->cond_reg1]);
    cc=spvb_shuffle4(m,cc,in->cond_swz);
    uint32_t x=spvb_extract(m,m->t_f32,cc,0);
    uint16_t op;
    switch(in->cond){
    case 1: op=SpvOpFOrdLessThan; break;
    case 2: op=SpvOpFOrdEqual; break;
    case 3: op=SpvOpFOrdLessThanEqual; break;
    case 4: op=SpvOpFOrdGreaterThan; break;
    case 5: op=SpvOpFUnordNotEqual; break;
    default:op=SpvOpFOrdGreaterThanEqual; break;
    }
    return spvb_bin(m,op,m->t_bool,x,spvm_cf(m,0.0f));
}

static uint32_t pred_merge(VpCtx* c, uint32_t newv, uint32_t oldv){
    if(!c->pred4) return newv;
    return spvb_select4(&c->m,c->pred4,newv,oldv);
}

static void store_masked(VpCtx* c, uint32_t dst_var, uint32_t val, uint8_t mask,
                         uint32_t gate){
    SpvMod* m=&c->m;
    uint32_t oldv=spvb_load(m,m->t_vf[4],dst_var);
    if(gate) val=spvb_select4(m,gate,val,oldv);
    spvb_store(m,dst_var,pred_merge(c,mask_merge(c,oldv,val,mask),oldv));
}

static void write_dst(VpCtx* c, const VpInstr* in, uint32_t val, uint8_t mask,
                      int is_sca){
    SpvMod* m=&c->m;
    if((in->vec_op==VPV_ARL||in->vec_op==VPV_ARR)&&!is_sca){
        uint32_t fl=spvb_ext1(m,m->t_vf[4],GlslFloor,val);
        uint32_t oldv=spvb_load(m,m->t_vf[4],c->v_a[in->addr_reg1]);
        spvb_store(m,c->v_a[in->addr_reg1],
                   pred_merge(c,mask_merge(c,oldv,fl,mask),oldv));
        return;
    }
    if(in->cond_upd0||in->cond_upd1){
        uint32_t oldc=spvb_load(m,m->t_vf[4],c->v_cc[in->cond_reg1]);
        spvb_store(m,c->v_cc[in->cond_reg1],
                   pred_merge(c,mask_merge(c,oldc,val,mask),oldc));
    }
    if(in->saturate) val=spvb_ext3(m,m->t_vf[4],GlslFClamp,val,
                                   c->zero4,spvm_cf4(m,1,1,1,1));
    uint32_t gate=cond_gate(c,in);
    uint8_t tmp = is_sca ? in->sca_dst_tmp : in->dst_tmp;
    int to_out = is_sca ? !in->vec_result : (in->vec_result!=0);
    if(to_out && in->out_reg<16){
        c->written_outs|=1u<<in->out_reg;
        store_masked(c,c->v_o[in->out_reg],val,mask,gate);
    }
    if(tmp!=0x3f) store_masked(c,c->v_r[tmp&63],val,mask,gate);
}

static uint32_t dot_helper(SpvMod* m, uint32_t a, uint32_t b, int ncomp){
    if(ncomp==4){
        uint32_t d=spvm_id(m);
        { uint32_t ar[]={m->t_f32,d,a,b}; spvm_b(m,SpvOpDot,ar,4); }
        return d;
    }
    uint32_t a3=spvm_id(m),b3=spvm_id(m);
    { uint32_t ar[]={m->t_vf[3],a3,a,a,0,1,2}; spvm_b(m,SpvOpVectorShuffle,ar,7); }
    { uint32_t ar[]={m->t_vf[3],b3,b,b,0,1,2}; spvm_b(m,SpvOpVectorShuffle,ar,7); }
    uint32_t d=spvm_id(m);
    { uint32_t ar[]={m->t_f32,d,a3,b3}; spvm_b(m,SpvOpDot,ar,4); }
    return d;
}
static uint32_t cmp_set(VpCtx* c, uint16_t op, uint32_t a, uint32_t b){
    SpvMod* m=&c->m;
    uint32_t bv=spvb_bin(m,op,m->t_bv4,a,b);
    return spvb_select4(m,bv,spvm_cf4(m,1,1,1,1),c->zero4);
}

int vp_translate(const VpProgram* p, uint32_t* out, int cap,
                 uint32_t* used_attrs, uint32_t* written_outs,
                 uint32_t* vtex_used){
    static VpCtx ctx;
    VpCtx* c=&ctx;
    memset(c,0,sizeof *c);
    c->prog=p;
    SpvMod* m=&c->m;
    spvm_init(m);
    c->p_fn_v4=spvm_ptr(m,SpvSCFunction,m->t_vf[4]);

    uint32_t attrs=0, outs=0; int nins=0; uint32_t vtex=0;
    VpInstr dec[512];
    for(uint32_t i=p->start;i<512;i++){
        vp_decode_instr(p->instr[i],&dec[nins]);
        VpInstr* in=&dec[nins]; nins++;
        switch(in->sca_op){
        case VPS_BRA: case VPS_CAL: case VPS_CLI: case VPS_RET:
        case VPS_BRB: case VPS_CLB: case VPS_PSH: case VPS_POP:
            fprintf(stderr,"[VP] unsupported SCA control op %u at slot %u - skip program\n",
                    in->sca_op,i);
            return 0;
        }
        if(in->vec_op==VPV_TXL) vtex|=1u<<(in->tex_unit&3);
        for(int s2=0;s2<3;s2++) if(in->src[s2].reg_type==VP_SRC_INPUT)
            attrs|=1u<<(in->input_idx&15);
        if(in->end) break;
        if(nins==512) break;
    }

    static int br_tgt[512];
    int has_branch=0, needs_loop=0;
    for(int i=0;i<nins;i++){
        br_tgt[i]=-1;
        if(dec[i].sca_op!=VPS_BRI) continue;
        long t=(long)dec[i].iaddr-(long)p->start;
        if(t<0||t>nins){
            fprintf(stderr,"[VP] BRI target slot %u outside program [%u,%u) - "
                    "skip program\n",dec[i].iaddr,p->start,p->start+(unsigned)nins);
            return 0;
        }
        br_tgt[i]=(int)t; has_branch=1;
        if(t<=i) needs_loop=1;
    }
    if(has_branch){
        static uint32_t seen[32]; static int nseen;
        uint32_t hsh=2166136261u;
        for(int i=0;i<nins;i++) for(int k=0;k<4;k++){
            uint32_t v=p->instr[p->start+i][k];
            for(int b=0;b<4;b++){ hsh^=(v>>(b*8))&0xff; hsh*=16777619u; } }
        int isnew=1;
        for(int i=0;i<nseen;i++) if(seen[i]==hsh){ isnew=0; break; }
        if(isnew&&nseen<32){
            seen[nseen++]=hsh;
            char pth[64]; snprintf(pth,sizeof pth,"out/vpbr_%08x.bin",hsh);
            FILE* f=fopen(pth,"wb");
            if(f){ fwrite(&p->instr[p->start][0],16,(size_t)nins,f); fclose(f); }
            fprintf(stderr,"[VP] branching program %08x start=%u nins=%d loop=%d",
                    hsh,p->start,nins,needs_loop);
            for(int i=0;i<nins;i++) if(br_tgt[i]>=0)
                fprintf(stderr," %d->%d",i,br_tgt[i]);
            fprintf(stderr,"\n");
        }
    }

    uint32_t iface[64]; int nif=0;
    uint32_t p_in_v4=spvm_ptr(m,SpvSCInput,m->t_vf[4]);
    uint32_t p_out_v4=spvm_ptr(m,SpvSCOutput,m->t_vf[4]);
    for(int a=0;a<16;a++) if(attrs&(1u<<a)){
        uint32_t v=spvm_id(m);
        { uint32_t ar[]={p_in_v4,v,SpvSCInput}; spvm_g(m,SpvOpVariable,ar,3); }
        { uint32_t ar[]={v,SpvDecLocation,(uint32_t)a}; spvm_d(m,SpvOpDecorate,ar,3); }
        c->in_var[a]=v; iface[nif++]=v;
    }
    uint32_t nconst=p->nconst? p->nconst:468;
    uint32_t t_arr=spvm_id(m);
    { uint32_t ar[]={t_arr,m->t_vf[4],spvm_cu(m,nconst)}; spvm_g(m,SpvOpTypeArray,ar,3); }
    { uint32_t ar[]={t_arr,SpvDecArrayStride,16}; spvm_d(m,SpvOpDecorate,ar,3); }
    uint32_t t_blk=spvm_id(m);
    { uint32_t ar[]={t_blk,t_arr}; spvm_g(m,SpvOpTypeStruct,ar,2); }
    { uint32_t ar[]={t_blk,0,SpvDecOffset,0}; spvm_d(m,SpvOpMemberDecorate,ar,4); }
    { uint32_t ar[]={t_blk,SpvDecBlock}; spvm_d(m,SpvOpDecorate,ar,2); }
    uint32_t p_blk=spvm_ptr(m,SpvSCUniform,t_blk);
    c->ubo=spvm_id(m);
    { uint32_t ar[]={p_blk,c->ubo,SpvSCUniform}; spvm_g(m,SpvOpVariable,ar,3); }
    { uint32_t ar[]={c->ubo,SpvDecDescriptorSet,0}; spvm_d(m,SpvOpDecorate,ar,3); }
    { uint32_t ar[]={c->ubo,SpvDecBinding,0}; spvm_d(m,SpvOpDecorate,ar,3); }
    c->p_uni_v4=spvm_ptr(m,SpvSCUniform,m->t_vf[4]);
    if(vtex){
        c->t_img=spvm_id(m);
        { uint32_t ar[]={c->t_img,m->t_f32,1 ,0,0,0,1,0}; spvm_g(m,SpvOpTypeImage,ar,8); }
        c->t_simg=spvm_id(m);
        { uint32_t ar[]={c->t_simg,c->t_img}; spvm_g(m,SpvOpTypeSampledImage,ar,2); }
        c->p_uc_simg=spvm_ptr(m,SpvSCUniformConstant,c->t_simg);
        for(int u=0;u<4;u++) if(vtex&(1u<<u)){
            uint32_t v=spvm_id(m);
            { uint32_t ar[]={c->p_uc_simg,v,SpvSCUniformConstant}; spvm_g(m,SpvOpVariable,ar,3); }
            { uint32_t ar[]={v,SpvDecDescriptorSet,0}; spvm_d(m,SpvOpDecorate,ar,3); }
            { uint32_t ar[]={v,SpvDecBinding,4u+(uint32_t)u}; spvm_d(m,SpvOpDecorate,ar,3); }
            c->img_var[u]=v;
        }
    }
    c->vtex_used=vtex;

    uint32_t t_pv=spvm_id(m);
    { uint32_t ar[]={t_pv,m->t_vf[4],m->t_f32}; spvm_g(m,SpvOpTypeStruct,ar,3); }
    { uint32_t ar[]={t_pv,0,SpvDecBuiltIn,SpvBIPosition}; spvm_d(m,SpvOpMemberDecorate,ar,4); }
    { uint32_t ar[]={t_pv,1,SpvDecBuiltIn,SpvBIPointSize}; spvm_d(m,SpvOpMemberDecorate,ar,4); }
    { uint32_t ar[]={t_pv,SpvDecBlock}; spvm_d(m,SpvOpDecorate,ar,2); }
    uint32_t p_pv=spvm_ptr(m,SpvSCOutput,t_pv);
    uint32_t v_pv=spvm_id(m);
    { uint32_t ar[]={p_pv,v_pv,SpvSCOutput}; spvm_g(m,SpvOpVariable,ar,3); }
    iface[nif++]=v_pv;

    static const int8_t OUT_LOC[16]={-1,0,1,13,14,2,12,3,4,5,6,7,8,9,10,11};
    uint32_t out_var[16]={0};
    for(int i2=0;i2<nins;i2++){
        const VpInstr* in=&dec[i2];
        if(in->vec_op&&in->vec_result&&in->out_reg<16) outs|=1u<<in->out_reg;
        if(in->sca_op&&!in->vec_result&&in->out_reg<16&&
           in->sca_op!=VPS_NOP&&in->sca_op!=VPS_BRI) outs|=1u<<in->out_reg;
        if(in->end) break;
    }
    for(int o=1;o<16;o++){
        int loc=OUT_LOC[o];
        if(loc<0) continue;
        uint32_t v=spvm_id(m);
        { uint32_t ar[]={p_out_v4,v,SpvSCOutput}; spvm_g(m,SpvOpVariable,ar,3); }
        { uint32_t ar[]={v,SpvDecLocation,(uint32_t)loc}; spvm_d(m,SpvOpDecorate,ar,3); }
        out_var[o]=v; iface[nif++]=v;
    }

    c->entry=spvm_id(m);
    { uint32_t ar[]={m->t_void,c->entry,0,m->t_fnvoid}; spvm_b(m,SpvOpFunction,ar,4); }
    { uint32_t lbl=spvm_id(m); uint32_t ar[]={lbl}; spvm_b(m,SpvOpLabel,ar,1); }
    for(int r=0;r<64;r++){ c->v_r[r]=spvm_id(m);
        uint32_t ar[]={c->p_fn_v4,c->v_r[r],SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3); }
    for(int o=0;o<16;o++){ c->v_o[o]=spvm_id(m);
        uint32_t ar[]={c->p_fn_v4,c->v_o[o],SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3); }
    for(int i2=0;i2<2;i2++){ c->v_cc[i2]=spvm_id(m); c->v_a[i2]=spvm_id(m);
        uint32_t ar[]={c->p_fn_v4,c->v_cc[i2],SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3);
        uint32_t ar2[]={c->p_fn_v4,c->v_a[i2],SpvSCFunction}; spvm_b(m,SpvOpVariable,ar2,3); }
    if(has_branch){
        uint32_t p_fn_i=spvm_ptr(m,SpvSCFunction,m->t_i32);
        uint32_t p_fn_b=spvm_ptr(m,SpvSCFunction,m->t_bool);
        c->v_pc=spvm_id(m);
        { uint32_t ar[]={p_fn_i,c->v_pc,SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3); }
        c->v_skip=spvm_id(m);
        { uint32_t ar[]={p_fn_b,c->v_skip,SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3); }
        c->v_iter=spvm_id(m);
        { uint32_t ar[]={p_fn_i,c->v_iter,SpvSCFunction}; spvm_b(m,SpvOpVariable,ar,3); }
        c->b_true=spvm_id(m);
        { uint32_t ar[]={m->t_bool,c->b_true}; spvm_g(m,SpvOpConstantTrue,ar,2); }
        c->b_false=spvm_id(m);
        { uint32_t ar[]={m->t_bool,c->b_false}; spvm_g(m,SpvOpConstantFalse,ar,2); }
    }
    c->zero4=spvm_cf4(m,0,0,0,0);
    uint32_t odef=spvm_cf4(m,0,0,0,1);
    for(int r=0;r<64;r++) spvb_store(m,c->v_r[r],c->zero4);
    for(int o=0;o<16;o++) spvb_store(m,c->v_o[o],odef);
    spvb_store(m,c->v_cc[0],c->zero4); spvb_store(m,c->v_cc[1],c->zero4);
    spvb_store(m,c->v_a[0],c->zero4);  spvb_store(m,c->v_a[1],c->zero4);

    uint32_t lbl_head=0,lbl_body=0,lbl_cont=0,lbl_merge=0;
    if(has_branch){
        spvb_store(m,c->v_pc,spvm_ci(m,0));
        spvb_store(m,c->v_skip,c->b_false);
        if(needs_loop){
            spvb_store(m,c->v_iter,spvm_ci(m,0));
            lbl_head=spvm_id(m); lbl_body=spvm_id(m);
            lbl_cont=spvm_id(m); lbl_merge=spvm_id(m);
            { uint32_t ar[]={lbl_head};  spvm_b(m,SpvOpBranch,ar,1); }
            { uint32_t ar[]={lbl_head};  spvm_b(m,SpvOpLabel,ar,1); }
            { uint32_t ar[]={lbl_merge,lbl_cont,0}; spvm_b(m,SpvOpLoopMerge,ar,3); }
            { uint32_t ar[]={lbl_body};  spvm_b(m,SpvOpBranch,ar,1); }
            { uint32_t ar[]={lbl_body};  spvm_b(m,SpvOpLabel,ar,1); }
            spvb_store(m,c->v_skip,c->b_false);
        }
    }

    for(int i2=0;i2<nins;i2++){
        const VpInstr* in=&dec[i2];
        c->pred=0; c->pred4=0;
        if(has_branch){
            uint32_t pc=spvb_load(m,m->t_i32,c->v_pc);
            uint32_t act=spvb_bin(m,SpvOpSLessThanEqual,m->t_bool,pc,spvm_ci(m,i2));
            if(needs_loop){
                uint32_t sk=spvb_load(m,m->t_bool,c->v_skip);
                act=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,act,
                             spvb_un(m,SpvOpLogicalNot,m->t_bool,sk));
            }
            c->pred=act;
            c->pred4=spvm_id(m);
            { uint32_t ar[]={m->t_bv4,c->pred4,act,act,act,act};
              spvm_b(m,SpvOpCompositeConstruct,ar,6); }
        }
        if(in->sca_op==VPS_BRI){
            uint32_t taken=c->pred?c->pred:c->b_true;
            uint32_t cnd=branch_cond(c,in);
            if(cnd) taken=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,taken,cnd);
            uint32_t pc=spvb_load(m,m->t_i32,c->v_pc);
            uint32_t np=spvm_id(m);
            { uint32_t ar[]={m->t_i32,np,taken,spvm_ci(m,br_tgt[i2]),pc};
              spvm_b(m,SpvOpSelect,ar,5); }
            spvb_store(m,c->v_pc,np);
            if(br_tgt[i2]<=i2){
                uint32_t sk=spvb_load(m,m->t_bool,c->v_skip);
                uint32_t ns=spvm_id(m);
                { uint32_t ar[]={m->t_bool,ns,taken,c->b_true,sk};
                  spvm_b(m,SpvOpSelect,ar,5); }
                spvb_store(m,c->v_skip,ns);
            }
        }
        if(in->vec_op){
            uint32_t r=0, a,b,d;
            switch(in->vec_op){
            case VPV_MOV: case VPV_ARL: case VPV_ARR:
                r=load_src(c,in,0);
                if(in->vec_op==VPV_ARR) r=spvb_ext1(m,m->t_vf[4],GlslFloor,
                    spvb_bin(m,SpvOpFAdd,m->t_vf[4],r,spvm_cf4(m,0.5f,0.5f,0.5f,0.5f)));
                break;
            case VPV_MUL: a=load_src(c,in,0); b=load_src(c,in,1);
                r=spvb_bin(m,SpvOpFMul,m->t_vf[4],a,b); break;
            case VPV_ADD: a=load_src(c,in,0); b=load_src(c,in,2);
                r=spvb_bin(m,SpvOpFAdd,m->t_vf[4],a,b); break;
            case VPV_MAD: a=load_src(c,in,0); b=load_src(c,in,1); d=load_src(c,in,2);
                r=spvb_bin(m,SpvOpFAdd,m->t_vf[4],
                           spvb_bin(m,SpvOpFMul,m->t_vf[4],a,b),d); break;
            case VPV_DP3: a=load_src(c,in,0); b=load_src(c,in,1);
                r=spvb_splat4(m,dot_helper(m,a,b,3)); break;
            case VPV_DPH:{ a=load_src(c,in,0); b=load_src(c,in,1);
                uint32_t d3=dot_helper(m,a,b,3);
                uint32_t bw=spvb_extract(m,m->t_f32,b,3);
                r=spvb_splat4(m,spvb_bin(m,SpvOpFAdd,m->t_f32,d3,bw)); break; }
            case VPV_DP4: a=load_src(c,in,0); b=load_src(c,in,1);
                r=spvb_splat4(m,dot_helper(m,a,b,4)); break;
            case VPV_DST:{ a=load_src(c,in,0); b=load_src(c,in,1);
                uint32_t ay=spvb_extract(m,m->t_f32,a,1), by=spvb_extract(m,m->t_f32,b,1);
                uint32_t az=spvb_extract(m,m->t_f32,a,2), bw=spvb_extract(m,m->t_f32,b,3);
                r=spvb_construct4(m,spvm_cf(m,1.0f),
                                  spvb_bin(m,SpvOpFMul,m->t_f32,ay,by),az,bw); break; }
            case VPV_MIN: a=load_src(c,in,0); b=load_src(c,in,1);
                r=spvb_ext2(m,m->t_vf[4],GlslFMin,a,b); break;
            case VPV_MAX: a=load_src(c,in,0); b=load_src(c,in,1);
                r=spvb_ext2(m,m->t_vf[4],GlslFMax,a,b); break;
            case VPV_SLT: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFOrdLessThan,a,b); break;
            case VPV_SGE: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFOrdGreaterThanEqual,a,b); break;
            case VPV_SEQ: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFOrdEqual,a,b); break;
            case VPV_SGT: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFOrdGreaterThan,a,b); break;
            case VPV_SLE: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFOrdLessThanEqual,a,b); break;
            case VPV_SNE: a=load_src(c,in,0); b=load_src(c,in,1);
                r=cmp_set(c,SpvOpFUnordNotEqual,a,b); break;
            case VPV_SFL: r=c->zero4; break;
            case VPV_STR: r=spvm_cf4(m,1,1,1,1); break;
            case VPV_FRC: r=spvb_ext1(m,m->t_vf[4],GlslFract,load_src(c,in,0)); break;
            case VPV_FLR: r=spvb_ext1(m,m->t_vf[4],GlslFloor,load_src(c,in,0)); break;
            case VPV_SSG: r=spvb_ext1(m,m->t_vf[4],GlslFSign,load_src(c,in,0)); break;
            case VPV_TXL:{
                uint32_t coord=load_src(c,in,0);
                uint32_t u2=in->tex_unit&3;
                uint32_t img=spvb_load(m,c->t_simg,c->img_var[u2]);
                uint32_t cx=spvb_extract(m,m->t_f32,coord,0);
                uint32_t cy=spvb_extract(m,m->t_f32,coord,1);
                uint32_t lod=spvb_extract(m,m->t_f32,coord,3);
                uint32_t c2=spvm_id(m);
                { uint32_t ar[]={m->t_vf[2],c2,cx,cy}; spvm_b(m,SpvOpCompositeConstruct,ar,4); }
                { static int th=-1;
                  if(th<0) th=getenv("PS3_RSX_TXLHALF")?1:0;
                  if(th){
                    spvm_cap(m,SpvCapImageQuery);
                    uint32_t im=spvm_id(m);
                    { uint32_t a2[]={c->t_img,im,img}; spvm_b(m,SpvOpImage,a2,3); }
                    uint32_t t_v2i=spvm_id(m);
                    { uint32_t a2[]={t_v2i,m->t_i32,2}; spvm_g(m,SpvOpTypeVector,a2,3); }
                    uint32_t szi=spvm_id(m);
                    { uint32_t a2[]={t_v2i,szi,im,spvm_ci(m,0)};
                      spvm_b(m,SpvOpImageQuerySizeLod,a2,4); }
                    uint32_t sz=spvb_un(m,SpvOpConvertSToF,m->t_vf[2],szi);
                    uint32_t halfc=spvm_id(m);
                    { uint32_t a2[]={m->t_vf[2],halfc,spvm_cf(m,0.5f),spvm_cf(m,0.5f)};
                      spvm_b(m,SpvOpCompositeConstruct,a2,4); }
                    uint32_t bias=spvb_bin(m,SpvOpFDiv,m->t_vf[2],halfc,sz);
                    c2=spvb_bin(m,SpvOpFAdd,m->t_vf[2],c2,bias);
                  } }
                r=spvm_id(m);
                { uint32_t ar[]={m->t_vf[4],r,img,c2,2 ,lod};
                  spvm_b(m,SpvOpImageSampleExplicitLod,ar,6); }
                break; }
            default:
                fprintf(stderr,"[VP] unsupported VEC op %u - skip program\n",in->vec_op);
                return 0;
            }
            write_dst(c,in,r,in->vec_mask,0);
        }
        if(in->sca_op&&in->sca_op!=VPS_BRI){
            uint32_t sv=0, r=0;
            if(in->sca_op!=VPS_NOP){
                sv=load_src(c,in,2);
                sv=spvb_extract(m,m->t_f32,sv,0);
            }
            switch(in->sca_op){
            case VPS_NOP: break;
            case VPS_MOV: r=sv; break;
            case VPS_RCP: case VPS_RCC:
                r=spvb_bin(m,SpvOpFDiv,m->t_f32,spvm_cf(m,1.0f),sv); break;
            case VPS_RSQ:
                r=spvb_ext1(m,m->t_f32,GlslInverseSqrt,
                            spvb_ext1(m,m->t_f32,GlslFAbs,sv)); break;
            case VPS_EXP: case VPS_EX2:
                r=spvb_ext1(m,m->t_f32,GlslExp2,sv); break;
            case VPS_LOG: case VPS_LG2:
                r=spvb_ext1(m,m->t_f32,GlslLog2,
                            spvb_ext1(m,m->t_f32,GlslFAbs,sv)); break;
            case VPS_SIN: r=spvb_ext1(m,m->t_f32,GlslSin,sv); break;
            case VPS_COS: r=spvb_ext1(m,m->t_f32,GlslCos,sv); break;
            case VPS_LIT:{
                uint32_t full=load_src(c,in,2);
                uint32_t tx=spvb_extract(m,m->t_f32,full,0);
                uint32_t ty=spvb_extract(m,m->t_f32,full,1);
                uint32_t tw=spvb_extract(m,m->t_f32,full,3);
                uint32_t mx=spvb_ext2(m,m->t_f32,GlslFMax,tx,spvm_cf(m,0.0f));
                uint32_t lg=spvb_ext1(m,m->t_f32,GlslLog2,
                             spvb_ext2(m,m->t_f32,GlslFMax,ty,spvm_cf(m,0.0f)));
                uint32_t pw=spvb_ext1(m,m->t_f32,GlslExp2,
                             spvb_bin(m,SpvOpFMul,m->t_f32,tw,lg));
                uint32_t gt=spvb_bin(m,SpvOpFOrdGreaterThan,m->t_bool,tx,spvm_cf(m,0.0f));
                uint32_t z=spvm_cf(m,0.0f);
                uint32_t sel=spvm_id(m);
                { uint32_t ar[]={m->t_f32,sel,gt,pw,z}; spvm_b(m,SpvOpSelect,ar,5); }
                uint32_t one=spvm_cf(m,1.0f);
                uint32_t q=spvb_construct4(m,one,mx,sel,one);
                write_dst(c,in,q,in->sca_mask,1);
                r=0; sv=0;
                goto sca_done;
            }
            default:
                fprintf(stderr,"[VP] unsupported SCA op %u - skip program\n",in->sca_op);
                return 0;
            }
            if(in->sca_op!=VPS_NOP) write_dst(c,in,spvb_splat4(m,r),in->sca_mask,1);
            sca_done:;
        }
        if(in->end) break;
    }

    if(needs_loop){
        { uint32_t ar[]={lbl_cont};  spvm_b(m,SpvOpBranch,ar,1); }
        { uint32_t ar[]={lbl_cont};  spvm_b(m,SpvOpLabel,ar,1); }
        uint32_t it=spvb_bin(m,SpvOpIAdd,m->t_i32,
                             spvb_load(m,m->t_i32,c->v_iter),spvm_ci(m,1));
        spvb_store(m,c->v_iter,it);
        uint32_t again=spvb_bin(m,SpvOpLogicalAnd,m->t_bool,
            spvb_load(m,m->t_bool,c->v_skip),
            spvb_bin(m,SpvOpSLessThan,m->t_bool,it,spvm_ci(m,VP_MAX_PASSES)));
        { uint32_t ar[]={again,lbl_head,lbl_merge};
          spvm_b(m,SpvOpBranchConditional,ar,3); }
        { uint32_t ar[]={lbl_merge}; spvm_b(m,SpvOpLabel,ar,1); }
    }

    { uint32_t pos=spvb_load(m,m->t_vf[4],c->v_o[0]);
      uint32_t ptr=spvm_id(m);
      uint32_t ar[]={spvm_ptr(m,SpvSCOutput,m->t_vf[4]),ptr,v_pv,spvm_ci(m,0)};
      spvm_b(m,SpvOpAccessChain,ar,4);
      spvb_store(m,ptr,pos); }
    { float pmax=63.0f;
      { static float e=-1.0f;
        if(e<0.0f){ const char* s=getenv("PS3_RSX_PSIZEMAX");
                    e=s?(float)atof(s):63.0f; if(e<=0.0f) e=63.0f; }
        pmax=e; }
      uint32_t ps = (outs&(1u<<6))
          ? spvb_extract(m,m->t_f32,spvb_load(m,m->t_vf[4],c->v_o[6]),0)
          : spvm_cf(m,1.0f);
      ps=spvb_ext3(m,m->t_f32,GlslFClamp,ps,spvm_cf(m,1.0f),spvm_cf(m,pmax));
      uint32_t ptr=spvm_id(m);
      uint32_t ar[]={spvm_ptr(m,SpvSCOutput,m->t_f32),ptr,v_pv,spvm_ci(m,1)};
      spvm_b(m,SpvOpAccessChain,ar,4);
      spvb_store(m,ptr,ps); }
    for(int o=1;o<16;o++) if(out_var[o]){
        uint32_t val=spvb_load(m,m->t_vf[4],c->v_o[o]);
        spvb_store(m,out_var[o],val);
    }

    { uint32_t ar[1]; spvm_b(m,SpvOpReturn,ar,0); }
    { uint32_t ar[1]; spvm_b(m,SpvOpFunctionEnd,ar,0); }

    *used_attrs=attrs|c->used_attrs;
    *written_outs=outs;
    *vtex_used=vtex;
    return spvm_finish(m,c->entry,SpvEMVertex,iface,nif,0,out,cap);
}
