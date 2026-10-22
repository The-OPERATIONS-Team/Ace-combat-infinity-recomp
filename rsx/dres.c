#include "spv.h"

int dres_vs(uint32_t* out, int cap){
    SpvMod m; spvm_init(&m);
    uint32_t p_in_i=spvm_ptr(&m,SpvSCInput,m.t_i32);
    uint32_t v_idx=spvm_id(&m);
    { uint32_t a[]={p_in_i,v_idx,SpvSCInput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_idx,SpvDecBuiltIn,42 }; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t t_pv=spvm_id(&m);
    { uint32_t a[]={t_pv,m.t_vf[4],m.t_f32}; spvm_g(&m,SpvOpTypeStruct,a,3); }
    { uint32_t a[]={t_pv,0,SpvDecBuiltIn,SpvBIPosition}; spvm_d(&m,SpvOpMemberDecorate,a,4); }
    { uint32_t a[]={t_pv,1,SpvDecBuiltIn,SpvBIPointSize}; spvm_d(&m,SpvOpMemberDecorate,a,4); }
    { uint32_t a[]={t_pv,SpvDecBlock}; spvm_d(&m,SpvOpDecorate,a,2); }
    uint32_t p_pv=spvm_ptr(&m,SpvSCOutput,t_pv);
    uint32_t v_pv=spvm_id(&m);
    { uint32_t a[]={p_pv,v_pv,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    uint32_t p_out_v4=spvm_ptr(&m,SpvSCOutput,m.t_vf[4]);
    uint32_t v_uv=spvm_id(&m);
    { uint32_t a[]={p_out_v4,v_uv,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_uv,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }

    uint32_t entry=spvm_id(&m);
    { uint32_t a[]={m.t_void,entry,0,m.t_fnvoid}; spvm_b(&m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(&m); uint32_t a[]={lbl}; spvm_b(&m,SpvOpLabel,a,1); }
    uint32_t idx=spvb_load(&m,m.t_i32,v_idx);
    uint32_t i1=spvb_bin(&m,199 ,m.t_i32,idx,spvm_ci(&m,1));
    uint32_t i2=spvb_bin(&m,194 ,m.t_i32,idx,spvm_ci(&m,1));
    uint32_t f1=spvb_un(&m,SpvOpConvertSToF,m.t_f32,i1);
    uint32_t f2=spvb_un(&m,SpvOpConvertSToF,m.t_f32,i2);
    uint32_t x4=spvb_bin(&m,SpvOpFMul,m.t_f32,f1,spvm_cf(&m,4.0f));
    uint32_t y4=spvb_bin(&m,SpvOpFMul,m.t_f32,f2,spvm_cf(&m,4.0f));
    uint32_t x =spvb_bin(&m,SpvOpFSub,m.t_f32,x4,spvm_cf(&m,1.0f));
    uint32_t y =spvb_bin(&m,SpvOpFSub,m.t_f32,y4,spvm_cf(&m,1.0f));
    uint32_t pos=spvb_construct4(&m,x,y,spvm_cf(&m,0.0f),spvm_cf(&m,1.0f));
    { uint32_t ptr=spvm_id(&m);
      uint32_t a[]={spvm_ptr(&m,SpvSCOutput,m.t_vf[4]),ptr,v_pv,spvm_ci(&m,0)};
      spvm_b(&m,SpvOpAccessChain,a,4); spvb_store(&m,ptr,pos); }
    { uint32_t ptr=spvm_id(&m);
      uint32_t a[]={spvm_ptr(&m,SpvSCOutput,m.t_f32),ptr,v_pv,spvm_ci(&m,1)};
      spvm_b(&m,SpvOpAccessChain,a,4); spvb_store(&m,ptr,spvm_cf(&m,1.0f)); }
    uint32_t ux=spvb_bin(&m,SpvOpFAdd,m.t_f32,
                  spvb_bin(&m,SpvOpFMul,m.t_f32,x,spvm_cf(&m,0.5f)),spvm_cf(&m,0.5f));
    uint32_t uy=spvb_bin(&m,SpvOpFAdd,m.t_f32,
                  spvb_bin(&m,SpvOpFMul,m.t_f32,y,spvm_cf(&m,0.5f)),spvm_cf(&m,0.5f));
    spvb_store(&m,v_uv,spvb_construct4(&m,ux,uy,spvm_cf(&m,0.0f),spvm_cf(&m,1.0f)));
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[3]={v_idx,v_pv,v_uv};
    return spvm_finish(&m,entry,SpvEMVertex,iface,3,0,out,cap);
}

int dres_fs(uint32_t* out, int cap, int mode){
    int fixed_point=(mode==1);
    SpvMod m; spvm_init(&m);
    uint32_t p_in=spvm_ptr(&m,SpvSCInput,m.t_vf[4]);
    uint32_t v_uv=spvm_id(&m);
    { uint32_t a[]={p_in,v_uv,SpvSCInput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_uv,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t p_out=spvm_ptr(&m,SpvSCOutput,m.t_vf[4]);
    uint32_t v_out=spvm_id(&m);
    { uint32_t a[]={p_out,v_out,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_out,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t t_img=spvm_id(&m);
    { uint32_t a[]={t_img,m.t_f32,1,0,0,0,1,0}; spvm_g(&m,SpvOpTypeImage,a,8); }
    uint32_t t_simg=spvm_id(&m);
    { uint32_t a[]={t_simg,t_img}; spvm_g(&m,SpvOpTypeSampledImage,a,2); }
    uint32_t p_uc=spvm_ptr(&m,SpvSCUniformConstant,t_simg);
    uint32_t v_img=spvm_id(&m);
    { uint32_t a[]={p_uc,v_img,SpvSCUniformConstant}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_img,SpvDecDescriptorSet,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    { uint32_t a[]={v_img,SpvDecBinding,8}; spvm_d(&m,SpvOpDecorate,a,3); }

    uint32_t entry=spvm_id(&m);
    { uint32_t a[]={m.t_void,entry,0,m.t_fnvoid}; spvm_b(&m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(&m); uint32_t a[]={lbl}; spvm_b(&m,SpvOpLabel,a,1); }
    uint32_t uv4=spvb_load(&m,m.t_vf[4],v_uv);
    uint32_t ux=spvb_extract(&m,m.t_f32,uv4,0), uy=spvb_extract(&m,m.t_f32,uv4,1);
    uint32_t uv=spvm_id(&m);
    { uint32_t a[]={m.t_vf[2],uv,ux,uy}; spvm_b(&m,SpvOpCompositeConstruct,a,4); }
    uint32_t img=spvb_load(&m,t_simg,v_img);
    uint32_t s=spvm_id(&m);
    { uint32_t a[]={m.t_vf[4],s,img,uv}; spvm_b(&m,SpvOpImageSampleImplicitLod,a,4); }
    uint32_t d=spvb_extract(&m,m.t_f32,s,0);
    if(mode==2){
        spvb_store(&m,v_out,spvb_construct4(&m,d,d,d,spvm_cf(&m,1.0f)));
        { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
        { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
        uint32_t iface2[2]={v_uv,v_out};
        return spvm_finish(&m,entry,SpvEMFragment,iface2,2,0,out,cap);
    }
    uint32_t top,hi,lo;
    if(fixed_point){
        uint32_t f24=spvb_ext3(&m,m.t_f32,GlslFClamp,
            spvb_bin(&m,SpvOpFAdd,m.t_f32,
                spvb_bin(&m,SpvOpFMul,m.t_f32,d,spvm_cf(&m,16777215.0f)),
                spvm_cf(&m,0.5f)),
            spvm_cf(&m,0.0f),spvm_cf(&m,16777215.0f));
        uint32_t d24=spvb_un(&m,SpvOpConvertFToS,m.t_i32,f24);
        top=spvb_bin(&m,199 ,m.t_i32,
            spvb_bin(&m,194 ,m.t_i32,d24,spvm_ci(&m,16)),
            spvm_ci(&m,0xff));
        hi=spvb_bin(&m,199,m.t_i32,
            spvb_bin(&m,194,m.t_i32,d24,spvm_ci(&m,8)),spvm_ci(&m,0xff));
        lo=spvb_bin(&m,199,m.t_i32,d24,spvm_ci(&m,0xff));
    } else {
        uint32_t u=spvb_un(&m,124 ,m.t_i32,d);
        top=spvb_bin(&m,199,m.t_i32,
            spvb_bin(&m,194,m.t_i32,u,spvm_ci(&m,23)),spvm_ci(&m,0xff));
        hi=spvb_bin(&m,199,m.t_i32,
            spvb_bin(&m,194,m.t_i32,u,spvm_ci(&m,15)),spvm_ci(&m,0xff));
        lo=spvb_bin(&m,199,m.t_i32,
            spvb_bin(&m,194,m.t_i32,u,spvm_ci(&m,7)),spvm_ci(&m,0xff));
    }
    uint32_t r=spvb_bin(&m,SpvOpFDiv,m.t_f32,
        spvb_un(&m,SpvOpConvertSToF,m.t_f32,top),spvm_cf(&m,255.0f));
    uint32_t g=spvb_bin(&m,SpvOpFDiv,m.t_f32,
        spvb_un(&m,SpvOpConvertSToF,m.t_f32,hi),spvm_cf(&m,255.0f));
    uint32_t b=spvb_bin(&m,SpvOpFDiv,m.t_f32,
        spvb_un(&m,SpvOpConvertSToF,m.t_f32,lo),spvm_cf(&m,255.0f));
    spvb_store(&m,v_out,spvb_construct4(&m,g,b,b,r));
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[2]={v_uv,v_out};
    return spvm_finish(&m,entry,SpvEMFragment,iface,2,0,out,cap);
}
