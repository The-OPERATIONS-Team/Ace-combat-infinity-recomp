#include "spv.h"
#include <stdio.h>

int dbg_flat_fs(uint32_t* out, int cap){
    SpvMod m; spvm_init(&m);
    uint32_t p_out=spvm_ptr(&m,SpvSCOutput,m.t_vf[4]);
    uint32_t v_out=spvm_id(&m);
    { uint32_t a[]={p_out,v_out,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_out,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t red=spvm_cf4(&m,1.0f,0.0f,0.0f,1.0f);
    uint32_t entry=spvm_id(&m);
    { uint32_t a[]={m.t_void,entry,0,m.t_fnvoid}; spvm_b(&m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(&m); uint32_t a[]={lbl}; spvm_b(&m,SpvOpLabel,a,1); }
    spvb_store(&m,v_out,red);
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[1]={v_out};
    return spvm_finish(&m,entry,SpvEMFragment,iface,1,0,out,cap);
}

int dbg_passthru_vs(uint32_t* out, int cap){
    SpvMod m; spvm_init(&m);
    uint32_t p_in=spvm_ptr(&m,SpvSCInput,m.t_vf[4]);
    uint32_t v_in=spvm_id(&m);
    { uint32_t a[]={p_in,v_in,SpvSCInput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_in,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t t_pv=spvm_id(&m);
    { uint32_t a[]={t_pv,m.t_vf[4],m.t_f32}; spvm_g(&m,SpvOpTypeStruct,a,3); }
    { uint32_t a[]={t_pv,0,SpvDecBuiltIn,SpvBIPosition}; spvm_d(&m,SpvOpMemberDecorate,a,4); }
    { uint32_t a[]={t_pv,1,SpvDecBuiltIn,SpvBIPointSize}; spvm_d(&m,SpvOpMemberDecorate,a,4); }
    { uint32_t a[]={t_pv,SpvDecBlock}; spvm_d(&m,SpvOpDecorate,a,2); }
    uint32_t p_pv=spvm_ptr(&m,SpvSCOutput,t_pv);
    uint32_t v_pv=spvm_id(&m);
    { uint32_t a[]={p_pv,v_pv,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    uint32_t entry=spvm_id(&m);
    { uint32_t a[]={m.t_void,entry,0,m.t_fnvoid}; spvm_b(&m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(&m); uint32_t a[]={lbl}; spvm_b(&m,SpvOpLabel,a,1); }
    uint32_t v=spvb_load(&m,m.t_vf[4],v_in);
    uint32_t x=spvb_extract(&m,m.t_f32,v,0), y=spvb_extract(&m,m.t_f32,v,1);
    uint32_t pos=spvb_construct4(&m,x,y,spvm_cf(&m,0.0f),spvm_cf(&m,1.0f));
    { uint32_t ptr=spvm_id(&m);
      uint32_t a[]={spvm_ptr(&m,SpvSCOutput,m.t_vf[4]),ptr,v_pv,spvm_ci(&m,0)};
      spvm_b(&m,SpvOpAccessChain,a,4);
      spvb_store(&m,ptr,pos); }
    { uint32_t ptr=spvm_id(&m);
      uint32_t a[]={spvm_ptr(&m,SpvSCOutput,m.t_f32),ptr,v_pv,spvm_ci(&m,1)};
      spvm_b(&m,SpvOpAccessChain,a,4);
      spvb_store(&m,ptr,spvm_cf(&m,1.0f)); }
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[2]={v_in,v_pv};
    return spvm_finish(&m,entry,SpvEMVertex,iface,2,0,out,cap);
}

int dbg_uv_fs(uint32_t* out, int cap){
    SpvMod m; spvm_init(&m);
    uint32_t p_in=spvm_ptr(&m,SpvSCInput,m.t_vf[4]);
    uint32_t v_in=spvm_id(&m);
    { uint32_t a[]={p_in,v_in,SpvSCInput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_in,SpvDecLocation,3}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t p_out=spvm_ptr(&m,SpvSCOutput,m.t_vf[4]);
    uint32_t v_out=spvm_id(&m);
    { uint32_t a[]={p_out,v_out,SpvSCOutput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_out,SpvDecLocation,0}; spvm_d(&m,SpvOpDecorate,a,3); }
    uint32_t entry=spvm_id(&m);
    { uint32_t a[]={m.t_void,entry,0,m.t_fnvoid}; spvm_b(&m,SpvOpFunction,a,4); }
    { uint32_t lbl=spvm_id(&m); uint32_t a[]={lbl}; spvm_b(&m,SpvOpLabel,a,1); }
    uint32_t v=spvb_load(&m,m.t_vf[4],v_in);
    uint32_t x=spvb_extract(&m,m.t_f32,v,0), y=spvb_extract(&m,m.t_f32,v,1);
    uint32_t col=spvb_construct4(&m,x,y,spvm_cf(&m,0.0f),spvm_cf(&m,1.0f));
    spvb_store(&m,v_out,col);
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[2]={v_in,v_out};
    return spvm_finish(&m,entry,SpvEMFragment,iface,2,0,out,cap);
}

int dbg_tex_fs(uint32_t* out, int cap){
    SpvMod m; spvm_init(&m);
    uint32_t p_in=spvm_ptr(&m,SpvSCInput,m.t_vf[4]);
    uint32_t v_in=spvm_id(&m);
    { uint32_t a[]={p_in,v_in,SpvSCInput}; spvm_g(&m,SpvOpVariable,a,3); }
    { uint32_t a[]={v_in,SpvDecLocation,3}; spvm_d(&m,SpvOpDecorate,a,3); }
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
    uint32_t v=spvb_load(&m,m.t_vf[4],v_in);
    uint32_t x=spvb_extract(&m,m.t_f32,v,0), y=spvb_extract(&m,m.t_f32,v,1);
    uint32_t uv=spvm_id(&m);
    { uint32_t a[]={m.t_vf[2],uv,x,y}; spvm_b(&m,SpvOpCompositeConstruct,a,4); }
    uint32_t img=spvb_load(&m,t_simg,v_img);
    uint32_t col=spvm_id(&m);
    { uint32_t a[]={m.t_vf[4],col,img,uv}; spvm_b(&m,SpvOpImageSampleImplicitLod,a,4); }
    spvb_store(&m,v_out,col);
    { uint32_t a[1]; spvm_b(&m,SpvOpReturn,a,0); }
    { uint32_t a[1]; spvm_b(&m,SpvOpFunctionEnd,a,0); }
    uint32_t iface[2]={v_in,v_out};
    return spvm_finish(&m,entry,SpvEMFragment,iface,2,0,out,cap);
}
