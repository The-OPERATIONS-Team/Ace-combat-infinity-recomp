#include "spv.h"
#include <string.h>
#include <stdio.h>

static void emit(uint32_t* buf, int* n, int cap, SpvMod* m,
                 uint16_t op, const uint32_t* a, int na){
    if(*n+na+1>cap){ m->fail=1; return; }
    buf[(*n)++]=((uint32_t)(na+1)<<16)|op;
    for(int i=0;i<na;i++) buf[(*n)++]=a[i];
}
void spvm_g(SpvMod* m, uint16_t op, const uint32_t* a, int n){ emit(m->glob,&m->gn,SPVM_GLOB,m,op,a,n); }
void spvm_d(SpvMod* m, uint16_t op, const uint32_t* a, int n){ emit(m->deco,&m->dn,SPVM_DECO,m,op,a,n); }
void spvm_b(SpvMod* m, uint16_t op, const uint32_t* a, int n){ emit(m->body,&m->bn,SPVM_BODY,m,op,a,n); }

#define G(m,op,...) do{ uint32_t a_[]={__VA_ARGS__}; spvm_g(m,op,a_,(int)(sizeof a_/4)); }while(0)
#define B(m,op,...) do{ uint32_t a_[]={__VA_ARGS__}; spvm_b(m,op,a_,(int)(sizeof a_/4)); }while(0)

uint32_t spvm_id(SpvMod* m){ return m->next_id++; }

void spvm_cap(SpvMod* m, uint32_t capability){
    for(int i=0;i<m->nxcap;i++) if(m->xcap[i]==capability) return;
    if(m->nxcap<(int)(sizeof m->xcap/4)) m->xcap[m->nxcap++]=capability;
    else m->fail=1;
}

void spvm_init(SpvMod* m){
    memset(m,0,sizeof *m);
    m->next_id=1;
    m->glsl=spvm_id(m);
    m->t_void=spvm_id(m);   G(m,SpvOpTypeVoid,m->t_void);
    m->t_fnvoid=spvm_id(m); G(m,SpvOpTypeFunction,m->t_fnvoid,m->t_void);
    m->t_bool=spvm_id(m);   G(m,SpvOpTypeBool,m->t_bool);
    m->t_f32=spvm_id(m);    G(m,SpvOpTypeFloat,m->t_f32,32);
    m->t_i32=spvm_id(m);    G(m,SpvOpTypeInt,m->t_i32,32,1);
    m->t_u32=spvm_id(m);    G(m,SpvOpTypeInt,m->t_u32,32,0);
    for(int n=2;n<=4;n++){ m->t_vf[n]=spvm_id(m); G(m,SpvOpTypeVector,m->t_vf[n],m->t_f32,(uint32_t)n); }
    m->t_bv4=spvm_id(m);    G(m,SpvOpTypeVector,m->t_bv4,m->t_bool,4);
}

uint32_t spvm_ptr(SpvMod* m, uint32_t sc, uint32_t type){
    for(int i=0;i<m->nptr;i++)
        if(m->ptrs[i].sc==sc&&m->ptrs[i].ty==type) return m->ptrs[i].id;
    uint32_t id=spvm_id(m);
    G(m,SpvOpTypePointer,id,sc,type);
    if(m->nptr<64){ m->ptrs[m->nptr].sc=sc; m->ptrs[m->nptr].ty=type; m->ptrs[m->nptr].id=id; m->nptr++; }
    return id;
}
uint32_t spvm_cf(SpvMod* m, float f){
    uint32_t bits; memcpy(&bits,&f,4);
    for(int i=0;i<m->ncf;i++) if(m->cf[i].bits==bits) return m->cf[i].id;
    uint32_t id=spvm_id(m);
    G(m,SpvOpConstant,m->t_f32,id,bits);
    if(m->ncf<512){ m->cf[m->ncf].bits=bits; m->cf[m->ncf].id=id; m->ncf++; }
    return id;
}
uint32_t spvm_ci(SpvMod* m, int32_t v){
    for(int i=0;i<m->nci;i++) if(m->ci[i].v==v) return m->ci[i].id;
    uint32_t id=spvm_id(m);
    G(m,SpvOpConstant,m->t_i32,id,(uint32_t)v);
    if(m->nci<SPVM_CI_CACHE){ m->ci[m->nci].v=v; m->ci[m->nci].id=id; m->nci++; }
    return id;
}
uint32_t spvm_cu(SpvMod* m, uint32_t v){
    for(int i=0;i<m->ncu;i++) if(m->cu[i].v==v) return m->cu[i].id;
    uint32_t id=spvm_id(m);
    G(m,SpvOpConstant,m->t_u32,id,v);
    if(m->ncu<64){ m->cu[m->ncu].v=v; m->cu[m->ncu].id=id; m->ncu++; }
    return id;
}
uint32_t spvm_cf4(SpvMod* m, float x, float y, float z, float w){
    uint32_t cx=spvm_cf(m,x),cy=spvm_cf(m,y),cz=spvm_cf(m,z),cw=spvm_cf(m,w);
    uint32_t id=spvm_id(m);
    G(m,SpvOpConstantComposite,m->t_vf[4],id,cx,cy,cz,cw);
    return id;
}

uint32_t spvb_load(SpvMod* m, uint32_t type, uint32_t ptr){
    uint32_t id=spvm_id(m); B(m,SpvOpLoad,type,id,ptr); return id;
}
void spvb_store(SpvMod* m, uint32_t ptr, uint32_t val){ B(m,SpvOpStore,ptr,val); }
uint32_t spvb_bin(SpvMod* m, uint16_t op, uint32_t type, uint32_t a, uint32_t b){
    uint32_t id=spvm_id(m); B(m,op,type,id,a,b); return id;
}
uint32_t spvb_un(SpvMod* m, uint16_t op, uint32_t type, uint32_t a){
    uint32_t id=spvm_id(m); B(m,op,type,id,a); return id;
}
uint32_t spvb_ext1(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a){
    uint32_t id=spvm_id(m); B(m,SpvOpExtInst,type,id,m->glsl,inst,a); return id;
}
uint32_t spvb_ext2(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a, uint32_t b){
    uint32_t id=spvm_id(m); B(m,SpvOpExtInst,type,id,m->glsl,inst,a,b); return id;
}
uint32_t spvb_ext3(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a, uint32_t b, uint32_t c){
    uint32_t id=spvm_id(m); B(m,SpvOpExtInst,type,id,m->glsl,inst,a,b,c); return id;
}
uint32_t spvb_shuffle4(SpvMod* m, uint32_t v, const uint8_t swz[4]){
    if(swz[0]==0&&swz[1]==1&&swz[2]==2&&swz[3]==3) return v;
    uint32_t id=spvm_id(m);
    B(m,SpvOpVectorShuffle,m->t_vf[4],id,v,v,swz[0],swz[1],swz[2],swz[3]);
    return id;
}
uint32_t spvb_extract(SpvMod* m, uint32_t type, uint32_t v, uint32_t idx){
    uint32_t id=spvm_id(m); B(m,SpvOpCompositeExtract,type,id,v,idx); return id;
}
uint32_t spvb_construct4(SpvMod* m, uint32_t x, uint32_t y, uint32_t z, uint32_t w){
    uint32_t id=spvm_id(m); B(m,SpvOpCompositeConstruct,m->t_vf[4],id,x,y,z,w); return id;
}
uint32_t spvb_splat4(SpvMod* m, uint32_t f){
    return spvb_construct4(m,f,f,f,f);
}
uint32_t spvb_select4(SpvMod* m, uint32_t bvec, uint32_t a, uint32_t b){
    uint32_t id=spvm_id(m); B(m,SpvOpSelect,m->t_vf[4],id,bvec,a,b); return id;
}

int spvm_finish(SpvMod* m, uint32_t entry, uint32_t exec_model,
                const uint32_t* iface, int niface, int depth_replacing,
                uint32_t* out, int cap){
    if(m->fail) return 0;
    int n=0;
    #define W(x) do{ if(n>=cap) return 0; out[n++]=(x); }while(0)
    W(0x07230203); W(0x00010000); W(0); W(m->next_id); W(0);
    W((2u<<16)|SpvOpCapability); W(1);
    for(int i=0;i<m->nxcap;i++){ W((2u<<16)|SpvOpCapability); W(m->xcap[i]); }
    { const char* s="GLSL.std.450"; int len=(int)strlen(s), words=(len+4)/4;
      W(((uint32_t)(2+words)<<16)|SpvOpExtInstImport); W(m->glsl);
      for(int i=0;i<words;i++){ uint32_t w=0;
          for(int b=0;b<4;b++){ int c=i*4+b; if(c<len) w|=(uint32_t)(unsigned char)s[c]<<(b*8); }
          W(w); } }
    W((3u<<16)|SpvOpMemoryModel); W(0); W(1);
    { const char* s="main"; int words=2;
      W(((uint32_t)(3+words+niface)<<16)|SpvOpEntryPoint);
      W(exec_model); W(entry);
      W(0x6e69616du); W(0);
      for(int i=0;i<niface;i++) W(iface[i]); }
    if(exec_model==SpvEMFragment){
        W((3u<<16)|SpvOpExecutionMode); W(entry); W(SpvExecOriginUpperLeft);
        if(depth_replacing){ W((3u<<16)|SpvOpExecutionMode); W(entry); W(SpvExecDepthReplacing); }
    }
    if(n+m->dn+m->gn+m->bn>cap) return 0;
    memcpy(out+n,m->deco,m->dn*4); n+=m->dn;
    memcpy(out+n,m->glob,m->gn*4); n+=m->gn;
    memcpy(out+n,m->body,m->bn*4); n+=m->bn;
    #undef W
    return n;
}
