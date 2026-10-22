#pragma once
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union PPUVec {
    uint32_t u32[4];
    int32_t  s32[4];
    float    f32[4];
} PPUVec;

typedef struct PPUContext {
    uint64_t r[32];
    double   f[32];
    PPUVec   v[32];
    uint8_t  cr[8];
    uint64_t lr, ctr;
    uint8_t  ca, ov, so;
    uint32_t fpscr, vrsave;
    uint64_t reserve_addr;
    uint64_t reserve_value;
    uint8_t  reserve_valid;
    uint32_t resume_pc;
} PPUContext;

typedef void (*PPCFunc)(PPUContext*, uint8_t*);

PPCFunc ppu_lookup(uint32_t addr);
PPCFunc ppu_lookup_ex(uint32_t addr, PPUContext* ctx);

void ppu_unimpl(const char* what, uint32_t addr);

void ppu_hle(uint32_t nid, const char* lib, const char* name, PPUContext* ctx, uint8_t* base);
void ppu_miss(uint32_t addr);
void ppu_lookup_miss(uint32_t addr);
int ppu_acipatch(uint32_t* n);
void ppu_rt_init(uint8_t* base, uint64_t size);
void ppu_syscall(PPUContext* ctx, uint8_t* base);
extern __declspec(thread) volatile uint32_t g_curfn;
void ppu_dbg_bctr(PPUContext* ctx, uint32_t addr);
extern volatile int g_trace_n;
void ppu_trace_hit(uint32_t addr, PPUContext* ctx);
#define PPU_CURFN(a)        (g_curfn=(a), (void)(g_trace_n ? (ppu_trace_hit((a),ctx),0) : 0))
#ifdef PPU_TRACE
  #define PPU_DBG_BCTR(c,a)   ppu_dbg_bctr((c),(a))
#else
  #define PPU_DBG_BCTR(c,a)   ((void)0)
#endif
uint64_t ppu_timebase(void);

uint32_t ppu_lwarx(PPUContext* ctx, uint8_t* base, uint32_t ea);
uint64_t ppu_ldarx(PPUContext* ctx, uint8_t* base, uint32_t ea);
void     ppu_stwcx(PPUContext* ctx, uint8_t* base, uint32_t ea, uint32_t v);
void     ppu_stdcx(PPUContext* ctx, uint8_t* base, uint32_t ea, uint64_t v);

static inline uint8_t  PPU_LB(uint8_t* b, uint32_t ea){ return b[ea]; }
static inline uint16_t PPU_LH(uint8_t* b, uint32_t ea){ uint16_t v; memcpy(&v,b+ea,2); return __builtin_bswap16(v); }
static inline uint32_t PPU_LW(uint8_t* b, uint32_t ea){ uint32_t v; memcpy(&v,b+ea,4); return __builtin_bswap32(v); }
static inline uint64_t PPU_LD(uint8_t* b, uint32_t ea){ uint64_t v; memcpy(&v,b+ea,8); return __builtin_bswap64(v); }
static inline void PPU_STB(uint8_t* b, uint32_t ea, uint8_t  v){ b[ea]=v; }
static inline void PPU_STH(uint8_t* b, uint32_t ea, uint16_t v){ v=__builtin_bswap16(v); memcpy(b+ea,&v,2); }
static inline void PPU_STW(uint8_t* b, uint32_t ea, uint32_t v){ v=__builtin_bswap32(v); memcpy(b+ea,&v,4); }
static inline void PPU_STD(uint8_t* b, uint32_t ea, uint64_t v){ v=__builtin_bswap64(v); memcpy(b+ea,&v,8); }

static inline float  PPU_LFS(uint8_t* b, uint32_t ea){ uint32_t u=PPU_LW(b,ea); float f; memcpy(&f,&u,4); return f; }
static inline double PPU_LFD(uint8_t* b, uint32_t ea){ uint64_t u=PPU_LD(b,ea); double f; memcpy(&f,&u,8); return f; }
static inline void   PPU_STFS(uint8_t* b, uint32_t ea, float f){ uint32_t u; memcpy(&u,&f,4); PPU_STW(b,ea,u); }
static inline void   PPU_STFD(uint8_t* b, uint32_t ea, double f){ uint64_t u; memcpy(&u,&f,8); PPU_STD(b,ea,u); }

static inline void ppu_setcrf_s(PPUContext* c, int n, int64_t a, int64_t b){
    c->cr[n] = (uint8_t)((a<b?8:a>b?4:2) | (c->so?1:0));
}
static inline void ppu_setcrf_u(PPUContext* c, int n, uint64_t a, uint64_t b){
    c->cr[n] = (uint8_t)((a<b?8:a>b?4:2) | (c->so?1:0));
}
static inline void ppu_cr0(PPUContext* c, int64_t v){ ppu_setcrf_s(c, 0, v, 0); }

static inline uint32_t ppu_crbit(PPUContext* c, int b){
    return (c->cr[b>>2] >> (3-(b&3))) & 1;
}
static inline void ppu_setcrbit(PPUContext* c, int b, uint32_t v){
    uint8_t m = (uint8_t)(1 << (3-(b&3)));
    if (v) c->cr[b>>2] |= m; else c->cr[b>>2] &= (uint8_t)~m;
}

static inline uint32_t ppu_rotl32(uint32_t x, uint32_t n){ n&=31; return n? (x<<n)|(x>>(32-n)) : x; }
static inline uint64_t ppu_rotl64(uint64_t x, uint32_t n){ n&=63; return n? (x<<n)|(x>>(64-n)) : x; }
static inline uint32_t ppu_mask32(uint32_t mb, uint32_t me){
    uint32_t begin = 0xFFFFFFFFu >> mb;
    uint32_t end   = 0xFFFFFFFFu << (31 - me);
    return (mb <= me) ? (begin & end) : (begin | end);
}
static inline uint64_t ppu_mask64(uint32_t mb, uint32_t me){
    uint64_t begin = ~0ull >> mb;
    uint64_t end   = ~0ull << (63 - me);
    return (mb <= me) ? (begin & end) : (begin | end);
}

static inline uint8_t ppu_vb(const PPUVec* v, int j){
    return (uint8_t)(v->u32[j>>2] >> (8*(3-(j&3))));
}
static inline void ppu_vsb(PPUVec* v, int j, uint8_t b){
    int sh = 8*(3-(j&3)); uint32_t m = 0xFFu<<sh;
    v->u32[j>>2] = (v->u32[j>>2] & ~m) | ((uint32_t)b<<sh);
}
static inline void ppu_vperm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r;
    for (int i=0;i<16;i++){ int s = ppu_vb(c,i) & 0x1F; ppu_vsb(&r,i, s<16?ppu_vb(a,s):ppu_vb(b,s-16)); }
    *d = r;
}
static inline void ppu_vsldoi(PPUVec* d, const PPUVec* a, const PPUVec* b, int shb){
    PPUVec r;
    for (int i=0;i<16;i++){ int s=i+shb; ppu_vsb(&r,i, s<16?ppu_vb(a,s):ppu_vb(b,s-16)); }
    *d = r;
}
static inline void ppu_lvsl(PPUVec* d, uint32_t ea){ int sh=ea&0xF; for(int i=0;i<16;i++) ppu_vsb(d,i,(uint8_t)(sh+i)); }
static inline void ppu_lvsr(PPUVec* d, uint32_t ea){ int sh=ea&0xF; for(int i=0;i<16;i++) ppu_vsb(d,i,(uint8_t)(16-sh+i)); }

static inline float ppu_satf2i(float f, int* ovf){
    double d=(double)f;
    if (d > 2147483647.0){ *ovf=1; return 2147483647.0f; }
    if (d < -2147483648.0){ *ovf=1; return -2147483648.0f; }
    return f;
}

static inline uint16_t ppu_vh(const PPUVec* v, int j){
    return (uint16_t)(v->u32[j>>1] >> (16*(1-(j&1))));
}
static inline void ppu_vsh(PPUVec* v, int j, uint16_t h){
    int sh = 16*(1-(j&1)); uint32_t m = 0xFFFFu<<sh;
    v->u32[j>>1] = (v->u32[j>>1] & ~m) | ((uint32_t)h<<sh);
}

static inline uint8_t  ppu_satub(int32_t v){ return v<0?0:v>255?255:(uint8_t)v; }
static inline int8_t   ppu_satsb(int32_t v){ return v<-128?-128:v>127?127:(int8_t)v; }
static inline uint16_t ppu_satuh(int32_t v){ return v<0?0:v>65535?65535:(uint16_t)v; }
static inline int16_t  ppu_satsh(int32_t v){ return v<-32768?-32768:v>32767?32767:(int16_t)v; }
static inline uint32_t ppu_satuw(int64_t v){ return v<0?0u:v>0xFFFFFFFFll?0xFFFFFFFFu:(uint32_t)v; }
static inline int32_t  ppu_satsw(int64_t v){ return v<-2147483648ll?(int32_t)-2147483648ll:v>2147483647ll?2147483647:(int32_t)v; }

static inline void ppu_vpkuhum(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++){ ppu_vsb(&r,j,(uint8_t)ppu_vh(a,j)); ppu_vsb(&r,8+j,(uint8_t)ppu_vh(b,j)); } *d=r;
}
static inline void ppu_vpkuwum(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ ppu_vsh(&r,j,(uint16_t)a->u32[j]); ppu_vsh(&r,4+j,(uint16_t)b->u32[j]); } *d=r;
}
static inline void ppu_vpkuhus(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++){ uint16_t x=ppu_vh(a,j),y=ppu_vh(b,j);
        ppu_vsb(&r,j,   x>255?255:(uint8_t)x); ppu_vsb(&r,8+j, y>255?255:(uint8_t)y); } *d=r;
}
static inline void ppu_vpkuwus(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ uint32_t x=a->u32[j],y=b->u32[j];
        ppu_vsh(&r,j,   x>65535?65535:(uint16_t)x); ppu_vsh(&r,4+j, y>65535?65535:(uint16_t)y); } *d=r;
}
static inline void ppu_vpkshus(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++){ int16_t x=(int16_t)ppu_vh(a,j),y=(int16_t)ppu_vh(b,j);
        ppu_vsb(&r,j,ppu_satub(x)); ppu_vsb(&r,8+j,ppu_satub(y)); } *d=r;
}
static inline void ppu_vpkswus(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ int32_t x=a->s32[j],y=b->s32[j];
        ppu_vsh(&r,j,ppu_satuh(x)); ppu_vsh(&r,4+j,ppu_satuh(y)); } *d=r;
}
static inline void ppu_vpkshss(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++){ int16_t x=(int16_t)ppu_vh(a,j),y=(int16_t)ppu_vh(b,j);
        ppu_vsb(&r,j,(uint8_t)ppu_satsb(x)); ppu_vsb(&r,8+j,(uint8_t)ppu_satsb(y)); } *d=r;
}
static inline void ppu_vpkswss(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ int32_t x=a->s32[j],y=b->s32[j];
        ppu_vsh(&r,j,(uint16_t)ppu_satsh(x)); ppu_vsh(&r,4+j,(uint16_t)ppu_satsh(y)); } *d=r;
}
static inline void ppu_vpkpx(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){
        uint32_t x=a->u32[j], y=b->u32[j];
        uint16_t px=(uint16_t)(((x>>24)&1)<<15 | ((x>>19)&0x1f)<<10 | ((x>>11)&0x1f)<<5 | ((x>>3)&0x1f));
        uint16_t py=(uint16_t)(((y>>24)&1)<<15 | ((y>>19)&0x1f)<<10 | ((y>>11)&0x1f)<<5 | ((y>>3)&0x1f));
        ppu_vsh(&r,j,px); ppu_vsh(&r,4+j,py); } *d=r;
}
static inline void ppu_vupkhsb(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++) ppu_vsh(&r,j,(uint16_t)(int16_t)(int8_t)ppu_vb(b,j)); *d=r;
}
static inline void ppu_vupklsb(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<8;j++) ppu_vsh(&r,j,(uint16_t)(int16_t)(int8_t)ppu_vb(b,8+j)); *d=r;
}
static inline void ppu_vupkhsh(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++) r.u32[j]=(uint32_t)(int32_t)(int16_t)ppu_vh(b,j); *d=r;
}
static inline void ppu_vupklsh(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++) r.u32[j]=(uint32_t)(int32_t)(int16_t)ppu_vh(b,4+j); *d=r;
}
static inline void ppu_vupkhpx(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ uint16_t p=ppu_vh(b,j);
        r.u32[j]=(uint32_t)((p&0x8000)?0xFF000000u:0u)|(uint32_t)((p>>10)&0x1f)<<16|(uint32_t)((p>>5)&0x1f)<<8|(uint32_t)(p&0x1f); } *d=r;
}
static inline void ppu_vupklpx(PPUVec* d, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ uint16_t p=ppu_vh(b,4+j);
        r.u32[j]=(uint32_t)((p&0x8000)?0xFF000000u:0u)|(uint32_t)((p>>10)&0x1f)<<16|(uint32_t)((p>>5)&0x1f)<<8|(uint32_t)(p&0x1f); } *d=r;
}
static inline void ppu_vmule(PPUVec* d, const PPUVec* a, const PPUVec* b, int half, int sign, int odd){
    PPUVec r;
    if (half){
        for(int j=0;j<4;j++){ int k=2*j+odd;
            if (sign) r.s32[j]=(int32_t)(int16_t)ppu_vh(a,k)*(int32_t)(int16_t)ppu_vh(b,k);
            else      r.u32[j]=(uint32_t)ppu_vh(a,k)*(uint32_t)ppu_vh(b,k); }
    } else {
        for(int j=0;j<8;j++){ int k=2*j+odd;
            if (sign) ppu_vsh(&r,j,(uint16_t)((int16_t)((int8_t)ppu_vb(a,k)*(int16_t)(int8_t)ppu_vb(b,k))));
            else      ppu_vsh(&r,j,(uint16_t)((uint16_t)ppu_vb(a,k)*(uint16_t)ppu_vb(b,k))); }
    }
    *d=r;
}
static inline void ppu_vmsumubm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ uint32_t s=c->u32[j];
        for(int k=0;k<4;k++) s+=(uint32_t)ppu_vb(a,4*j+k)*(uint32_t)ppu_vb(b,4*j+k);
        r.u32[j]=s; } *d=r;
}
static inline void ppu_vmsummbm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ int32_t s=c->s32[j];
        for(int k=0;k<4;k++) s+=(int32_t)(int8_t)ppu_vb(a,4*j+k)*(int32_t)ppu_vb(b,4*j+k);
        r.s32[j]=s; } *d=r;
}
static inline void ppu_vmsumuhm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ uint32_t s=c->u32[j];
        for(int k=0;k<2;k++) s+=(uint32_t)ppu_vh(a,2*j+k)*(uint32_t)ppu_vh(b,2*j+k);
        r.u32[j]=s; } *d=r;
}
static inline void ppu_vmsumshm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ int32_t s=c->s32[j];
        for(int k=0;k<2;k++) s+=(int32_t)(int16_t)ppu_vh(a,2*j+k)*(int32_t)(int16_t)ppu_vh(b,2*j+k);
        r.s32[j]=s; } *d=r;
}
static inline void ppu_vmsumuhs(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ uint64_t s=c->u32[j];
        for(int k=0;k<2;k++) s+=(uint64_t)ppu_vh(a,2*j+k)*(uint64_t)ppu_vh(b,2*j+k);
        r.u32[j]=s>0xFFFFFFFFull?0xFFFFFFFFu:(uint32_t)s; } *d=r;
}
static inline void ppu_vmsumshs(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<4;j++){ int64_t s=c->s32[j];
        for(int k=0;k<2;k++) s+=(int64_t)(int16_t)ppu_vh(a,2*j+k)*(int64_t)(int16_t)ppu_vh(b,2*j+k);
        r.s32[j]=ppu_satsw(s); } *d=r;
}
static inline void ppu_vmladduhm(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<8;j++)
        ppu_vsh(&r,j,(uint16_t)((uint32_t)ppu_vh(a,j)*(uint32_t)ppu_vh(b,j)+(uint32_t)ppu_vh(c,j)));
    *d=r;
}
static inline void ppu_vmhaddshs(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<8;j++){
        int32_t p=((int32_t)(int16_t)ppu_vh(a,j)*(int32_t)(int16_t)ppu_vh(b,j))>>15;
        ppu_vsh(&r,j,(uint16_t)ppu_satsh(p+(int32_t)(int16_t)ppu_vh(c,j))); } *d=r;
}
static inline void ppu_vmhraddshs(PPUVec* d, const PPUVec* a, const PPUVec* b, const PPUVec* c){
    PPUVec r; for(int j=0;j<8;j++){
        int32_t p=(((int32_t)(int16_t)ppu_vh(a,j)*(int32_t)(int16_t)ppu_vh(b,j))+0x4000)>>15;
        ppu_vsh(&r,j,(uint16_t)ppu_satsh(p+(int32_t)(int16_t)ppu_vh(c,j))); } *d=r;
}
static inline void ppu_vsumsws(PPUVec* d, const PPUVec* a, const PPUVec* b){
    int64_t s=b->s32[3]; for(int j=0;j<4;j++) s+=a->s32[j];
    PPUVec r; r.u32[0]=r.u32[1]=r.u32[2]=0; r.s32[3]=ppu_satsw(s); *d=r;
}
static inline void ppu_vsum2sws(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; r.u32[0]=r.u32[2]=0;
    { int64_t s=(int64_t)b->s32[1]+a->s32[0]+a->s32[1]; r.s32[1]=ppu_satsw(s); }
    { int64_t s=(int64_t)b->s32[3]+a->s32[2]+a->s32[3]; r.s32[3]=ppu_satsw(s); }
    *d=r;
}
static inline void ppu_vsum4ubs(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ uint64_t s=b->u32[j];
        for(int k=0;k<4;k++) s+=ppu_vb(a,4*j+k);
        r.u32[j]=s>0xFFFFFFFFull?0xFFFFFFFFu:(uint32_t)s; } *d=r;
}
static inline void ppu_vsum4sbs(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ int64_t s=b->s32[j];
        for(int k=0;k<4;k++) s+=(int8_t)ppu_vb(a,4*j+k);
        r.s32[j]=ppu_satsw(s); } *d=r;
}
static inline void ppu_vsum4shs(PPUVec* d, const PPUVec* a, const PPUVec* b){
    PPUVec r; for(int j=0;j<4;j++){ int64_t s=b->s32[j];
        for(int k=0;k<2;k++) s+=(int16_t)ppu_vh(a,2*j+k);
        r.s32[j]=ppu_satsw(s); } *d=r;
}
static inline void ppu_vslo(PPUVec* d, const PPUVec* a, const PPUVec* b){
    int sh=(ppu_vb(b,15)>>3)&0xF; PPUVec r;
    for(int i=0;i<16;i++) ppu_vsb(&r,i,(i+sh<16)?ppu_vb(a,i+sh):0); *d=r;
}
static inline void ppu_vsro(PPUVec* d, const PPUVec* a, const PPUVec* b){
    int sh=(ppu_vb(b,15)>>3)&0xF; PPUVec r;
    for(int i=0;i<16;i++) ppu_vsb(&r,i,(i-sh>=0)?ppu_vb(a,i-sh):0); *d=r;
}
static inline void ppu_vsl(PPUVec* d, const PPUVec* a, const PPUVec* b){
    int sh=ppu_vb(b,15)&7; PPUVec r;
    for(int i=0;i<16;i++){ uint8_t hi=ppu_vb(a,i), lo=(i<15)?ppu_vb(a,i+1):0;
        ppu_vsb(&r,i,(uint8_t)((hi<<sh)|(sh?(lo>>(8-sh)):0))); } *d=r;
}
static inline void ppu_vsr(PPUVec* d, const PPUVec* a, const PPUVec* b){
    int sh=ppu_vb(b,15)&7; PPUVec r;
    for(int i=0;i<16;i++){ uint8_t lo=ppu_vb(a,i), hi=(i>0)?ppu_vb(a,i-1):0;
        ppu_vsb(&r,i,(uint8_t)((lo>>sh)|(sh?(hi<<(8-sh)):0))); } *d=r;
}

#ifdef __cplusplus
}
#endif
