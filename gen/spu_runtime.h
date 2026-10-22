#pragma once
#include <stdint.h>
#include <string.h>

#if defined(__SSSE3__)
#include <immintrin.h>
#define SPU_SSE 1
#define SPU_BSWAP_MASK _mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12)
#endif

typedef union {
    uint8_t  b[16];
    uint16_t h[8];
    uint32_t w[4];
    int32_t  sw[4];
    uint64_t d[2];
    float    fp[4];
    double   df[2];
} SpuReg;

typedef struct {
    SpuReg   r[128];
    uint8_t* ls;
    uint32_t lsmask;
    uint32_t pc;
    uint32_t srr0;
    uint32_t dec;
    uint32_t fpscr_pad;
    void*    spu;
    int32_t  pc_bias;
} SPUContext;

#define SPU_LSMASK 0x3ffffu

#define SPU_L_(n, ...) { enum { i = n }; __VA_ARGS__ }
#define SPU_LANES4(...)  do{ SPU_L_(0,__VA_ARGS__) SPU_L_(1,__VA_ARGS__) SPU_L_(2,__VA_ARGS__) SPU_L_(3,__VA_ARGS__) }while(0)
#define SPU_LANES8(...)  do{ SPU_L_(0,__VA_ARGS__) SPU_L_(1,__VA_ARGS__) SPU_L_(2,__VA_ARGS__) SPU_L_(3,__VA_ARGS__) \
                             SPU_L_(4,__VA_ARGS__) SPU_L_(5,__VA_ARGS__) SPU_L_(6,__VA_ARGS__) SPU_L_(7,__VA_ARGS__) }while(0)
#define SPU_LANES16(...) do{ SPU_L_(0,__VA_ARGS__) SPU_L_(1,__VA_ARGS__) SPU_L_(2,__VA_ARGS__) SPU_L_(3,__VA_ARGS__) \
                             SPU_L_(4,__VA_ARGS__) SPU_L_(5,__VA_ARGS__) SPU_L_(6,__VA_ARGS__) SPU_L_(7,__VA_ARGS__) \
                             SPU_L_(8,__VA_ARGS__) SPU_L_(9,__VA_ARGS__) SPU_L_(10,__VA_ARGS__) SPU_L_(11,__VA_ARGS__) \
                             SPU_L_(12,__VA_ARGS__) SPU_L_(13,__VA_ARGS__) SPU_L_(14,__VA_ARGS__) SPU_L_(15,__VA_ARGS__) }while(0)

static inline void spu_get_bytes(const SpuReg* r, uint8_t out[16]) {
#ifdef SPU_SSE
    _mm_storeu_si128((__m128i*)out,
        _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)r), SPU_BSWAP_MASK));
#else
    for (int i = 0; i < 4; i++) {
        uint32_t v = r->w[i];
        out[i*4+0] = (uint8_t)(v >> 24); out[i*4+1] = (uint8_t)(v >> 16);
        out[i*4+2] = (uint8_t)(v >> 8);  out[i*4+3] = (uint8_t)v;
    }
#endif
}
static inline void spu_set_bytes(SpuReg* r, const uint8_t in[16]) {
#ifdef SPU_SSE
    _mm_storeu_si128((__m128i*)r,
        _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in), SPU_BSWAP_MASK));
#else
    for (int i = 0; i < 4; i++)
        r->w[i] = ((uint32_t)in[i*4+0] << 24) | ((uint32_t)in[i*4+1] << 16) |
                  ((uint32_t)in[i*4+2] << 8)  |  (uint32_t)in[i*4+3];
#endif
}

static inline uint64_t spu_getd64(const SpuReg* r, int j){
    return ((uint64_t)r->w[2*j] << 32) | r->w[2*j+1];
}
static inline void spu_setd64(SpuReg* r, int j, uint64_t v){
    r->w[2*j] = (uint32_t)(v >> 32); r->w[2*j+1] = (uint32_t)v;
}
static inline double spu_getdf(const SpuReg* r, int j){
    uint64_t u = spu_getd64(r, j); double d; memcpy(&d, &u, 8); return d;
}
static inline void spu_setdf(SpuReg* r, int j, double d){
    uint64_t u; memcpy(&u, &d, 8); spu_setd64(r, j, u);
}

static inline void spu_lq(const SPUContext* c, uint32_t ea, SpuReg* out) {
    ea &= SPU_LSMASK & ~0xfu;
#ifdef SPU_SSE
    _mm_storeu_si128((__m128i*)out,
        _mm_shuffle_epi8(_mm_load_si128((const __m128i*)(c->ls + ea)), SPU_BSWAP_MASK));
#else
    for (int i = 0; i < 4; i++) {
        const uint8_t* p = c->ls + ea + i*4;
        out->w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
#endif
}
static inline void spu_stq(SPUContext* c, uint32_t ea, const SpuReg* in) {
    ea &= SPU_LSMASK & ~0xfu;
#ifdef SPU_SSE
    _mm_store_si128((__m128i*)(c->ls + ea),
        _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in), SPU_BSWAP_MASK));
#else
    for (int i = 0; i < 4; i++) {
        uint8_t* p = c->ls + ea + i*4;
        uint32_t v = in->w[i];
        p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
    }
#endif
}

static inline uint32_t spu_fmag(uint32_t u){
    u &= 0x7fffffffu; return (u & 0x7f800000u) ? u : 0u;
}
static inline uint32_t spu_fkey(uint32_t u){
    uint32_t m = spu_fmag(u);
    if(!m) return 0x80000000u;
    return (u & 0x80000000u) ? (0x80000000u - m) : (0x80000000u + m);
}
static inline int spu_fcgt1 (uint32_t a, uint32_t b){ return spu_fkey(a) >  spu_fkey(b); }
static inline int spu_fceq1 (uint32_t a, uint32_t b){ return spu_fkey(a) == spu_fkey(b); }
static inline int spu_fcmgt1(uint32_t a, uint32_t b){ return spu_fmag(a) >  spu_fmag(b); }
static inline int spu_fcmeq1(uint32_t a, uint32_t b){ return spu_fmag(a) == spu_fmag(b); }

#ifdef SPU_SSE
static inline __m128i spu_be_(const SpuReg* r){
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)r), SPU_BSWAP_MASK);
}
static inline void spu_from_be_(SpuReg* r, __m128i v){
    _mm_storeu_si128((__m128i*)r, _mm_shuffle_epi8(v, SPU_BSWAP_MASK));
}
#define SPU_IOTA_ _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
#endif

static inline void spu_shlqby(SpuReg* t, const SpuReg* a, unsigned n){
#ifdef SPU_SSE
    __m128i idx = _mm_add_epi8(SPU_IOTA_, _mm_set1_epi8((char)n));
    idx = _mm_or_si128(idx, _mm_cmpgt_epi8(idx, _mm_set1_epi8(15)));
    if(n>15) idx = _mm_set1_epi8((char)0x80);
    spu_from_be_(t, _mm_shuffle_epi8(spu_be_(a), idx));
#else
    uint8_t s[16],d[16]; spu_get_bytes(a,s);
    for(int k=0;k<16;k++) d[k]=(k+(int)n<16)?s[k+n]:0;
    spu_set_bytes(t,d);
#endif
}
static inline void spu_rotqby(SpuReg* t, const SpuReg* a, unsigned n){
#ifdef SPU_SSE
    __m128i idx = _mm_and_si128(_mm_add_epi8(SPU_IOTA_, _mm_set1_epi8((char)n)), _mm_set1_epi8(0x0f));
    spu_from_be_(t, _mm_shuffle_epi8(spu_be_(a), idx));
#else
    uint8_t s[16],d[16]; spu_get_bytes(a,s);
    for(int k=0;k<16;k++) d[k]=s[(k+n)&0xf];
    spu_set_bytes(t,d);
#endif
}
static inline void spu_rotqmby(SpuReg* t, const SpuReg* a, unsigned n){
#ifdef SPU_SSE
    __m128i idx = _mm_sub_epi8(SPU_IOTA_, _mm_set1_epi8((char)n));
    if(n>15){ spu_from_be_(t, _mm_setzero_si128()); return; }
    spu_from_be_(t, _mm_shuffle_epi8(spu_be_(a), idx));
#else
    uint8_t s[16],d[16]; spu_get_bytes(a,s);
    for(int k=0;k<16;k++) d[k]=(k>=(int)n&&k-(int)n<16)?s[k-n]:0;
    spu_set_bytes(t,d);
#endif
}
static inline void spu_shlqbi(SpuReg* t, const SpuReg* a, unsigned n){
    uint64_t hi=spu_getd64(a,0), lo=spu_getd64(a,1);
    if(n){ hi=(hi<<n)|(lo>>(64-n)); lo<<=n; }
    spu_setd64(t,0,hi); spu_setd64(t,1,lo);
}
static inline void spu_rotqbi(SpuReg* t, const SpuReg* a, unsigned n){
    uint64_t hi=spu_getd64(a,0), lo=spu_getd64(a,1);
    if(n){ uint64_t f=hi>>(64-n); hi=(hi<<n)|(lo>>(64-n)); lo=(lo<<n)|f; }
    spu_setd64(t,0,hi); spu_setd64(t,1,lo);
}
static inline void spu_rotqmbi(SpuReg* t, const SpuReg* a, unsigned n){
    uint64_t hi=spu_getd64(a,0), lo=spu_getd64(a,1);
    if(n){ lo=(lo>>n)|(hi<<(64-n)); hi>>=n; }
    spu_setd64(t,0,hi); spu_setd64(t,1,lo);
}
static inline void spu_shufb(SpuReg* t, const SpuReg* a, const SpuReg* b, const SpuReg* c){
#if defined(SPU_SSE) && defined(__SSE4_1__)
    __m128i va=spu_be_(a), vb=spu_be_(b), vc=spu_be_(c);
    __m128i idx   = _mm_and_si128(vc, _mm_set1_epi8(0x0f));
    __m128i sel   = _mm_blendv_epi8(_mm_shuffle_epi8(va,idx), _mm_shuffle_epi8(vb,idx),
                                    _mm_slli_epi16(vc,3));
    __m128i spec1 = _mm_blendv_epi8(_mm_set1_epi8((char)0xff), _mm_set1_epi8((char)0x80),
                                    _mm_slli_epi16(vc,2));
    __m128i spec  = _mm_blendv_epi8(_mm_setzero_si128(), spec1,
                                    _mm_slli_epi16(vc,1));
    spu_from_be_(t, _mm_blendv_epi8(sel, spec, vc));
#else
    uint8_t sa[16],sb[16],sc[16],d[16];
    spu_get_bytes(a,sa); spu_get_bytes(b,sb); spu_get_bytes(c,sc);
    for(int k=0;k<16;k++){ uint8_t s=sc[k];
        if((s&0xc0)==0x80) d[k]=0; else if((s&0xe0)==0xc0) d[k]=0xff;
        else if((s&0xe0)==0xe0) d[k]=0x80; else d[k]=(s&0x10)?sb[s&0xf]:sa[s&0xf]; }
    spu_set_bytes(t,d);
#endif
}

static inline void spu_cins(SpuReg* t, uint32_t ea, unsigned sz){
    uint32_t p = (ea & 0xfu) & ~(uint32_t)(sz - 1);
    int first = sz <= 4 ? 4 - (int)sz : 0;
#ifdef SPU_SSE
    __m128i id  = _mm_setr_epi8(0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f);
    __m128i d   = _mm_sub_epi8(SPU_IOTA_, _mm_set1_epi8((char)p));
    __m128i in  = _mm_cmpeq_epi8(_mm_min_epu8(d, _mm_set1_epi8((char)(sz - 1))), d);
    __m128i val = _mm_add_epi8(d, _mm_set1_epi8((char)first));
    spu_from_be_(t, _mm_or_si128(_mm_and_si128(in, val), _mm_andnot_si128(in, id)));
#else
    uint8_t b[16];
    for(int k=0;k<16;k++) b[k]=(uint8_t)(0x10+k);
    for(unsigned j=0;j<sz;j++) b[p+j]=(uint8_t)(first+(int)j);
    spu_set_bytes(t,b);
#endif
}

uint32_t spu_rdch(SPUContext* c, uint32_t ch);
void     spu_wrch(SPUContext* c, uint32_t ch, uint32_t val);
uint32_t spu_rchcnt(SPUContext* c, uint32_t ch);
void     spu_stop(SPUContext* c, uint32_t code);
void     spu_unimpl(const char* mnem, uint32_t pc);

typedef struct SpuThread SpuThread;
typedef void (*SpuBodyFn)(SPUContext*);
typedef struct SpuBody {
    uint32_t entry;
    void (*fn)(SPUContext*);
    const uint32_t* range;
    const uint32_t* sig_at;
    const uint8_t*  sig;
} SpuBody;
extern const SpuBody g_spu_bodies[];
extern const unsigned g_spu_nbodies;
void spu_interp(SPUContext* c);
int spu_reloc_hit(uint32_t pc, const uint8_t* ls);
typedef struct { void (*fn)(SPUContext*); uint32_t ea; } SpuJobGuest;
extern const SpuJobGuest g_spu_job_guest[];
extern const unsigned    g_spu_njob_guest;
int spu_jobbody_verify(void (*fn)(SPUContext*), const uint8_t* ls, uint32_t base);
int spu_body_accept(unsigned i, uint32_t pc, const uint8_t* ls);
void        spu_set_resolver(SpuBodyFn (*r)(uint32_t pc, const uint8_t* ls));
void        spu_set_intr_hook(int (*h)(SpuThread* t, uint32_t intr, uint32_t data1));
void        spu_rt_set_mainmem(uint8_t* base, uint64_t size);
void        spu_set_dma_read_hook(void (*h)(uint32_t ea, uint32_t sz),
                                  uint32_t lo, uint32_t hi);
SpuThread*  spu_thread_create(void (*run)(SPUContext*), const uint8_t* image,
                              uint32_t img_lsaddr, uint32_t img_size, uint32_t entry);
void        spu_thread_join(SpuThread* t);
uint8_t*    spu_thread_ls(SpuThread* t);
SpuThread*  spu_thread_alloc(void);
void        spu_thread_write_ls(SpuThread* t, uint32_t lsaddr, const void* src, uint32_t n);
void        spu_thread_set_arg64(SpuThread* t, int reg, uint64_t v);
void        spu_thread_start_at(SpuThread* t, void (*run)(SPUContext*), uint32_t entry);
int         spu_thread_running(SpuThread* t);
uint32_t    spu_thread_stop_code(SpuThread* t);
uint32_t    spu_thread_pc(SpuThread* t);
void        spu_push_inmbox(SpuThread* t, uint32_t v);
int         spu_pop_outmbox(SpuThread* t, uint32_t* out);
void        spu_signal(SpuThread* t, int which, uint32_t v);
