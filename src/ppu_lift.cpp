#include "ppu_lift.hpp"
#include "ppu_decode.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <set>
#include <map>
#include <vector>

static inline uint32_t OPCD(uint32_t i){ return i >> 26; }
static inline uint32_t XO  (uint32_t i){ return (i >> 1) & 0x3FF; }
static inline uint32_t RT (uint32_t i){ return (i >> 21) & 0x1F; }
static inline uint32_t RA (uint32_t i){ return (i >> 16) & 0x1F; }
static inline uint32_t RB (uint32_t i){ return (i >> 11) & 0x1F; }
static inline uint32_t SH (uint32_t i){ return (i >> 11) & 0x1F; }
static inline uint32_t MB (uint32_t i){ return (i >> 6)  & 0x1F; }
static inline uint32_t ME (uint32_t i){ return (i >> 1)  & 0x1F; }
static inline uint32_t BO (uint32_t i){ return (i >> 21) & 0x1F; }
static inline uint32_t BI (uint32_t i){ return (i >> 16) & 0x1F; }
static inline uint32_t Rc (uint32_t i){ return i & 1; }
static inline uint32_t LK (uint32_t i){ return i & 1; }
static inline uint32_t AA (uint32_t i){ return (i >> 1) & 1; }
static inline int32_t  Dimm(uint32_t i){ return (int16_t)(i & 0xFFFF); }
static inline uint32_t UI (uint32_t i){ return i & 0xFFFF; }
static inline uint32_t BF (uint32_t i){ return (i >> 23) & 7; }
static inline uint32_t BFA(uint32_t i){ return (i >> 18) & 7; }
static inline uint32_t Lbit(uint32_t i){ return (i >> 21) & 1; }
static inline uint32_t MB6(uint32_t i){ uint32_t m=(i>>5)&0x3F; return ((m&1)<<5)|(m>>1); }
static inline uint32_t SH6(uint32_t i){ return ((i>>11)&0x1F) | (((i>>1)&1)<<5); }

static std::string F(const char* f, ...){
    char b[2048]; va_list ap; va_start(ap,f); vsnprintf(b,sizeof b,f,ap); va_end(ap); return b;
}
static std::string ea_d(uint32_t i){
    if (RA(i)==0) return F("(uint32_t)(%d)", Dimm(i));
    return F("(uint32_t)(ctx->r[%u] + %d)", RA(i), Dimm(i));
}
static std::string ea_x(uint32_t i){
    if (RA(i)==0) return F("(uint32_t)(ctx->r[%u])", RB(i));
    return F("(uint32_t)(ctx->r[%u] + ctx->r[%u])", RA(i), RB(i));
}

static std::string branch_cond(uint32_t i, std::string& pre){
    uint32_t bo=BO(i), bi=BI(i);
    bool dec   = !(bo & 0x04);
    bool tcond = !(bo & 0x10);
    std::string terms;
    if (dec){
        pre += "ctx->ctr--; ";
        terms = (bo & 0x02) ? "ctx->ctr==0" : "ctx->ctr!=0";
    }
    if (tcond){
        std::string c = F("(ppu_crbit(ctx,%u)==%u)", bi, (bo&0x08)?1u:0u);
        terms = terms.empty() ? c : terms + " && " + c;
    }
    if (terms.empty()) terms = "1";
    return terms;
}

static void rc0(std::string& o, uint32_t i){
    if (Rc(i)) o += F(" ppu_cr0(ctx,(int64_t)ctx->r[%u]);", RA(i));
}
static void rc0t(std::string& o, uint32_t i){
    if (Rc(i)) o += F(" ppu_cr0(ctx,(int64_t)ctx->r[%u]);", RT(i));
}

static void lift_fp(std::string& o, uint32_t i, uint32_t addr, bool single){
    uint32_t t=RT(i), a=RA(i), b=RB(i), c=(i>>6)&0x1F;
    auto fT=[&](){ return F("ctx->f[%u]",t); };
    auto wrap=[&](std::string e){ return single ? "(double)(float)(" + e + ")" : e; };
    uint32_t xo5 = (i>>1)&0x1F;
    switch(xo5){
    case 21: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u] + ctx->f[%u]",a,b)).c_str()); return;
    case 20: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u] - ctx->f[%u]",a,b)).c_str()); return;
    case 25: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u] * ctx->f[%u]",a,c)).c_str()); return;
    case 18: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u] / ctx->f[%u]",a,b)).c_str()); return;
    case 22: o+=F("%s = %s;\n",fT().c_str(),wrap(F("__builtin_sqrt(ctx->f[%u])",b)).c_str()); return;
    case 24: o+=F("%s = %s;\n",fT().c_str(),wrap(F("1.0/ctx->f[%u]",b)).c_str()); return;
    case 26: o+=F("%s = %s;\n",fT().c_str(),wrap(F("1.0/__builtin_sqrt(ctx->f[%u])",b)).c_str()); return;
    case 29: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u]*ctx->f[%u] + ctx->f[%u]",a,c,b)).c_str()); return;
    case 28: o+=F("%s = %s;\n",fT().c_str(),wrap(F("ctx->f[%u]*ctx->f[%u] - ctx->f[%u]",a,c,b)).c_str()); return;
    case 31: o+=F("%s = %s;\n",fT().c_str(),wrap(F("-(ctx->f[%u]*ctx->f[%u] + ctx->f[%u])",a,c,b)).c_str()); return;
    case 30: o+=F("%s = %s;\n",fT().c_str(),wrap(F("-(ctx->f[%u]*ctx->f[%u] - ctx->f[%u])",a,c,b)).c_str()); return;
    case 23: o+=F("%s = (ctx->f[%u] >= 0.0) ? ctx->f[%u] : ctx->f[%u];\n",fT().c_str(),a,c,b); return;
    }
    uint32_t xo=XO(i);
    switch(xo){
    case 0: case 32:
        o+=F("{ double x=ctx->f[%u],y=ctx->f[%u]; ctx->cr[%u]=(x!=x||y!=y)?1:(x<y?8:x>y?4:2); }\n",a,b,BF(i)); return;
    case 72:  o+=F("ctx->f[%u] = ctx->f[%u];\n",t,b); return;
    case 40:  o+=F("ctx->f[%u] = -ctx->f[%u];\n",t,b); return;
    case 264: o+=F("ctx->f[%u] = __builtin_fabs(ctx->f[%u]);\n",t,b); return;
    case 136: o+=F("ctx->f[%u] = -__builtin_fabs(ctx->f[%u]);\n",t,b); return;
    case 12:  o+=F("ctx->f[%u] = (double)(float)ctx->f[%u];\n",t,b); return;
    case 14: case 15:
        o+=F("{ double _d=ctx->f[%u]; int32_t v=_d>=2147483647.0?2147483647:_d<=-2147483648.0?(int32_t)-2147483648ll:(int32_t)_d; uint64_t u=(uint32_t)v; __builtin_memcpy(&ctx->f[%u],&u,8); }\n",b,t); return;
    case 814: case 815:
        o+=F("{ int64_t v=(int64_t)ctx->f[%u]; __builtin_memcpy(&ctx->f[%u],&v,8); }\n",b,t); return;
    case 846:
        o+=F("{ int64_t v; __builtin_memcpy(&v,&ctx->f[%u],8); ctx->f[%u]=(double)v; }\n",b,t); return;
    case 583:
        o+=F("{ uint64_t u=ctx->fpscr; __builtin_memcpy(&ctx->f[%u],&u,8); }\n",t); return;
    case 711:
        o+=F("{ uint64_t u; __builtin_memcpy(&u,&ctx->f[%u],8); ctx->fpscr=(uint32_t)u; }\n",b); return;
    case 70:  o+=F("ctx->fpscr &= ~(1u<<(31-%u));\n",t); return;
    case 38:  o+=F("ctx->fpscr |=  (1u<<(31-%u));\n",t); return;
    case 64:  o+=F("ctx->cr[%u] = (uint8_t)((ctx->fpscr>>(4*(7-%u)))&0xF);\n",BF(i),BFA(i)); return;
    case 134: o+="/* mtfsfi */\n"; return;
    default:  o+=F("ppu_unimpl(\"fpop\",0x%x);\n",addr); return;
    }
}

static void lift_vmx(std::string& o, uint32_t i, uint32_t addr){
    uint32_t vt=RT(i), va=RA(i), vb=RB(i), vc=(i>>6)&0x1F;
    auto V=[&](uint32_t r){ return F("&ctx->v[%u]",r); };

    uint32_t xo6 = i & 0x3F;
    switch(xo6){
    case 32: o+=F("ppu_vmhaddshs(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 33: o+=F("ppu_vmhraddshs(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 34: o+=F("ppu_vmladduhm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 36: o+=F("ppu_vmsumubm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 37: o+=F("ppu_vmsummbm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 38: o+=F("ppu_vmsumuhm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 39: o+=F("ppu_vmsumuhs(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 40: o+=F("ppu_vmsumshm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 41: o+=F("ppu_vmsumshs(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 42: o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=(ctx->v[%u].u32[k]&~ctx->v[%u].u32[k])|(ctx->v[%u].u32[k]&ctx->v[%u].u32[k]);\n",vt,va,vc,vb,vc); return;
    case 43: o+=F("ppu_vperm(%s,%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),V(vc).c_str()); return;
    case 44: o+=F("ppu_vsldoi(%s,%s,%s,%u);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str(),(i>>6)&0xF); return;
    case 46: o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=ctx->v[%u].f32[k]*ctx->v[%u].f32[k]+ctx->v[%u].f32[k];\n",vt,va,vc,vb); return;
    case 47: o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=ctx->v[%u].f32[k]-ctx->v[%u].f32[k]*ctx->v[%u].f32[k];\n",vt,vb,va,vc); return;
    default: break;
    }

    {
        uint32_t xo10 = i & 0x3FF; bool dot = (i>>10)&1;
        const char* cmp = nullptr; int lanes = 0; bool sgn=false;
        switch(xo10){
        case 6:   cmp="=="; lanes=16; break;
        case 70:  cmp="=="; lanes=8;  break;
        case 134: cmp="=="; lanes=4;  break;
        case 518: cmp=">";  lanes=16; break;
        case 582: cmp=">";  lanes=8;  break;
        case 646: cmp=">";  lanes=4;  break;
        case 774: cmp=">";  lanes=16; sgn=true; break;
        case 838: cmp=">";  lanes=8;  sgn=true; break;
        case 902: cmp=">";  lanes=4;  sgn=true; break;
        case 198: cmp="=="; lanes=-4; break;
        case 454: cmp=">="; lanes=-4; break;
        case 710: cmp=">";  lanes=-4; break;
        case 966:
            o+=F("for(int k=0;k<4;k++){ float x=ctx->v[%u].f32[k],y=ctx->v[%u].f32[k];"
                 " ctx->v[%u].u32[k]=((x<=y)?0u:0x80000000u)|((x>=-y)?0u:0x40000000u); }\n",va,vb,vt);
            if (dot) o+=F("{ uint32_t z=ctx->v[%u].u32[0]|ctx->v[%u].u32[1]|ctx->v[%u].u32[2]|ctx->v[%u].u32[3]; ctx->cr[6]=(uint8_t)(z?0:2); }\n",vt,vt,vt,vt);
            return;
        default: cmp=nullptr; break;
        }
        if (cmp){
            if (lanes==-4)
                o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=(ctx->v[%u].f32[k]%sctx->v[%u].f32[k])?0xFFFFFFFFu:0;\n",vt,va,cmp,vb);
            else if (lanes==4)
                o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=(%sctx->v[%u].u32[k] %s %sctx->v[%u].u32[k])?0xFFFFFFFFu:0;\n",
                     vt, sgn?"(int32_t)":"", va, cmp, sgn?"(int32_t)":"", vb);
            else if (lanes==8)
                o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(%sppu_vh(&ctx->v[%u],k) %s %sppu_vh(&ctx->v[%u],k))?0xFFFF:0);\n",
                     vt, sgn?"(int16_t)":"", va, cmp, sgn?"(int16_t)":"", vb);
            else
                o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(%sppu_vb(&ctx->v[%u],k) %s %sppu_vb(&ctx->v[%u],k))?0xFF:0);\n",
                     vt, sgn?"(int8_t)":"", va, cmp, sgn?"(int8_t)":"", vb);
            if (dot)
                o+=F("{ uint32_t _a=ctx->v[%u].u32[0]&ctx->v[%u].u32[1]&ctx->v[%u].u32[2]&ctx->v[%u].u32[3];"
                     " uint32_t _o=ctx->v[%u].u32[0]|ctx->v[%u].u32[1]|ctx->v[%u].u32[2]|ctx->v[%u].u32[3];"
                     " ctx->cr[6]=(uint8_t)(((_a==0xFFFFFFFFu)?8:0)|((_o==0)?2:0)); }\n",vt,vt,vt,vt,vt,vt,vt,vt);
            return;
        }
    }

    uint32_t xo = i & 0x7FF;
    auto w4 =[&](const char* expr){ o+=F("for(int k=0;k<4;k++) %s\n", F(expr,vt,va,vb).c_str()); };
    auto b16=[&](const char* expr){
        o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(uint8_t)(%s));\n", vt, F(expr,va,vb).c_str()); };
    auto h8 =[&](const char* expr){
        o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(uint16_t)(%s));\n", vt, F(expr,va,vb).c_str()); };
    switch(xo){
    case 0:    b16("ppu_vb(&ctx->v[%u],k)+ppu_vb(&ctx->v[%u],k)"); return;
    case 64:   h8 ("ppu_vh(&ctx->v[%u],k)+ppu_vh(&ctx->v[%u],k)"); return;
    case 128:  w4 ("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]+ctx->v[%u].u32[k];"); return;
    case 1024: b16("ppu_vb(&ctx->v[%u],k)-ppu_vb(&ctx->v[%u],k)"); return;
    case 1088: h8 ("ppu_vh(&ctx->v[%u],k)-ppu_vh(&ctx->v[%u],k)"); return;
    case 1152: w4 ("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]-ctx->v[%u].u32[k];"); return;
    case 384:  o+=F("for(int k=0;k<4;k++){ uint32_t _s=ctx->v[%u].u32[k]+ctx->v[%u].u32[k]; ctx->v[%u].u32[k]=(_s<ctx->v[%u].u32[k])?1u:0u; }\n",va,vb,vt,va); return;
    case 1408: o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=(ctx->v[%u].u32[k]>=ctx->v[%u].u32[k])?1u:0u;\n",vt,va,vb); return;
    case 512:  b16("ppu_satub((int32_t)ppu_vb(&ctx->v[%u],k)+ppu_vb(&ctx->v[%u],k))"); return;
    case 576:  h8 ("ppu_satuh((int32_t)ppu_vh(&ctx->v[%u],k)+ppu_vh(&ctx->v[%u],k))"); return;
    case 640:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=ppu_satuw((int64_t)ctx->v[%u].u32[k]+ctx->v[%u].u32[k]);\n",vt,va,vb); return;
    case 768:  b16("(uint8_t)ppu_satsb((int32_t)(int8_t)ppu_vb(&ctx->v[%u],k)+(int8_t)ppu_vb(&ctx->v[%u],k))"); return;
    case 832:  h8 ("(uint16_t)ppu_satsh((int32_t)(int16_t)ppu_vh(&ctx->v[%u],k)+(int16_t)ppu_vh(&ctx->v[%u],k))"); return;
    case 896:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].s32[k]=ppu_satsw((int64_t)ctx->v[%u].s32[k]+ctx->v[%u].s32[k]);\n",vt,va,vb); return;
    case 1536: b16("ppu_satub((int32_t)ppu_vb(&ctx->v[%u],k)-ppu_vb(&ctx->v[%u],k))"); return;
    case 1600: h8 ("ppu_satuh((int32_t)ppu_vh(&ctx->v[%u],k)-ppu_vh(&ctx->v[%u],k))"); return;
    case 1664: o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=ppu_satuw((int64_t)ctx->v[%u].u32[k]-ctx->v[%u].u32[k]);\n",vt,va,vb); return;
    case 1792: b16("(uint8_t)ppu_satsb((int32_t)(int8_t)ppu_vb(&ctx->v[%u],k)-(int8_t)ppu_vb(&ctx->v[%u],k))"); return;
    case 1856: h8 ("(uint16_t)ppu_satsh((int32_t)(int16_t)ppu_vh(&ctx->v[%u],k)-(int16_t)ppu_vh(&ctx->v[%u],k))"); return;
    case 1920: o+=F("for(int k=0;k<4;k++) ctx->v[%u].s32[k]=ppu_satsw((int64_t)ctx->v[%u].s32[k]-ctx->v[%u].s32[k]);\n",vt,va,vb); return;
    case 1026: b16("(uint8_t)(((uint32_t)ppu_vb(&ctx->v[%u],k)+ppu_vb(&ctx->v[%u],k)+1)>>1)"); return;
    case 1090: h8 ("(uint16_t)(((uint32_t)ppu_vh(&ctx->v[%u],k)+ppu_vh(&ctx->v[%u],k)+1)>>1)"); return;
    case 1154: o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=(uint32_t)(((uint64_t)ctx->v[%u].u32[k]+ctx->v[%u].u32[k]+1)>>1);\n",vt,va,vb); return;
    case 1282: b16("(uint8_t)(((int32_t)(int8_t)ppu_vb(&ctx->v[%u],k)+(int8_t)ppu_vb(&ctx->v[%u],k)+1)>>1)"); return;
    case 1346: h8 ("(uint16_t)(((int32_t)(int16_t)ppu_vh(&ctx->v[%u],k)+(int16_t)ppu_vh(&ctx->v[%u],k)+1)>>1)"); return;
    case 1410: o+=F("for(int k=0;k<4;k++) ctx->v[%u].s32[k]=(int32_t)(((int64_t)ctx->v[%u].s32[k]+ctx->v[%u].s32[k]+1)>>1);\n",vt,va,vb); return;
    case 2:    o+=F("for(int k=0;k<16;k++){ uint8_t x=ppu_vb(&ctx->v[%u],k),y=ppu_vb(&ctx->v[%u],k); ppu_vsb(&ctx->v[%u],k,x>y?x:y); }\n",va,vb,vt); return;
    case 66:   o+=F("for(int k=0;k<8;k++){ uint16_t x=ppu_vh(&ctx->v[%u],k),y=ppu_vh(&ctx->v[%u],k); ppu_vsh(&ctx->v[%u],k,x>y?x:y); }\n",va,vb,vt); return;
    case 130:  o+=F("for(int k=0;k<4;k++){ uint32_t x=ctx->v[%u].u32[k],y=ctx->v[%u].u32[k]; ctx->v[%u].u32[k]=x>y?x:y; }\n",va,vb,vt); return;
    case 258:  o+=F("for(int k=0;k<16;k++){ int8_t x=(int8_t)ppu_vb(&ctx->v[%u],k),y=(int8_t)ppu_vb(&ctx->v[%u],k); ppu_vsb(&ctx->v[%u],k,(uint8_t)(x>y?x:y)); }\n",va,vb,vt); return;
    case 322:  o+=F("for(int k=0;k<8;k++){ int16_t x=(int16_t)ppu_vh(&ctx->v[%u],k),y=(int16_t)ppu_vh(&ctx->v[%u],k); ppu_vsh(&ctx->v[%u],k,(uint16_t)(x>y?x:y)); }\n",va,vb,vt); return;
    case 386:  o+=F("for(int k=0;k<4;k++){ int32_t x=ctx->v[%u].s32[k],y=ctx->v[%u].s32[k]; ctx->v[%u].s32[k]=x>y?x:y; }\n",va,vb,vt); return;
    case 514:  o+=F("for(int k=0;k<16;k++){ uint8_t x=ppu_vb(&ctx->v[%u],k),y=ppu_vb(&ctx->v[%u],k); ppu_vsb(&ctx->v[%u],k,x<y?x:y); }\n",va,vb,vt); return;
    case 578:  o+=F("for(int k=0;k<8;k++){ uint16_t x=ppu_vh(&ctx->v[%u],k),y=ppu_vh(&ctx->v[%u],k); ppu_vsh(&ctx->v[%u],k,x<y?x:y); }\n",va,vb,vt); return;
    case 642:  o+=F("for(int k=0;k<4;k++){ uint32_t x=ctx->v[%u].u32[k],y=ctx->v[%u].u32[k]; ctx->v[%u].u32[k]=x<y?x:y; }\n",va,vb,vt); return;
    case 770:  o+=F("for(int k=0;k<16;k++){ int8_t x=(int8_t)ppu_vb(&ctx->v[%u],k),y=(int8_t)ppu_vb(&ctx->v[%u],k); ppu_vsb(&ctx->v[%u],k,(uint8_t)(x<y?x:y)); }\n",va,vb,vt); return;
    case 834:  o+=F("for(int k=0;k<8;k++){ int16_t x=(int16_t)ppu_vh(&ctx->v[%u],k),y=(int16_t)ppu_vh(&ctx->v[%u],k); ppu_vsh(&ctx->v[%u],k,(uint16_t)(x<y?x:y)); }\n",va,vb,vt); return;
    case 898:  o+=F("for(int k=0;k<4;k++){ int32_t x=ctx->v[%u].s32[k],y=ctx->v[%u].s32[k]; ctx->v[%u].s32[k]=x<y?x:y; }\n",va,vb,vt); return;
    case 1028: w4("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]&ctx->v[%u].u32[k];"); return;
    case 1092: w4("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]&~ctx->v[%u].u32[k];"); return;
    case 1156: w4("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]|ctx->v[%u].u32[k];"); return;
    case 1220: w4("ctx->v[%u].u32[k]=ctx->v[%u].u32[k]^ctx->v[%u].u32[k];"); return;
    case 1284: w4("ctx->v[%u].u32[k]=~(ctx->v[%u].u32[k]|ctx->v[%u].u32[k]);"); return;
    case 4:    o+=F("for(int k=0;k<16;k++){ uint8_t x=ppu_vb(&ctx->v[%u],k); int s=ppu_vb(&ctx->v[%u],k)&7; ppu_vsb(&ctx->v[%u],k,(uint8_t)((x<<s)|(x>>((8-s)&7)))); }\n",va,vb,vt); return;
    case 68:   o+=F("for(int k=0;k<8;k++){ uint16_t x=ppu_vh(&ctx->v[%u],k); int s=ppu_vh(&ctx->v[%u],k)&15; ppu_vsh(&ctx->v[%u],k,(uint16_t)((x<<s)|(x>>((16-s)&15)))); }\n",va,vb,vt); return;
    case 132:  o+=F("for(int k=0;k<4;k++){ uint32_t x=ctx->v[%u].u32[k]; int s=ctx->v[%u].u32[k]&31; ctx->v[%u].u32[k]=(x<<s)|(s?(x>>(32-s)):0); }\n",va,vb,vt); return;
    case 260:  o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(uint8_t)(ppu_vb(&ctx->v[%u],k)<<(ppu_vb(&ctx->v[%u],k)&7)));\n",vt,va,vb); return;
    case 324:  o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(uint16_t)(ppu_vh(&ctx->v[%u],k)<<(ppu_vh(&ctx->v[%u],k)&15)));\n",vt,va,vb); return;
    case 388:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=ctx->v[%u].u32[k]<<(ctx->v[%u].u32[k]&31);\n",vt,va,vb); return;
    case 516:  o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(uint8_t)(ppu_vb(&ctx->v[%u],k)>>(ppu_vb(&ctx->v[%u],k)&7)));\n",vt,va,vb); return;
    case 580:  o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(uint16_t)(ppu_vh(&ctx->v[%u],k)>>(ppu_vh(&ctx->v[%u],k)&15)));\n",vt,va,vb); return;
    case 644:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=ctx->v[%u].u32[k]>>(ctx->v[%u].u32[k]&31);\n",vt,va,vb); return;
    case 772:  o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(uint8_t)((int8_t)ppu_vb(&ctx->v[%u],k)>>(ppu_vb(&ctx->v[%u],k)&7)));\n",vt,va,vb); return;
    case 836:  o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(uint16_t)((int16_t)ppu_vh(&ctx->v[%u],k)>>(ppu_vh(&ctx->v[%u],k)&15)));\n",vt,va,vb); return;
    case 900:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].s32[k]=ctx->v[%u].s32[k]>>(ctx->v[%u].u32[k]&31);\n",vt,va,vb); return;
    case 452:  o+=F("ppu_vsl(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 708:  o+=F("ppu_vsr(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1036: o+=F("ppu_vslo(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1100: o+=F("ppu_vsro(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 8:    o+=F("ppu_vmule(%s,%s,%s,0,0,1);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 72:   o+=F("ppu_vmule(%s,%s,%s,1,0,1);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 264:  o+=F("ppu_vmule(%s,%s,%s,0,1,1);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 328:  o+=F("ppu_vmule(%s,%s,%s,1,1,1);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 520:  o+=F("ppu_vmule(%s,%s,%s,0,0,0);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 584:  o+=F("ppu_vmule(%s,%s,%s,1,0,0);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 776:  o+=F("ppu_vmule(%s,%s,%s,0,1,0);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 840:  o+=F("ppu_vmule(%s,%s,%s,1,1,0);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1544: o+=F("ppu_vsum4ubs(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1608: o+=F("ppu_vsum4shs(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1672: o+=F("ppu_vsum2sws(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1800: o+=F("ppu_vsum4sbs(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 1928: o+=F("ppu_vsumsws(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 10:   w4("ctx->v[%u].f32[k]=ctx->v[%u].f32[k]+ctx->v[%u].f32[k];"); return;
    case 74:   w4("ctx->v[%u].f32[k]=ctx->v[%u].f32[k]-ctx->v[%u].f32[k];"); return;
    case 1034: o+=F("for(int k=0;k<4;k++){ float x=ctx->v[%u].f32[k],y=ctx->v[%u].f32[k]; ctx->v[%u].f32[k]=x>y?x:y; }\n",va,vb,vt); return;
    case 1098: o+=F("for(int k=0;k<4;k++){ float x=ctx->v[%u].f32[k],y=ctx->v[%u].f32[k]; ctx->v[%u].f32[k]=x<y?x:y; }\n",va,vb,vt); return;
    case 266:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=1.0f/ctx->v[%u].f32[k];\n",vt,vb); return;
    case 330:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=1.0f/__builtin_sqrtf(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 394:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_exp2f(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 458:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_log2f(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 522:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_nearbyintf(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 586:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_truncf(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 650:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_ceilf(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 714:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=__builtin_floorf(ctx->v[%u].f32[k]);\n",vt,vb); return;
    case 842:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=(float)ctx->v[%u].s32[k]/(float)(1u<<%u);\n",vt,vb,va); return;
    case 778:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].f32[k]=(float)ctx->v[%u].u32[k]/(float)(1u<<%u);\n",vt,vb,va); return;
    case 970:  o+=F("for(int k=0;k<4;k++){ int ov=0; ctx->v[%u].s32[k]=(int32_t)ppu_satf2i(ctx->v[%u].f32[k]*(float)(1u<<%u),&ov); }\n",vt,vb,va); return;
    case 906:  o+=F("for(int k=0;k<4;k++){ double d=(double)ctx->v[%u].f32[k]*(double)(1u<<%u); ctx->v[%u].u32[k]=d<0?0u:d>4294967295.0?0xFFFFFFFFu:(uint32_t)d; }\n",vb,va,vt); return;
    case 524:  o+=F("{ uint8_t s=ppu_vb(&ctx->v[%u],%u); for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,s); }\n",vb,va&15,vt); return;
    case 588:  o+=F("{ uint16_t s=ppu_vh(&ctx->v[%u],%u); for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,s); }\n",vb,va&7,vt); return;
    case 652:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=ctx->v[%u].u32[%u];\n",vt,vb,va&3); return;
    case 780:  o+=F("for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(uint8_t)%d);\n",vt,(int)((va<<27))>>27); return;
    case 844:  o+=F("for(int k=0;k<8;k++) ppu_vsh(&ctx->v[%u],k,(uint16_t)%d);\n",vt,(int)((va<<27))>>27); return;
    case 908:  o+=F("for(int k=0;k<4;k++) ctx->v[%u].s32[k]=(int32_t)(%d);\n",vt,(int)((va<<27))>>27); return;
    case 12:   o+=F("{ PPUVec r; for(int k=0;k<8;k++){ ppu_vsb(&r,2*k,ppu_vb(&ctx->v[%u],k)); ppu_vsb(&r,2*k+1,ppu_vb(&ctx->v[%u],k)); } ctx->v[%u]=r; }\n",va,vb,vt); return;
    case 76:   o+=F("{ PPUVec r; for(int k=0;k<4;k++){ ppu_vsh(&r,2*k,ppu_vh(&ctx->v[%u],k)); ppu_vsh(&r,2*k+1,ppu_vh(&ctx->v[%u],k)); } ctx->v[%u]=r; }\n",va,vb,vt); return;
    case 140:  o+=F("{ PPUVec r; r.u32[0]=ctx->v[%u].u32[0]; r.u32[1]=ctx->v[%u].u32[0]; r.u32[2]=ctx->v[%u].u32[1]; r.u32[3]=ctx->v[%u].u32[1]; ctx->v[%u]=r; }\n",va,vb,va,vb,vt); return;
    case 268:  o+=F("{ PPUVec r; for(int k=0;k<8;k++){ ppu_vsb(&r,2*k,ppu_vb(&ctx->v[%u],8+k)); ppu_vsb(&r,2*k+1,ppu_vb(&ctx->v[%u],8+k)); } ctx->v[%u]=r; }\n",va,vb,vt); return;
    case 332:  o+=F("{ PPUVec r; for(int k=0;k<4;k++){ ppu_vsh(&r,2*k,ppu_vh(&ctx->v[%u],4+k)); ppu_vsh(&r,2*k+1,ppu_vh(&ctx->v[%u],4+k)); } ctx->v[%u]=r; }\n",va,vb,vt); return;
    case 396:  o+=F("{ PPUVec r; r.u32[0]=ctx->v[%u].u32[2]; r.u32[1]=ctx->v[%u].u32[2]; r.u32[2]=ctx->v[%u].u32[3]; r.u32[3]=ctx->v[%u].u32[3]; ctx->v[%u]=r; }\n",va,vb,va,vb,vt); return;
    case 14:   o+=F("ppu_vpkuhum(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 78:   o+=F("ppu_vpkuwum(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 142:  o+=F("ppu_vpkuhus(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 206:  o+=F("ppu_vpkuwus(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 270:  o+=F("ppu_vpkshus(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 334:  o+=F("ppu_vpkswus(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 398:  o+=F("ppu_vpkshss(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 462:  o+=F("ppu_vpkswss(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 782:  o+=F("ppu_vpkpx(%s,%s,%s);\n",V(vt).c_str(),V(va).c_str(),V(vb).c_str()); return;
    case 526:  o+=F("ppu_vupkhsb(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 590:  o+=F("ppu_vupkhsh(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 654:  o+=F("ppu_vupklsb(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 718:  o+=F("ppu_vupklsh(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 846:  o+=F("ppu_vupkhpx(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 974:  o+=F("ppu_vupklpx(%s,%s);\n",V(vt).c_str(),V(vb).c_str()); return;
    case 1540: o+=F("for(int k=0;k<4;k++) ctx->v[%u].u32[k]=0;\n",vt); return;
    case 1604: o+="/* mtvscr */\n"; return;
    }
    o+=F("ppu_unimpl(\"vmx\",0x%x);\n",addr);
}

static bool lift_insn(std::string& o, const ElfImage& elf, uint32_t i, uint32_t addr,
                      uint32_t start, uint32_t end, std::set<uint32_t>& called){
    Instr di = ppu_decode(i, addr);
    o += F("    /* %08x  %s */\n    ", addr, di.text().c_str());
    uint32_t op = OPCD(i);
    uint32_t next = addr + 4;

    auto rT=[&](){ return F("ctx->r[%u]",RT(i)); };
    auto rA=[&](){ return F("ctx->r[%u]",RA(i)); };
    auto rB=[&](){ return F("ctx->r[%u]",RB(i)); };
    auto rS=[&](){ return F("ctx->r[%u]",RT(i)); };

    auto branch_to=[&](uint32_t tgt, bool link)->void{
        if (link) o += F("ctx->lr = 0x%xull; ", next);
        if (tgt>=start && tgt<end && !link){ o += F("goto loc_%x;\n", tgt); }
        else { called.insert(tgt); o += F("sub_%x(ctx, base);%s\n", tgt, link?"":" return;"); }
    };

    switch(op){
    case 3:  o+="/* twi (trap ignored) */\n"; break;
    case 14: if(RA(i)==0) o+=F("%s = (uint64_t)(int64_t)%d;\n",rT().c_str(),Dimm(i));
             else o+=F("%s = %s + (int64_t)%d;\n",rT().c_str(),rA().c_str(),Dimm(i)); break;
    case 15: if(RA(i)==0) o+=F("%s = (uint64_t)(int64_t)(%d << 16);\n",rT().c_str(),(int)(int16_t)UI(i));
             else o+=F("%s = %s + (int64_t)(%d << 16);\n",rT().c_str(),rA().c_str(),(int)(int16_t)UI(i)); break;
    case 12: o+=F("{ uint64_t a=%s, r=a+(uint64_t)(int64_t)%d; ctx->ca=(r<a); %s=r; }\n",
                  rA().c_str(),Dimm(i),rT().c_str()); break;
    case 13: o+=F("{ uint64_t a=%s, r=a+(uint64_t)(int64_t)%d; ctx->ca=(r<a); %s=r; ppu_cr0(ctx,(int64_t)r); }\n",
                  rA().c_str(),Dimm(i),rT().c_str()); break;
    case 8:  o+=F("{ uint64_t a=%s, im=(uint64_t)(int64_t)%d, r=im-a; ctx->ca=(im>=a); %s=r; }\n",
                  rA().c_str(),Dimm(i),rT().c_str()); break;
    case 7:  o+=F("%s = (uint64_t)((int64_t)%s * (int64_t)%d);\n",rT().c_str(),rA().c_str(),Dimm(i)); break;
    case 24: o+=F("%s = %s | %uu;\n",rA().c_str(),rS().c_str(),UI(i)); break;
    case 25: o+=F("%s = %s | ((uint64_t)%uu << 16);\n",rA().c_str(),rS().c_str(),UI(i)); break;
    case 26: o+=F("%s = %s ^ %uu;\n",rA().c_str(),rS().c_str(),UI(i)); break;
    case 27: o+=F("%s = %s ^ ((uint64_t)%uu << 16);\n",rA().c_str(),rS().c_str(),UI(i)); break;
    case 28: o+=F("%s = %s & %uu; ppu_cr0(ctx,(int64_t)%s);\n",rA().c_str(),rS().c_str(),UI(i),rA().c_str()); break;
    case 29: o+=F("%s = %s & ((uint64_t)%uu << 16); ppu_cr0(ctx,(int64_t)%s);\n",rA().c_str(),rS().c_str(),UI(i),rA().c_str()); break;
    case 11: o+=F("ppu_setcrf_s(ctx,%u,%s%s,(int64_t)%d);\n",BF(i),
                  Lbit(i)?"(int64_t)":"(int64_t)(int32_t)",rA().c_str(),Dimm(i)); break;
    case 10: o+=F("ppu_setcrf_u(ctx,%u,%s%s,(uint64_t)%uu);\n",BF(i),
                  Lbit(i)?"(uint64_t)":"(uint64_t)(uint32_t)",rA().c_str(),UI(i)); break;
    case 21: o+=F("%s = ppu_rotl32((uint32_t)%s,%u) & ppu_mask32(%u,%u);",rA().c_str(),rS().c_str(),SH(i),MB(i),ME(i)); rc0(o,i); o+="\n"; break;
    case 23: o+=F("%s = ppu_rotl32((uint32_t)%s,(uint32_t)%s&31) & ppu_mask32(%u,%u);",rA().c_str(),rS().c_str(),rB().c_str(),MB(i),ME(i)); rc0(o,i); o+="\n"; break;
    case 20: o+=F("{ uint32_t m=ppu_mask32(%u,%u); %s=((uint32_t)%s & ~m)|(ppu_rotl32((uint32_t)%s,%u)&m); }",MB(i),ME(i),rA().c_str(),rA().c_str(),rS().c_str(),SH(i)); rc0(o,i); o+="\n"; break;
    case 30: { uint32_t x=(i>>2)&7, sh=SH6(i), mb=MB6(i);
        if(x==0) o+=F("%s = ppu_rotl64(%s,%u) & ppu_mask64(%u,63);",rA().c_str(),rS().c_str(),sh,mb);
        else if(x==1) o+=F("%s = ppu_rotl64(%s,%u) & ppu_mask64(0,%u);",rA().c_str(),rS().c_str(),sh,mb);
        else if(x==2) o+=F("%s = ppu_rotl64(%s,%u) & ppu_mask64(%u,%u);",rA().c_str(),rS().c_str(),sh,mb,63-sh);
        else if(x==3) o+=F("{ uint64_t m=ppu_mask64(%u,%u); %s=(%s&~m)|(ppu_rotl64(%s,%u)&m); }",mb,63-sh,rA().c_str(),rA().c_str(),rS().c_str(),sh);
        else if(x==4){
            uint32_t isr=(i>>1)&1; uint32_t m=MB6(i);
            if(!isr) o+=F("%s = ppu_rotl64(%s,(uint32_t)%s&63) & ppu_mask64(%u,63);",rA().c_str(),rS().c_str(),rB().c_str(),m);
            else     o+=F("%s = ppu_rotl64(%s,(uint32_t)%s&63) & ppu_mask64(0,%u);",rA().c_str(),rS().c_str(),rB().c_str(),m);
        }
        else { o+=F("ppu_unimpl(\"rldc\",0x%x);",addr); }
        rc0(o,i); o+="\n"; } break;
    case 32: o+=F("%s = (uint32_t)PPU_LW(base,%s);\n",rT().c_str(),ea_d(i).c_str()); break;
    case 33: o+=F("%s=(uint32_t)PPU_LW(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",rT().c_str(),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 34: o+=F("%s = (uint8_t)PPU_LB(base,%s);\n",rT().c_str(),ea_d(i).c_str()); break;
    case 35: o+=F("%s=(uint8_t)PPU_LB(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",rT().c_str(),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 40: o+=F("%s = (uint16_t)PPU_LH(base,%s);\n",rT().c_str(),ea_d(i).c_str()); break;
    case 41: o+=F("%s=(uint16_t)PPU_LH(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",rT().c_str(),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 42: o+=F("%s = (uint64_t)(int64_t)(int16_t)PPU_LH(base,%s);\n",rT().c_str(),ea_d(i).c_str()); break;
    case 43: o+=F("%s=(uint64_t)(int64_t)(int16_t)PPU_LH(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",rT().c_str(),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 46: o+=F("{ uint32_t e=%s; for(int r=%u;r<32;r++){ ctx->r[r]=(uint32_t)PPU_LW(base,e); e+=4; } }\n",
                  ea_d(i).c_str(),RT(i)); break;
    case 47: o+=F("{ uint32_t e=%s; for(int r=%u;r<32;r++){ PPU_STW(base,e,(uint32_t)ctx->r[r]); e+=4; } }\n",
                  ea_d(i).c_str(),RT(i)); break;
    case 36: o+=F("PPU_STW(base,%s,(uint32_t)%s);\n",ea_d(i).c_str(),rS().c_str()); break;
    case 37: o+=F("PPU_STW(base,(uint32_t)(ctx->r[%u]+%d),(uint32_t)%s); ctx->r[%u]+=%d;\n",RA(i),Dimm(i),rS().c_str(),RA(i),Dimm(i)); break;
    case 38: o+=F("PPU_STB(base,%s,(uint8_t)%s);\n",ea_d(i).c_str(),rS().c_str()); break;
    case 39: o+=F("PPU_STB(base,(uint32_t)(ctx->r[%u]+%d),(uint8_t)%s); ctx->r[%u]+=%d;\n",RA(i),Dimm(i),rS().c_str(),RA(i),Dimm(i)); break;
    case 44: o+=F("PPU_STH(base,%s,(uint16_t)%s);\n",ea_d(i).c_str(),rS().c_str()); break;
    case 45: o+=F("PPU_STH(base,(uint32_t)(ctx->r[%u]+%d),(uint16_t)%s); ctx->r[%u]+=%d;\n",RA(i),Dimm(i),rS().c_str(),RA(i),Dimm(i)); break;
    case 48: o+=F("ctx->f[%u] = (double)PPU_LFS(base,%s);\n",RT(i),ea_d(i).c_str()); break;
    case 49: o+=F("ctx->f[%u]=(double)PPU_LFS(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",RT(i),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 50: o+=F("ctx->f[%u] = PPU_LFD(base,%s);\n",RT(i),ea_d(i).c_str()); break;
    case 51: o+=F("ctx->f[%u]=PPU_LFD(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",RT(i),RA(i),Dimm(i),RA(i),Dimm(i)); break;
    case 52: o+=F("PPU_STFS(base,%s,(float)ctx->f[%u]);\n",ea_d(i).c_str(),RT(i)); break;
    case 53: o+=F("PPU_STFS(base,(uint32_t)(ctx->r[%u]+%d),(float)ctx->f[%u]); ctx->r[%u]+=%d;\n",RA(i),Dimm(i),RT(i),RA(i),Dimm(i)); break;
    case 54: o+=F("PPU_STFD(base,%s,ctx->f[%u]);\n",ea_d(i).c_str(),RT(i)); break;
    case 55: o+=F("PPU_STFD(base,(uint32_t)(ctx->r[%u]+%d),ctx->f[%u]); ctx->r[%u]+=%d;\n",RA(i),Dimm(i),RT(i),RA(i),Dimm(i)); break;
    case 59: lift_fp(o,i,addr,true);  break;
    case 63: lift_fp(o,i,addr,false); break;
    case 58: { int32_t ds=(int16_t)(i&0xFFFC);
        if((i&3)==0) o+=F("%s = PPU_LD(base,%s);\n",rT().c_str(),(RA(i)?F("(uint32_t)(ctx->r[%u]+%d)",RA(i),ds):F("(uint32_t)(%d)",ds)).c_str());
        else if((i&3)==1) o+=F("%s=PPU_LD(base,(uint32_t)(ctx->r[%u]+%d)); ctx->r[%u]+=%d;\n",rT().c_str(),RA(i),ds,RA(i),ds);
        else o+=F("%s = (uint64_t)(int64_t)(int32_t)PPU_LW(base,%s);\n",rT().c_str(),(RA(i)?F("(uint32_t)(ctx->r[%u]+%d)",RA(i),ds):F("(uint32_t)(%d)",ds)).c_str());
        } break;
    case 62: { int32_t ds=(int16_t)(i&0xFFFC);
        if((i&3)==0) o+=F("PPU_STD(base,%s,%s);\n",(RA(i)?F("(uint32_t)(ctx->r[%u]+%d)",RA(i),ds):F("(uint32_t)(%d)",ds)).c_str(),rS().c_str());
        else o+=F("PPU_STD(base,(uint32_t)(ctx->r[%u]+%d),%s); ctx->r[%u]+=%d;\n",RA(i),ds,rS().c_str(),RA(i),ds);
        } break;
    case 16: { int32_t bd=(int16_t)(i&0xFFFC); uint32_t tgt=AA(i)?(uint32_t)bd:addr+bd;
        std::string pre; std::string cond=branch_cond(i,pre);
        o+=F("%sif (%s) { ",pre.c_str(),cond.c_str());
        if(LK(i)){ o+=F("ctx->lr=0x%xull; sub_%x(ctx,base); ",next,tgt); called.insert(tgt); }
        else if(tgt>=start&&tgt<end){ o+=F("goto loc_%x; ",tgt); }
        else { o+=F("sub_%x(ctx,base); return; ",tgt); called.insert(tgt); }
        o+="}\n"; } break;
    case 18: { int32_t li=(int32_t)(i&0x03FFFFFC); li<<=6; li>>=6; uint32_t tgt=AA(i)?(uint32_t)li:addr+li;
        branch_to(tgt, LK(i)); if(!LK(i)) return true; } break;
    case 19: { uint32_t xo=XO(i);
        if(xo==16){
            if(BO(i)==20){ o+="return;\n"; return true; }
            std::string pre,cond=branch_cond(i,pre); o+=F("%sif(%s) return;\n",pre.c_str(),cond.c_str());
        } else if(xo==528){
            if(BO(i)==20){ if(LK(i)) o+=F("ctx->lr=0x%xull; { PPCFunc f=ppu_lookup_ex((uint32_t)ctx->ctr,ctx); f(ctx,base); }\n",next);
                           else { o+=F("PPU_DBG_BCTR(ctx,0x%xu); { PPCFunc f=ppu_lookup_ex((uint32_t)ctx->ctr,ctx); f(ctx,base); } return;\n",addr); return true; } }
            else { std::string pre,cond=branch_cond(i,pre); o+=F("%sif(%s){ PPCFunc f=ppu_lookup_ex((uint32_t)ctx->ctr,ctx); f(ctx,base); %s}\n",pre.c_str(),cond.c_str(),LK(i)?"":"return; "); }
        } else if(xo==0)   o+=F("ctx->cr[%u] = ctx->cr[%u];\n",BF(i),BFA(i));
        else if(xo==257) o+=F("ppu_setcrbit(ctx,%u, ppu_crbit(ctx,%u)&ppu_crbit(ctx,%u));\n",RT(i),RA(i),RB(i));
        else if(xo==449) o+=F("ppu_setcrbit(ctx,%u, ppu_crbit(ctx,%u)|ppu_crbit(ctx,%u));\n",RT(i),RA(i),RB(i));
        else if(xo==193) o+=F("ppu_setcrbit(ctx,%u, ppu_crbit(ctx,%u)^ppu_crbit(ctx,%u));\n",RT(i),RA(i),RB(i));
        else if(xo==417) o+=F("ppu_setcrbit(ctx,%u, ppu_crbit(ctx,%u)|(ppu_crbit(ctx,%u)^1u));\n",RT(i),RA(i),RB(i));
        else if(xo==129) o+=F("ppu_setcrbit(ctx,%u, ppu_crbit(ctx,%u)&(ppu_crbit(ctx,%u)^1u));\n",RT(i),RA(i),RB(i));
        else if(xo==225) o+=F("ppu_setcrbit(ctx,%u, (ppu_crbit(ctx,%u)&ppu_crbit(ctx,%u))^1u);\n",RT(i),RA(i),RB(i));
        else if(xo==33)  o+=F("ppu_setcrbit(ctx,%u, (ppu_crbit(ctx,%u)|ppu_crbit(ctx,%u))^1u);\n",RT(i),RA(i),RB(i));
        else if(xo==289) o+=F("ppu_setcrbit(ctx,%u, (ppu_crbit(ctx,%u)^ppu_crbit(ctx,%u))^1u);\n",RT(i),RA(i),RB(i));
        else if(xo==150) o+="/* isync */\n";
        else o+=F("ppu_unimpl(\"%s\",0x%x);\n",di.mnem.c_str(),addr);
        } break;
    case 17: o+="ppu_syscall(ctx, base);\n"; break;
    case 4:  lift_vmx(o,i,addr); break;
    case 31: { uint32_t xo=XO(i);
        switch(xo){
        case 4:   o+="/* tw (trap ignored) */\n"; break;
        case 266: o+=F("%s = %s + %s;",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 40:  o+=F("%s = %s - %s;",rT().c_str(),rB().c_str(),rA().c_str()); rc0t(o,i); o+="\n"; break;
        case 10:  o+=F("{ uint64_t a=%s,b=%s,r=a+b; ctx->ca=(r<a); %s=r;",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 138: o+=F("{ uint64_t a=%s,b=%s,c=ctx->ca,r=a+b+c; ctx->ca=(r<a)||(c&&r==a); %s=r;",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 8:   o+=F("{ uint64_t a=%s,b=%s,r=b-a; ctx->ca=(b>=a); %s=r;",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 136: o+=F("{ uint64_t a=%s,b=%s,c=ctx->ca,r=b+~a+c; ctx->ca=(r<b)||(c&&r==b); %s=r;",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 202: o+=F("{ uint64_t a=%s,c=ctx->ca,r=a+c; ctx->ca=(r<a); %s=r;",rA().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 200: o+=F("{ uint64_t a=%s,c=ctx->ca,r=~a+c; ctx->ca=(c&&r==0); %s=r;",rA().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 234: o+=F("{ uint64_t a=%s,c=ctx->ca,r=a+c+0xFFFFFFFFFFFFFFFFull; ctx->ca=(a!=0)||c; %s=r;",rA().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 232:
                  o+=F("{ uint64_t a=%s,c=ctx->ca,s=~a,r=s+c+0xFFFFFFFFFFFFFFFFull; ctx->ca=(s!=0)||(c!=0); %s=r;",rA().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 104: o+=F("%s = (uint64_t)(- (int64_t)%s);",rT().c_str(),rA().c_str()); rc0t(o,i); o+="\n"; break;
        case 235: o+=F("%s = (uint64_t)((int64_t)(int32_t)%s * (int64_t)(int32_t)%s);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 75:  o+=F("%s = (uint64_t)(int64_t)(int32_t)(((int64_t)(int32_t)%s * (int64_t)(int32_t)%s) >> 32);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 11:  o+=F("%s = (uint64_t)(uint32_t)(((uint64_t)(uint32_t)%s * (uint64_t)(uint32_t)%s) >> 32);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 233: o+=F("%s = (uint64_t)((int64_t)%s * (int64_t)%s);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 73:  o+=F("%s = (uint64_t)(int64_t)(((__int128)(int64_t)%s * (int64_t)%s) >> 64);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 9:   o+=F("%s = (uint64_t)(((unsigned __int128)(uint64_t)%s * (uint64_t)%s) >> 64);",rT().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 491: o+=F("{ int32_t a=(int32_t)%s,b=(int32_t)%s; %s=(uint64_t)(int64_t)((b!=0 && !(a==(-2147483647-1)&&b==-1)) ? a/b : 0);",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 459: o+=F("%s = (uint64_t)(uint32_t)((uint32_t)%s ? (uint32_t)%s/(uint32_t)%s : 0);",rT().c_str(),rB().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 489: o+=F("{ int64_t a=(int64_t)%s,b=(int64_t)%s; %s=(uint64_t)((b!=0 && !(a==(-9223372036854775807ll-1)&&b==-1)) ? a/b : 0);",rA().c_str(),rB().c_str(),rT().c_str()); rc0t(o,i); o+=" }\n"; break;
        case 457: o+=F("%s = (%s ? %s/%s : 0);",rT().c_str(),rB().c_str(),rA().c_str(),rB().c_str()); rc0t(o,i); o+="\n"; break;
        case 28:  o+=F("%s = %s & %s;",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 444: o+=F("%s = %s | %s;",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 316: o+=F("%s = %s ^ %s;",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 476: o+=F("%s = ~(%s & %s);",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 124: o+=F("%s = ~(%s | %s);",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 60:  o+=F("%s = %s & ~%s;",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 412: o+=F("%s = %s | ~%s;",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 284: o+=F("%s = ~(%s ^ %s);",rA().c_str(),rS().c_str(),rB().c_str()); rc0(o,i); o+="\n"; break;
        case 954: o+=F("%s = (uint64_t)(int64_t)(int8_t)%s;",rA().c_str(),rS().c_str()); rc0(o,i); o+="\n"; break;
        case 922: o+=F("%s = (uint64_t)(int64_t)(int16_t)%s;",rA().c_str(),rS().c_str()); rc0(o,i); o+="\n"; break;
        case 986: o+=F("%s = (uint64_t)(int64_t)(int32_t)%s;",rA().c_str(),rS().c_str()); rc0(o,i); o+="\n"; break;
        case 26:  o+=F("%s = (uint64_t)((uint32_t)%s ? (uint32_t)__builtin_clz((uint32_t)%s) : 32u);",rA().c_str(),rS().c_str(),rS().c_str()); rc0(o,i); o+="\n"; break;
        case 58:  o+=F("%s = (uint64_t)(%s ? __builtin_clzll(%s) : 64);",rA().c_str(),rS().c_str(),rS().c_str()); rc0(o,i); o+="\n"; break;
        case 122: o+=F("{ uint64_t s=%s,r=0; for(int b=0;b<8;b++){ uint64_t byte=(s>>(8*b))&0xFF; r|=(uint64_t)__builtin_popcountll(byte)<<(8*b); } %s=r; }\n",rS().c_str(),rA().c_str()); break;
        case 24:  o+=F("{ uint32_t s=(uint32_t)%s&0x3F; %s = (s<32)?((uint64_t)((uint32_t)%s<<s)):0;",rB().c_str(),rA().c_str(),rS().c_str()); rc0(o,i); o+=" }\n"; break;
        case 536: o+=F("{ uint32_t s=(uint32_t)%s&0x3F; %s = (s<32)?((uint64_t)((uint32_t)%s>>s)):0;",rB().c_str(),rA().c_str(),rS().c_str()); rc0(o,i); o+=" }\n"; break;
        case 792: o+=F("{ int32_t v=(int32_t)%s; uint32_t s=(uint32_t)%s&0x3F; if(s>31)s=31; ctx->ca=(v<0)&&((v&(int32_t)((1u<<s)-1u))!=0); %s=(uint64_t)(int64_t)(v>>s);",rS().c_str(),rB().c_str(),rA().c_str()); rc0(o,i); o+=" }\n"; break;
        case 824: { uint32_t s=SH(i); o+=F("{ int32_t v=(int32_t)%s; ctx->ca=(v<0)&&((v&(int32_t)((1u<<%u)-1u))!=0); %s=(uint64_t)(int64_t)(v>>%u);",rS().c_str(),s,rA().c_str(),s); rc0(o,i); o+=" }\n"; } break;
        case 27:  o+=F("{ uint32_t s=(uint32_t)%s&0x7F; %s = (s<64)?(%s<<s):0;",rB().c_str(),rA().c_str(),rS().c_str()); rc0(o,i); o+=" }\n"; break;
        case 539: o+=F("{ uint32_t s=(uint32_t)%s&0x7F; %s = (s<64)?(%s>>s):0;",rB().c_str(),rA().c_str(),rS().c_str()); rc0(o,i); o+=" }\n"; break;
        case 794: o+=F("{ int64_t v=(int64_t)%s; uint32_t s=(uint32_t)%s&0x7F; if(s>63)s=63; ctx->ca=(v<0)&&((v&(int64_t)(((uint64_t)1<<s)-1))!=0); %s=(uint64_t)(v>>s);",rS().c_str(),rB().c_str(),rA().c_str()); rc0(o,i); o+=" }\n"; break;
        case 826: case 827: { uint32_t s=SH6(i); o+=F("{ int64_t v=(int64_t)%s; ctx->ca=(v<0)&&((v&(int64_t)(((uint64_t)1<<%u)-1))!=0); %s=(uint64_t)(v>>%u);",rS().c_str(),s,rA().c_str(),s); rc0(o,i); o+=" }\n"; } break;
        case 0:   o+=F("ppu_setcrf_s(ctx,%u,%s%s,%s%s);\n",BF(i),Lbit(i)?"(int64_t)":"(int64_t)(int32_t)",rA().c_str(),Lbit(i)?"(int64_t)":"(int64_t)(int32_t)",rB().c_str()); break;
        case 32:  o+=F("ppu_setcrf_u(ctx,%u,%s%s,%s%s);\n",BF(i),Lbit(i)?"(uint64_t)":"(uint64_t)(uint32_t)",rA().c_str(),Lbit(i)?"(uint64_t)":"(uint64_t)(uint32_t)",rB().c_str()); break;
        case 339: { uint32_t spr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5);
            if(spr==8) o+=F("%s = ctx->lr;\n",rT().c_str());
            else if(spr==9) o+=F("%s = ctx->ctr;\n",rT().c_str());
            else if(spr==1) o+=F("%s = ((uint64_t)ctx->so<<31)|((uint64_t)ctx->ov<<30)|((uint64_t)ctx->ca<<29);\n",rT().c_str());
            else if(spr==268) o+=F("%s = ppu_timebase();\n",rT().c_str());
            else if(spr==269) o+=F("%s = ppu_timebase()>>32;\n",rT().c_str());
            else if(spr==256) o+=F("%s = ctx->vrsave;\n",rT().c_str());
            else o+=F("ppu_unimpl(\"mfspr\",0x%x);\n",addr); } break;
        case 371: { uint32_t tbr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5);
            if(tbr==269) o+=F("%s = ppu_timebase()>>32;\n",rT().c_str());
            else o+=F("%s = ppu_timebase();\n",rT().c_str()); } break;
        case 467: { uint32_t spr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5);
            if(spr==8) o+=F("ctx->lr = %s;\n",rT().c_str());
            else if(spr==9) o+=F("ctx->ctr = %s;\n",rT().c_str());
            else if(spr==1) o+=F("{ uint64_t x=%s; ctx->so=(x>>31)&1; ctx->ov=(x>>30)&1; ctx->ca=(x>>29)&1; }\n",rT().c_str());
            else if(spr==256) o+=F("ctx->vrsave = (uint32_t)%s;\n",rT().c_str());
            else o+=F("ppu_unimpl(\"mtspr\",0x%x);\n",addr); } break;
        case 19:  o+=F("{ uint32_t cr=0; for(int n=0;n<8;n++) cr=(cr<<4)|ctx->cr[n]; %s=cr; }\n",rT().c_str()); break;
        case 144: { uint32_t fxm=(i>>12)&0xFF; o+=F("{ uint32_t s=(uint32_t)%s; for(int n=0;n<8;n++) if(%u&(0x80>>n)) ctx->cr[n]=(s>>(4*(7-n)))&0xF; }\n",rT().c_str(),fxm); } break;
        case 512: o+=F("ctx->cr[%u]=(uint8_t)((ctx->so?8:0)|(ctx->ov?4:0)|(ctx->ca?2:0)); ctx->so=0; ctx->ov=0; ctx->ca=0;\n",BF(i)); break;
        case 23:  o+=F("%s = (uint32_t)PPU_LW(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 55:  o+=F("%s = (uint32_t)PPU_LW(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",rT().c_str(),RA(i),RB(i),RA(i),RB(i)); break;
        case 87:  o+=F("%s = (uint8_t)PPU_LB(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 119: o+=F("%s = (uint8_t)PPU_LB(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",rT().c_str(),RA(i),RB(i),RA(i),RB(i)); break;
        case 279: o+=F("%s = (uint16_t)PPU_LH(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 311: o+=F("%s = (uint16_t)PPU_LH(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",rT().c_str(),RA(i),RB(i),RA(i),RB(i)); break;
        case 343: o+=F("%s = (uint64_t)(int64_t)(int16_t)PPU_LH(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 341: o+=F("%s = (uint64_t)(int64_t)(int32_t)PPU_LW(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 21:  o+=F("%s = PPU_LD(base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 53:  o+=F("%s = PPU_LD(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",rT().c_str(),RA(i),RB(i),RA(i),RB(i)); break;
        case 151: o+=F("PPU_STW(base,%s,(uint32_t)%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 183: o+=F("PPU_STW(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),(uint32_t)%s); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),rS().c_str(),RA(i),RB(i)); break;
        case 215: o+=F("PPU_STB(base,%s,(uint8_t)%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 247: o+=F("PPU_STB(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),(uint8_t)%s); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),rS().c_str(),RA(i),RB(i)); break;
        case 407: o+=F("PPU_STH(base,%s,(uint16_t)%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 439: o+=F("PPU_STH(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),(uint16_t)%s); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),rS().c_str(),RA(i),RB(i)); break;
        case 149: o+=F("PPU_STD(base,%s,%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 181: o+=F("PPU_STD(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),%s); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),rS().c_str(),RA(i),RB(i)); break;
        case 534: o+=F("{ uint32_t v; __builtin_memcpy(&v, base+(%s), 4); %s=v; }\n",ea_x(i).c_str(),rT().c_str()); break;
        case 790: o+=F("{ uint16_t v; __builtin_memcpy(&v, base+(%s), 2); %s=v; }\n",ea_x(i).c_str(),rT().c_str()); break;
        case 662: o+=F("{ uint32_t v=(uint32_t)%s; __builtin_memcpy(base+(%s), &v, 4); }\n",rS().c_str(),ea_x(i).c_str()); break;
        case 918: o+=F("{ uint16_t v=(uint16_t)%s; __builtin_memcpy(base+(%s), &v, 2); }\n",rS().c_str(),ea_x(i).c_str()); break;
        case 597: { uint32_t nb=RB(i)?RB(i):32;
            o+=F("{ uint32_t e=%s; int n=%u; int r=%u; while(n>0){ uint32_t v=0; for(int k=0;k<4;k++){ v<<=8; if(n>0){ v|=PPU_LB(base,e); e++; n--; } } ctx->r[r]=v; r=(r+1)&31; } }\n",
                 (RA(i)?F("(uint32_t)ctx->r[%u]",RA(i)):std::string("0u")).c_str(), nb, RT(i)); } break;
        case 725: { uint32_t nb=RB(i)?RB(i):32;
            o+=F("{ uint32_t e=%s; int n=%u; int r=%u; while(n>0){ uint32_t v=(uint32_t)ctx->r[r]; for(int k=0;k<4&&n>0;k++){ PPU_STB(base,e,(uint8_t)(v>>24)); v<<=8; e++; n--; } r=(r+1)&31; } }\n",
                 (RA(i)?F("(uint32_t)ctx->r[%u]",RA(i)):std::string("0u")).c_str(), nb, RT(i)); } break;
        case 535: o+=F("ctx->f[%u] = (double)PPU_LFS(base,%s);\n",RT(i),ea_x(i).c_str()); break;
        case 567: o+=F("ctx->f[%u] = (double)PPU_LFS(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",RT(i),RA(i),RB(i),RA(i),RB(i)); break;
        case 599: o+=F("ctx->f[%u] = PPU_LFD(base,%s);\n",RT(i),ea_x(i).c_str()); break;
        case 631: o+=F("ctx->f[%u] = PPU_LFD(base,(uint32_t)(ctx->r[%u]+ctx->r[%u])); ctx->r[%u]+=ctx->r[%u];\n",RT(i),RA(i),RB(i),RA(i),RB(i)); break;
        case 663: o+=F("PPU_STFS(base,%s,(float)ctx->f[%u]);\n",ea_x(i).c_str(),RT(i)); break;
        case 695: o+=F("PPU_STFS(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),(float)ctx->f[%u]); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),RT(i),RA(i),RB(i)); break;
        case 727: o+=F("PPU_STFD(base,%s,ctx->f[%u]);\n",ea_x(i).c_str(),RT(i)); break;
        case 759: o+=F("PPU_STFD(base,(uint32_t)(ctx->r[%u]+ctx->r[%u]),ctx->f[%u]); ctx->r[%u]+=ctx->r[%u];\n",RA(i),RB(i),RT(i),RA(i),RB(i)); break;
        case 983: o+=F("{ int32_t v; __builtin_memcpy(&v,&ctx->f[%u],4); PPU_STW(base,%s,(uint32_t)v); }\n",RT(i),ea_x(i).c_str()); break;
        case 103: case 359: o+=F("{ uint32_t e=%s & ~0xFu; for(int k=0;k<4;k++) ctx->v[%u].u32[k]=PPU_LW(base,e+4*k); }\n",ea_x(i).c_str(),RT(i)); break;
        case 231: case 487: o+=F("{ uint32_t e=%s & ~0xFu; for(int k=0;k<4;k++) PPU_STW(base,e+4*k,ctx->v[%u].u32[k]); }\n",ea_x(i).c_str(),RT(i)); break;
        case 6:   o+=F("ppu_lvsl(&ctx->v[%u],%s);\n",RT(i),ea_x(i).c_str()); break;
        case 38:  o+=F("ppu_lvsr(&ctx->v[%u],%s);\n",RT(i),ea_x(i).c_str()); break;
        case 7:   o+=F("{ uint32_t e=%s; ppu_vsb(&ctx->v[%u], e&0xF, PPU_LB(base,e)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 39:  o+=F("{ uint32_t e=%s & ~1u; ppu_vsh(&ctx->v[%u], (e&0xF)>>1, PPU_LH(base,e)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 135: o+=F("{ uint32_t e=%s; PPU_STB(base,e, ppu_vb(&ctx->v[%u], e&0xF)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 167: o+=F("{ uint32_t e=%s & ~1u; PPU_STH(base,e, ppu_vh(&ctx->v[%u], (e&0xF)>>1)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 519: case 775: o+=F("{ uint32_t e=%s; int n=e&0xF; for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(k<16-n)?PPU_LB(base,e+(uint32_t)k):0); }\n",ea_x(i).c_str(),RT(i)); break;
        case 551: case 807: o+=F("{ uint32_t e=%s; int n=e&0xF; for(int k=0;k<16;k++) ppu_vsb(&ctx->v[%u],k,(k>=16-n)?PPU_LB(base,e-16u+(uint32_t)k):0); }\n",ea_x(i).c_str(),RT(i)); break;
        case 647: case 903: o+=F("{ uint32_t e=%s; int n=e&0xF; for(int k=0;k<16-n;k++) PPU_STB(base,e+(uint32_t)k,ppu_vb(&ctx->v[%u],k)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 679: case 935: o+=F("{ uint32_t e=%s; int n=e&0xF; for(int k=16-n;k<16;k++) PPU_STB(base,e-16u+(uint32_t)k,ppu_vb(&ctx->v[%u],k)); }\n",ea_x(i).c_str(),RT(i)); break;
        case 71:  o+=F("{ uint32_t e=%s & ~3u; int el=(e&0xF)>>2; ctx->v[%u].u32[el]=PPU_LW(base,e); }\n",ea_x(i).c_str(),RT(i)); break;
        case 199: o+=F("{ uint32_t e=%s & ~3u; int el=(e&0xF)>>2; PPU_STW(base,e,ctx->v[%u].u32[el]); }\n",ea_x(i).c_str(),RT(i)); break;
        case 20:  o+=F("%s=ppu_lwarx(ctx,base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 84:  o+=F("%s=ppu_ldarx(ctx,base,%s);\n",rT().c_str(),ea_x(i).c_str()); break;
        case 150: o+=F("ppu_stwcx(ctx,base,%s,(uint32_t)%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 214: o+=F("ppu_stdcx(ctx,base,%s,%s);\n",ea_x(i).c_str(),rS().c_str()); break;
        case 598: o+="/* sync */\n"; break;
        case 854: o+="/* eieio */\n"; break;
        case 278: case 246: case 54: case 86: case 982: case 758: case 470:
            o+="/* cache hint (dcbt/dcbtst/dcbst/dcbf/icbi/dcba) */\n"; break;
        case 1014:
            o+=F("{ uint32_t e=%s & ~0x7Fu; for(int k=0;k<128;k++) base[e+k]=0; }\n",ea_x(i).c_str()); break;
        default:  o+=F("ppu_unimpl(\"%s\",0x%x);\n",di.mnem.c_str(),addr); break;
        }
        } break;
    default: o+=F("ppu_unimpl(\"%s\",0x%x);\n",di.mnem.c_str(),addr); break;
    }
    (void)elf; (void)rB;
    return false;
}

static void recover_jump_tables(const ElfImage& elf, uint32_t start, uint32_t end,
                                const std::set<uint32_t>& tocs, std::set<uint32_t>& leaders,
                                std::map<uint32_t,std::vector<uint32_t>>& jt){
    if(tocs.empty()) return;
    for(uint32_t a=start+4; a<end; a+=4){
        uint32_t i=elf.r32(a);
        if(!(OPCD(i)==19 && XO(i)==528 && BO(i)==20 && !LK(i))) continue;
        uint32_t mc=elf.r32(a-4);
        if(!(OPCD(mc)==31 && XO(mc)==467)) continue;
        if((((mc>>16)&0x1F)|(((mc>>11)&0x1F)<<5))!=9) continue;
        uint32_t rctr=RT(mc);
        uint32_t lo = (a>=start+64)? a-64 : start;
        uint32_t rbase=0xFF; int32_t off=0; bool ok=false;
        for(uint32_t b=a-8; b>=lo; b-=4){
            uint32_t w=elf.r32(b);
            if(OPCD(w)==31 && XO(w)==266 && RT(w)==rctr){
                uint32_t cand[2]={RA(w),RB(w)};
                for(uint32_t c=0;c<2 && !ok;c++)
                    for(uint32_t d=b-4; d>=start; d-=4){
                        uint32_t lw=elf.r32(d);
                        if(OPCD(lw)==32 && RT(lw)==cand[c] && RA(lw)==2){
                            rbase=cand[c]; off=(int16_t)(lw&0xFFFF); ok=true; break;
                        }
                        if(d==start) break;
                    }
                break;
            }
            if(b==lo) break;
        }
        if(!ok) continue;
        (void)rbase;
        std::vector<uint32_t> best;
        for(uint32_t toc : tocs){
            uint32_t table_base = elf.r32(toc + (uint32_t)off);
            if(!table_base) continue;
            std::vector<uint32_t> got;
            for(int k=0;k<512;k++){
                int32_t entoff=(int32_t)elf.r32(table_base + 4u*(uint32_t)k);
                if(entoff>0x200000 || entoff<-0x200000) break;
                uint32_t target = table_base + (uint32_t)entoff;
                if(target<elf.code_lo || target>=elf.code_hi || (target&3)) break;
                if(!ppu_decode(elf.r32(target),target).valid) break;
                got.push_back(target);
            }
            if(got.size()>best.size()) best.swap(got);
        }
        if(best.size()<2) continue;
        for(uint32_t t : best){ if(t>=start && t<end) leaders.insert(t); jt[a].push_back(t); }
    }
}

struct PpuPatch { uint32_t word; bool replace; std::string code; };
static std::map<uint32_t,PpuPatch> g_patches;
static std::set<uint32_t> g_patched;
static std::map<uint32_t,uint32_t> g_patch_bad;

bool ppu_load_patches(const std::string& path, std::string& err){
    std::ifstream f(path);
    if (!f){ err = "cannot open " + path; return false; }
    std::string line; int ln = 0;
    while (std::getline(f, line)){
        ++ln;
        if (!line.empty() && line.back()=='\r') line.pop_back();
        if (line.find_first_not_of(" \t") == std::string::npos) continue;
        std::istringstream ss(line); std::string addr, word, kind, code;
        ss >> addr >> word >> kind;
        std::getline(ss, code);
        size_t p = code.find_first_not_of(" \t");
        code = (p == std::string::npos) ? "" : code.substr(p);
        if ((kind!="guard" && kind!="replace") || code.empty()){
            err = F("%s:%d: expected <addr> <insn word> guard|replace <C code>", path.c_str(), ln);
            return false;
        }
        g_patches[(uint32_t)strtoul(addr.c_str(),nullptr,0)] =
            { (uint32_t)strtoul(word.c_str(),nullptr,0), kind=="replace", code };
    }
    return true;
}

std::string ppu_patch_problems(){
    std::string s;
    for (auto& kv : g_patch_bad)
        s += F("patch at 0x%x expects %08x, the image has %08x\n", kv.first, g_patches[kv.first].word, kv.second);
    for (auto& kv : g_patches)
        if (!g_patched.count(kv.first) && !g_patch_bad.count(kv.first))
            s += F("patch at 0x%x is not inside any lifted function\n", kv.first);
    return s;
}

static bool lift_patched(std::string& o, const ElfImage& elf, uint32_t i, uint32_t addr,
                         uint32_t start, uint32_t end, std::set<uint32_t>& called, const PpuPatch& p){
    if (i != p.word){
        g_patch_bad[addr] = i;
        return lift_insn(o, elf, i, addr, start, end, called);
    }
    g_patched.insert(addr);
    std::string t;
    bool ended = lift_insn(t, elf, i, addr, start, end, called);
    size_t head = t.find('\n') + 1 + 4;
    std::string rest = t.substr(head);
    o += t.substr(0, head);
    if (p.replace){ o += p.code + "\n"; return false; }
    while (!rest.empty() && rest.back()=='\n') rest.pop_back();
    o += "{ " + p.code + "\n      else { " + rest + " } }\n";
    return ended;
}

std::string lift_function(const ElfImage& elf, uint32_t start, uint32_t end,
                          std::set<uint32_t>& called, const std::set<uint32_t>& tocs){
    std::set<uint32_t> leaders;
    std::map<uint32_t,std::vector<uint32_t>> jt;
    recover_jump_tables(elf, start, end, tocs, leaders, jt);

    std::string body;
    bool ended = false;
    for (uint32_t a=start; a<end; a+=4){
        body += F("loc_%x:\n", a);
        uint32_t i = elf.r32(a);
        auto it = jt.find(a);
        if (it != jt.end()){
            body += "    switch((uint32_t)ctx->ctr){\n";
            std::set<uint32_t> seen;
            for (uint32_t t : it->second) if(seen.insert(t).second){
                if (t>=start && t<end)
                    body += F("    case 0x%xu: goto loc_%x;\n", t, t);
                else { body += F("    case 0x%xu: sub_%x(ctx,base); return;\n", t, t); called.insert(t); }
            }
            body += "    default: { PPCFunc f=ppu_lookup_ex((uint32_t)ctx->ctr,ctx); f(ctx,base); return; } }\n";
            ended = true;
        } else {
            auto pt = g_patches.find(a);
            ended = (pt == g_patches.end()) ? lift_insn(body, elf, i, a, start, end, called)
                                            : lift_patched(body, elf, i, a, start, end, called, pt->second);
        }
    }
    if (!ended){ body += F("    sub_%x(ctx, base); return;\n", end); called.insert(end); }

    std::string out = F("void sub_%x(PPUContext* ctx, uint8_t* base) {\n", start);
    out += F("    PPU_CURFN(0x%xu);\n", start);
    if (start==0x8b8d2cu){
        out += "    ctx->resume_pc = 0;\n";
        out += "    uint64_t a1 = ctx->r[3];\n";
        out += "    uint64_t item = (ctx->r[4] + 8) & 0xffffffffull;\n";
        out += "    ctx->r[3] = (uint32_t)PPU_LW(base,(uint32_t)(a1 + 92));\n";
        out += "    ctx->r[4] = item;\n";
        out += "    ctx->lr = 0x8b8d50ull; sub_8b909c(ctx, base);\n";
        out += "    ctx->r[3] = (uint32_t)PPU_LW(base,(uint32_t)(a1 + 136));\n";
        out += "    ctx->lr = 0x8b8d68ull; sub_958b14(ctx, base);\n";
        out += "    return;\n";
        out += "}\n";
        return out;
    }
    {
        out += "    static const void* const Ltab[] = {\n        ";
        int col=0;
        for (uint32_t a=start; a<end; a+=4){
            out += F("&&loc_%x,", a);
            if (++col==16){ out += "\n        "; col=0; }
        }
        out += "\n    };\n";
        out += F("    if (ctx->resume_pc){ uint32_t _r=ctx->resume_pc; ctx->resume_pc=0;\n"
                 "        if (_r>=0x%xu && _r<0x%xu && !(_r&3)) goto *Ltab[(_r-0x%xu)>>2]; }\n",
                 start, end, start);
    }
    if (start==0x9678d0u)
        out += "    PPU_STD(base,(uint32_t)(ctx->r[1]+40),ctx->r[2]);\n"
               "    if(((uint32_t)ctx->r[4]&0xFF)==0xAC) return;\n";
    out += body;
    out += "}\n";
    return out;
}
