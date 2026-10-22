#include "spu_lift.hpp"
#include "spu_decode.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

static std::string F(const char* f, ...) {
    char b[1024]; va_list ap; va_start(ap, f); vsnprintf(b, sizeof b, f, ap); va_end(ap);
    return b;
}

static std::string RT(const SpuInsn& d){ return F("c->r[%u]", d.rt); }
static std::string RA(const SpuInsn& d){ return F("c->r[%u]", d.ra); }
static std::string RB(const SpuInsn& d){ return F("c->r[%u]", d.rb); }
static std::string RC(const SpuInsn& d){ return F("c->r[%u]", d.rc); }

static std::string word4(const SpuInsn& d, const char* expr){
    return F("for(int i=0;i<4;i++) %s.w[i]=%s;\n", RT(d).c_str(), expr);
}
static std::string half8(const SpuInsn& d, const char* expr){
    return F("for(int i=0;i<8;i++) %s.h[i]=%s;\n", RT(d).c_str(), expr);
}
static std::string byte16(const SpuInsn& d, const char* expr){
    return F("for(int i=0;i<16;i++) %s.b[i]=%s;\n", RT(d).c_str(), expr);
}

static uint32_t g_lo = 0, g_hi = 0;
static bool inrange(uint32_t a){ return a >= g_lo && a < g_hi; }
static std::string jmp(uint32_t a){
    if (inrange(a)) return F("goto loc_%x;", a);
    return F("c->pc=0x%x; goto dispatch;", a);
}

static bool lift_one(std::string& o, const SpuInsn& d, uint32_t pc){
    if(!d.mnem){ o += F("spu_unimpl(\"?\",0x%x);\n", pc); return false; }
    const char* m = d.mnem;
    auto is=[&](const char* s){ return strcmp(m,s)==0; };
    int32_t imm = d.imm;
    uint32_t next = pc+4;

    if(is("il"))   { o+=F("for(int i=0;i<4;i++) %s.w[i]=(uint32_t)(int32_t)%d;\n",RT(d).c_str(),imm); return false; }
    if(is("ilh"))  { o+=F("for(int i=0;i<8;i++) %s.h[i]=0x%x;\n",RT(d).c_str(),imm&0xffff); return false; }
    if(is("ilhu")) { o+=F("for(int i=0;i<4;i++) %s.w[i]=0x%xu<<16;\n",RT(d).c_str(),imm&0xffff); return false; }
    if(is("ila"))  { o+=F("for(int i=0;i<4;i++) %s.w[i]=0x%xu;\n",RT(d).c_str(),(uint32_t)imm&0x3ffff); return false; }
    if(is("iohl")) { o+=F("for(int i=0;i<4;i++) %s.w[i]|=0x%xu;\n",RT(d).c_str(),imm&0xffff); return false; }
    if(is("fsmbi")){ uint32_t w[4];
        for(int j=0;j<4;j++){ w[j]=0; for(int b=0;b<4;b++) if(((uint32_t)imm>>(15-(4*j+b)))&1) w[j]|=0xffu<<(24-8*b); }
        o+=F("%s.w[0]=0x%08xu; %s.w[1]=0x%08xu; %s.w[2]=0x%08xu; %s.w[3]=0x%08xu;\n",
             RT(d).c_str(),w[0],RT(d).c_str(),w[1],RT(d).c_str(),w[2],RT(d).c_str(),w[3]); return false; }

    if(is("a"))    { o+=word4(d, F("%s.w[i]+%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("ai"))   { o+=word4(d, F("%s.w[i]+(uint32_t)(int32_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("ah"))   { o+=half8(d, F("%s.h[i]+%s.h[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("ahi"))  { o+=half8(d, F("%s.h[i]+(uint16_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("sf"))   { o+=word4(d, F("%s.w[i]-%s.w[i]",RB(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("sfi"))  { o+=word4(d, F("(uint32_t)(int32_t)%d-%s.w[i]",imm,RA(d).c_str()).c_str()); return false; }
    if(is("sfh"))  { o+=half8(d, F("%s.h[i]-%s.h[i]",RB(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("sfhi")) { o+=half8(d, F("(uint16_t)%d-%s.h[i]",imm,RA(d).c_str()).c_str()); return false; }
    if(is("addx")) { o+=word4(d, F("%s.w[i]+%s.w[i]+(%s.w[i]&1)",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("sfx"))  { o+=word4(d, F("%s.w[i]-%s.w[i]-1+(%s.w[i]&1)",RB(d).c_str(),RA(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("cg"))   { o+=word4(d, F("((%s.w[i]+%s.w[i])<%s.w[i])?1u:0u",RA(d).c_str(),RB(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("bg"))   { o+=word4(d, F("(%s.w[i]>=%s.w[i])?1u:0u",RB(d).c_str(),RA(d).c_str()).c_str()); return false; }

    if(is("mpy"))  { o+=word4(d, F("(uint32_t)((int32_t)(int16_t)%s.w[i]*(int32_t)(int16_t)%s.w[i])",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyu")) { o+=word4(d, F("(uint32_t)((%s.w[i]&0xffff)*(%s.w[i]&0xffff))",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyh")) { o+=word4(d, F("(uint32_t)(((int32_t)(int16_t)(%s.w[i]>>16))*(int32_t)(int16_t)%s.w[i])<<16",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyhh")){ o+=word4(d, F("(uint32_t)(((int32_t)(int16_t)(%s.w[i]>>16))*(int32_t)(int16_t)(%s.w[i]>>16))",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyhhu")){ o+=word4(d, F("(%s.w[i]>>16)*(%s.w[i]>>16)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpys")) { o+=word4(d, F("(uint32_t)(((int32_t)(int16_t)%s.w[i]*(int32_t)(int16_t)%s.w[i])>>16)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyi")) { o+=word4(d, F("(uint32_t)((int32_t)(int16_t)%s.w[i]*%d)",RA(d).c_str(),imm).c_str()); return false; }
    if(is("mpyui")){ o+=word4(d, F("(uint32_t)((%s.w[i]&0xffff)*(uint32_t)%d)",RA(d).c_str(),imm&0xffff).c_str()); return false; }
    if(is("mpya")) { o+=word4(d, F("(uint32_t)((int32_t)(int16_t)%s.w[i]*(int32_t)(int16_t)%s.w[i])+%s.w[i]",RA(d).c_str(),RB(d).c_str(),RC(d).c_str()).c_str()); return false; }

    if(is("and")) { o+=word4(d, F("%s.w[i]&%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("or"))  { o+=word4(d, F("%s.w[i]|%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("xor")) { o+=word4(d, F("%s.w[i]^%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("nand")){ o+=word4(d, F("~(%s.w[i]&%s.w[i])",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("nor")) { o+=word4(d, F("~(%s.w[i]|%s.w[i])",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("andc")){ o+=word4(d, F("%s.w[i]&~%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("orc")) { o+=word4(d, F("%s.w[i]|~%s.w[i]",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("eqv")) { o+=word4(d, F("~(%s.w[i]^%s.w[i])",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("andi")){ o+=word4(d, F("%s.w[i]&(uint32_t)(int32_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("ori")) { o+=word4(d, F("%s.w[i]|(uint32_t)(int32_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("xori")){ o+=word4(d, F("%s.w[i]^(uint32_t)(int32_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("andbi")){o+=byte16(d,F("%s.b[i]&(uint8_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("orbi")){ o+=byte16(d,F("%s.b[i]|(uint8_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("xorbi")){o+=byte16(d,F("%s.b[i]^(uint8_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("andhi")){o+=half8(d, F("%s.h[i]&(uint16_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("orhi")){ o+=half8(d, F("%s.h[i]|(uint16_t)%d",RA(d).c_str(),imm).c_str()); return false; }
    if(is("xorhi")){o+=half8(d, F("%s.h[i]^(uint16_t)%d",RA(d).c_str(),imm).c_str()); return false; }

    if(is("ceq"))  { o+=word4(d, F("(%s.w[i]==%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("ceqb")) { o+=byte16(d,F("(%s.b[i]==%s.b[i])?0xff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("ceqh")) { o+=half8(d, F("(%s.h[i]==%s.h[i])?0xffff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("ceqi")) { o+=word4(d, F("(%s.w[i]==(uint32_t)(int32_t)%d)?~0u:0u",RA(d).c_str(),imm).c_str()); return false; }
    if(is("ceqhi")){ o+=half8(d, F("(%s.h[i]==(uint16_t)%d)?0xffff:0",RA(d).c_str(),imm).c_str()); return false; }
    if(is("ceqbi")){ o+=byte16(d,F("(%s.b[i]==(uint8_t)%d)?0xff:0",RA(d).c_str(),imm).c_str()); return false; }
    if(is("cgt"))  { o+=word4(d, F("((int32_t)%s.w[i]>(int32_t)%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("cgth")) { o+=half8(d, F("((int16_t)%s.h[i]>(int16_t)%s.h[i])?0xffff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("cgtb")) { o+=byte16(d,F("((int8_t)%s.b[i]>(int8_t)%s.b[i])?0xff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("cgti")) { o+=word4(d, F("((int32_t)%s.w[i]>%d)?~0u:0u",RA(d).c_str(),imm).c_str()); return false; }
    if(is("cgthi")){ o+=half8(d, F("((int16_t)%s.h[i]>(int16_t)%d)?0xffff:0",RA(d).c_str(),imm).c_str()); return false; }
    if(is("cgtbi")){ o+=byte16(d,F("((int8_t)%s.b[i]>(int8_t)%d)?0xff:0",RA(d).c_str(),imm).c_str()); return false; }
    if(is("clgt")) { o+=word4(d, F("(%s.w[i]>%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("clgth")){ o+=half8(d, F("(%s.h[i]>%s.h[i])?0xffff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("clgtb")){ o+=byte16(d,F("(%s.b[i]>%s.b[i])?0xff:0",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("clgti")){ o+=word4(d, F("(%s.w[i]>(uint32_t)(int32_t)%d)?~0u:0u",RA(d).c_str(),imm).c_str()); return false; }
    if(is("clgthi")){o+=half8(d, F("(%s.h[i]>(uint16_t)%d)?0xffff:0",RA(d).c_str(),imm).c_str()); return false; }
    if(is("clgtbi")){o+=byte16(d,F("(%s.b[i]>(uint8_t)%d)?0xff:0",RA(d).c_str(),imm).c_str()); return false; }

    if(is("shl"))  { o+=word4(d, F("(%s.w[i]&0x3f)<32?(%s.w[i]<<(%s.w[i]&0x3f)):0u",RB(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("shli")) { uint32_t s=imm&0x3f; o+=word4(d, F("%uu<32?(%s.w[i]<<%uu):0u",s,RA(d).c_str(),s).c_str()); return false; }
    if(is("shlh")) { o+=half8(d, F("(%s.h[i]&0x1f)<16?(uint16_t)(%s.h[i]<<(%s.h[i]&0x1f)):0",RB(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("shlhi")){ uint32_t s=imm&0x1f; o+=half8(d, F("%uu<16?(uint16_t)(%s.h[i]<<%uu):0",s,RA(d).c_str(),s).c_str()); return false; }
    if(is("rot"))  { o+=word4(d, F("(%s.w[i]<<(%s.w[i]&31))|(%s.w[i]>>((32-(%s.w[i]&31))&31))",RA(d).c_str(),RB(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("roti")) { uint32_t s=imm&31; o+=word4(d, F("(%s.w[i]<<%u)|(%s.w[i]>>((32-%u)&31))",RA(d).c_str(),s,RA(d).c_str(),s).c_str()); return false; }
    if(is("rotm")) { o+=word4(d, F("((0u-%s.w[i])&0x3f)<32?(%s.w[i]>>((0u-%s.w[i])&0x3f)):0u",RB(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("rotmi")){ uint32_t s=(0u-(uint32_t)imm)&0x3f; o+=word4(d, F("%uu<32?(%s.w[i]>>%uu):0u",s,RA(d).c_str(),s).c_str()); return false; }
    if(is("rotma")){ o+=word4(d, F("(uint32_t)(((0u-%s.w[i])&0x3f)<32?((int32_t)%s.w[i]>>((0u-%s.w[i])&0x3f)):((int32_t)%s.w[i]>>31))",RB(d).c_str(),RA(d).c_str(),RB(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("rotmai")){uint32_t s=(0u-(uint32_t)imm)&0x3f; o+=word4(d, F("(uint32_t)(%uu<32?((int32_t)%s.w[i]>>%uu):((int32_t)%s.w[i]>>31))",s,RA(d).c_str(),s,RA(d).c_str()).c_str()); return false; }
    if(is("rothm")){ o+=half8(d, F("(uint16_t)(((0u-%s.h[i])&0x1f)<16?(%s.h[i]>>((0u-%s.h[i])&0x1f)):0)",RB(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("rothmi")){uint32_t s=(0u-(uint32_t)imm)&0x1f; o+=half8(d, F("(uint16_t)(%uu<16?(%s.h[i]>>%uu):0)",s,RA(d).c_str(),s).c_str()); return false; }

    if(is("shlqbyi")||is("shlqby")){ std::string cnt = is("shlqby")?F("(%s.w[0]&0x1f)",RB(d).c_str()):F("%d",imm&0x1f);
        o+=F("spu_shlqby(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("rotqbyi")||is("rotqby")){ std::string cnt = is("rotqby")?F("(%s.w[0]&0xf)",RB(d).c_str()):F("(%d&0xf)",imm);
        o+=F("spu_rotqby(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("rotqmbyi")||is("rotqmby")){ std::string cnt = is("rotqmby")?F("((0-%s.w[0])&0x1f)",RB(d).c_str()):F("((0-(%d))&0x1f)",imm);
        o+=F("spu_rotqmby(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("shlqbii")||is("shlqbi")){ std::string cnt = is("shlqbi")?F("(%s.w[0]&7)",RB(d).c_str()):F("(%d&7)",imm);
        o+=F("spu_shlqbi(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("rotqbii")||is("rotqbi")){ std::string cnt = is("rotqbi")?F("(%s.w[0]&7)",RB(d).c_str()):F("(%d&7)",imm);
        o+=F("spu_rotqbi(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("rotqmbii")||is("rotqmbi")){ std::string cnt = is("rotqmbi")?F("((0-%s.w[0])&7)",RB(d).c_str()):F("((0-(%d))&7)",imm);
        o+=F("spu_rotqmbi(&%s,&%s,%s);\n",RT(d).c_str(),RA(d).c_str(),cnt.c_str()); return false; }
    if(is("rotqbybi")){ o+=F("spu_rotqby(&%s,&%s,((%s.w[0]>>3)&0xf));\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("rotqmbybi")){ o+=F("spu_rotqmby(&%s,&%s,((0-(%s.w[0]>>3))&0x1f));\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("shlqbybi")){ o+=F("spu_shlqby(&%s,&%s,((%s.w[0]>>3)&0x1f));\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }

    if(is("xsbh")) { o+=half8(d, F("(uint16_t)(int16_t)(int8_t)%s.h[i]",RA(d).c_str()).c_str()); return false; }
    if(is("xshw")) { o+=word4(d, F("(uint32_t)(int32_t)(int16_t)%s.w[i]",RA(d).c_str()).c_str()); return false; }
    if(is("xswd")) { o+=F("{ int64_t v0=(int64_t)(int32_t)%s.w[1], v1=(int64_t)(int32_t)%s.w[3]; %s.w[0]=(uint32_t)((uint64_t)v0>>32); %s.w[1]=(uint32_t)v0; %s.w[2]=(uint32_t)((uint64_t)v1>>32); %s.w[3]=(uint32_t)v1; }\n",RA(d).c_str(),RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("clz"))  { o+=word4(d, F("%s.w[i]?(uint32_t)__builtin_clz(%s.w[i]):32u",RA(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("cntb")) { o+=byte16(d,F("(uint8_t)__builtin_popcount(%s.b[i])",RA(d).c_str()).c_str()); return false; }
    if(is("avgb")) { o+=byte16(d,F("(uint8_t)((%s.b[i]+%s.b[i]+1)>>1)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("absdb")){ o+=byte16(d,F("(uint8_t)(%s.b[i]>%s.b[i]?%s.b[i]-%s.b[i]:%s.b[i]-%s.b[i])",RA(d).c_str(),RB(d).c_str(),RA(d).c_str(),RB(d).c_str(),RB(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("sumb")) { o+=F("for(int i=0;i<4;i++){ uint32_t a=%s.w[i],b=%s.w[i];"
        " uint32_t sa=(a&0xff)+((a>>8)&0xff)+((a>>16)&0xff)+(a>>24);"
        " uint32_t sb=(b&0xff)+((b>>8)&0xff)+((b>>16)&0xff)+(b>>24);"
        " %s.w[i]=(sb<<16)|(sa&0xffff); }\n",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()); return false; }

    if(is("selb")) { o+=word4(d, F("(%s.w[i]&%s.w[i])|(~%s.w[i]&%s.w[i])",RC(d).c_str(),RB(d).c_str(),RC(d).c_str(),RA(d).c_str()).c_str()); return false; }
    if(is("shufb")){ o+=F("spu_shufb(&%s,&%s,&%s,&%s);\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str(),RC(d).c_str()); return false; }
    if(is("orx"))  { o+=F("{ uint32_t v=%s.w[0]|%s.w[1]|%s.w[2]|%s.w[3]; %s.w[0]=v; %s.w[1]=%s.w[2]=%s.w[3]=0; }\n",RA(d).c_str(),RA(d).c_str(),RA(d).c_str(),RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("gb"))   { o+=F("{ uint32_t mm=0; for(int i=0;i<4;i++) mm|=(%s.w[i]&1u)<<(3-i); %s.w[0]=mm; %s.w[1]=%s.w[2]=%s.w[3]=0; }\n",RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("gbh"))  { o+=F("{ uint32_t mm=0; for(int i=0;i<4;i++){ mm|=((%s.w[i]>>16)&1u)<<(7-2*i); mm|=(%s.w[i]&1u)<<(6-2*i); } %s.w[0]=mm; %s.w[1]=%s.w[2]=%s.w[3]=0; }\n",RA(d).c_str(),RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("gbb"))  { o+=F("{ uint8_t a[16]; uint32_t mm=0; spu_get_bytes(&%s,a); for(int k=0;k<16;k++) mm|=(uint32_t)(a[k]&1u)<<(15-k); %s.w[0]=mm; %s.w[1]=%s.w[2]=%s.w[3]=0; }\n",RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("fsm"))  { o+=F("{ uint32_t mm=%s.w[0]; for(int i=0;i<4;i++) %s.w[i]=(mm>>(3-i)&1)?~0u:0u; }\n",RA(d).c_str(),RT(d).c_str()); return false; }
    if(is("fsmh")) { o+=F("{ uint32_t mm=%s.w[0]; for(int i=0;i<4;i++) %s.w[i]=((mm>>(7-2*i)&1)?0xffff0000u:0u)|((mm>>(6-2*i)&1)?0xffffu:0u); }\n",RA(d).c_str(),RT(d).c_str()); return false; }
    if(is("fsmb")) { o+=F("{ uint32_t mm=%s.w[0]; uint8_t t[16]; for(int k=0;k<16;k++) t[k]=(mm>>(15-k)&1)?0xff:0; spu_set_bytes(&%s,t); }\n",RA(d).c_str(),RT(d).c_str()); return false; }

    auto cins=[&](int sz, std::string ea)->void{
        o+=F("spu_cins(&%s,(%s),%d);\n", RT(d).c_str(), ea.c_str(), sz);
    };
    if(is("cbd")) { cins(1, F("(%s.w[0]+%d)",RA(d).c_str(),imm)); return false; }
    if(is("chd")) { cins(2, F("(%s.w[0]+%d)",RA(d).c_str(),imm)); return false; }
    if(is("cwd")) { cins(4, F("(%s.w[0]+%d)",RA(d).c_str(),imm)); return false; }
    if(is("cdd")) { cins(8, F("(%s.w[0]+%d)",RA(d).c_str(),imm)); return false; }
    if(is("cbx")) { cins(1, F("(%s.w[0]+%s.w[0])",RA(d).c_str(),RB(d).c_str())); return false; }
    if(is("chx")) { cins(2, F("(%s.w[0]+%s.w[0])",RA(d).c_str(),RB(d).c_str())); return false; }
    if(is("cwx")) { cins(4, F("(%s.w[0]+%s.w[0])",RA(d).c_str(),RB(d).c_str())); return false; }
    if(is("cdx")) { cins(8, F("(%s.w[0]+%s.w[0])",RA(d).c_str(),RB(d).c_str())); return false; }

    if(is("lqd")) { o+=F("spu_lq(c,(%s.w[0]+(%d<<4)),&%s);\n",RA(d).c_str(),imm,RT(d).c_str()); return false; }
    if(is("lqx")) { o+=F("spu_lq(c,(%s.w[0]+%s.w[0]),&%s);\n",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()); return false; }
    if(is("lqa")) { o+=F("spu_lq(c,(0x%xu),&%s);\n",((uint32_t)imm<<2),RT(d).c_str()); return false; }
    if(is("lqr")) { o+=F("spu_lq(c,(0x%xu),&%s);\n",(pc+((uint32_t)imm<<2)),RT(d).c_str()); return false; }
    if(is("stqd")){ o+=F("spu_stq(c,(%s.w[0]+(%d<<4)),&%s);\n",RA(d).c_str(),imm,RT(d).c_str()); return false; }
    if(is("stqx")){ o+=F("spu_stq(c,(%s.w[0]+%s.w[0]),&%s);\n",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()); return false; }
    if(is("stqa")){ o+=F("spu_stq(c,(0x%xu),&%s);\n",((uint32_t)imm<<2),RT(d).c_str()); return false; }
    if(is("stqr")){ o+=F("spu_stq(c,(0x%xu),&%s);\n",(pc+((uint32_t)imm<<2)),RT(d).c_str()); return false; }

    if(is("fa"))  { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]+%s.fp[i];\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("fs"))  { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]-%s.fp[i];\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("fm"))  { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]*%s.fp[i];\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("fma")) { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]*%s.fp[i]+%s.fp[i];\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str(),RC(d).c_str()); return false; }
    if(is("fnms")){ o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]-%s.fp[i]*%s.fp[i];\n",RT(d).c_str(),RC(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("fms")) { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i]*%s.fp[i]-%s.fp[i];\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str(),RC(d).c_str()); return false; }
    if(is("fi"))  { o+=F("for(int i=0;i<4;i++) %s.fp[i]=%s.fp[i];\n",RT(d).c_str(),RB(d).c_str()); return false; }
    if(is("frest")){o+=F("for(int i=0;i<4;i++) %s.fp[i]=1.0f/%s.fp[i];\n",RT(d).c_str(),RA(d).c_str()); return false; }
    if(is("frsqest")){o+=F("for(int i=0;i<4;i++){ float v=%s.fp[i]; %s.fp[i]=1.0f/__builtin_sqrtf(v<0?-v:v);}\n",RA(d).c_str(),RT(d).c_str()); return false; }
    if(is("fceq")){ o+=word4(d, F("spu_fceq1(%s.w[i],%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("fcgt")){ o+=word4(d, F("spu_fcgt1(%s.w[i],%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("csflt")){ o+=F("for(int i=0;i<4;i++) %s.fp[i]=(float)(int32_t)%s.w[i]*0x1p%df;\n",RT(d).c_str(),RA(d).c_str(),imm-155); return false; }
    if(is("cuflt")){ o+=F("for(int i=0;i<4;i++) %s.fp[i]=(float)%s.w[i]*0x1p%df;\n",RT(d).c_str(),RA(d).c_str(),imm-155); return false; }
    if(is("cflts")){ o+=F("for(int i=0;i<4;i++){ float _v=%s.fp[i]*0x1p%df; %s.w[i]=_v>=2147483648.0f?0x7fffffffu:(_v<=-2147483648.0f?0x80000000u:(uint32_t)(int32_t)_v); }\n",RA(d).c_str(),173-imm,RT(d).c_str()); return false; }
    if(is("cfltu")){ o+=F("for(int i=0;i<4;i++){ float _v=%s.fp[i]*0x1p%df; %s.w[i]=_v>=4294967296.0f?0xffffffffu:(_v<=0.0f?0u:(uint32_t)_v); }\n",RA(d).c_str(),173-imm,RT(d).c_str()); return false; }

    if(is("rdch"))  { o+=F("%s.w[0]=spu_rdch(c,%u); %s.w[1]=%s.w[2]=%s.w[3]=0;\n",RT(d).c_str(),d.ra,RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("wrch"))  { o+=F("spu_wrch(c,%u,%s.w[0]);\n",d.ra,RT(d).c_str()); return false; }
    if(is("rchcnt")){ o+=F("%s.w[0]=spu_rchcnt(c,%u); %s.w[1]=%s.w[2]=%s.w[3]=0;\n",RT(d).c_str(),d.ra,RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }

    if(is("br"))   { uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=jmp(t)+"\n"; return true; }
    if(is("bra"))  { uint32_t t=((uint32_t)imm<<2)&0x3fffc; o+=jmp(t)+"\n"; return true; }
    if(is("brsl")) { uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=F("%s.w[0]=0x%xu+(uint32_t)c->pc_bias;%s.w[1]=%s.w[2]=%s.w[3]=0; %s\n",RT(d).c_str(),next,RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),jmp(t).c_str()); return true; }
    if(is("brasl")){ uint32_t t=((uint32_t)imm<<2)&0x3fffc; o+=F("%s.w[0]=0x%xu+(uint32_t)c->pc_bias;%s.w[1]=%s.w[2]=%s.w[3]=0; %s\n",RT(d).c_str(),next,RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),jmp(t).c_str()); return true; }
    if(is("brz"))  { uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=F("if(%s.w[0]==0){ %s }\n",RT(d).c_str(),jmp(t).c_str()); return false; }
    if(is("brnz")) { uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=F("if(%s.w[0]!=0){ %s }\n",RT(d).c_str(),jmp(t).c_str()); return false; }
    if(is("brhz")) { uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=F("if((%s.w[0]&0xffff)==0){ %s }\n",RT(d).c_str(),jmp(t).c_str()); return false; }
    if(is("brhnz")){ uint32_t t=(pc+((uint32_t)imm<<2))&0x3fffc; o+=F("if((%s.w[0]&0xffff)!=0){ %s }\n",RT(d).c_str(),jmp(t).c_str()); return false; }
    if(is("bi"))   { o+=F("c->pc=%s.w[0]&0x3fffc; goto dispatch;\n",RA(d).c_str()); return true; }
    if(is("bisl")) { o+=F("%s.w[0]=0x%xu+(uint32_t)c->pc_bias;%s.w[1]=%s.w[2]=%s.w[3]=0; c->pc=%s.w[0]&0x3fffc; goto dispatch;\n",RT(d).c_str(),next,RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RA(d).c_str()); return true; }
    if(is("iret")) { o+=F("c->pc=c->srr0&0x3fffc; goto dispatch;\n"); return true; }
    if(is("biz"))  { o+=F("if(%s.w[0]==0){ c->pc=%s.w[0]&0x3fffc; goto dispatch; }\n",RT(d).c_str(),RA(d).c_str()); return false; }
    if(is("binz")) { o+=F("if(%s.w[0]!=0){ c->pc=%s.w[0]&0x3fffc; goto dispatch; }\n",RT(d).c_str(),RA(d).c_str()); return false; }
    if(is("bihz")) { o+=F("if((%s.w[0]&0xffff)==0){ c->pc=%s.w[0]&0x3fffc; goto dispatch; }\n",RT(d).c_str(),RA(d).c_str()); return false; }
    if(is("bihnz")){ o+=F("if((%s.w[0]&0xffff)!=0){ c->pc=%s.w[0]&0x3fffc; goto dispatch; }\n",RT(d).c_str(),RA(d).c_str()); return false; }

    if(is("hbr")||is("hbra")||is("hbrr")||is("hbrp")) { o+="/* branch hint */\n"; return false; }
    if(d.mnem[0]=='h' && (is("heq")||is("heqi")||is("hgt")||is("hgti")||is("hlgt")||is("hlgti"))) { o+="/* halt-if (assert) */\n"; return false; }
    if(is("nop")||is("lnop")) { o+="/* nop */\n"; return false; }
    if(is("sync")||is("dsync")) { o+="/* barrier */\n"; return false; }
    if(is("fscrrd")) { o+=F("for(int i=0;i<4;i++) %s.w[i]=0;\n",RT(d).c_str()); return false; }
    if(is("fscrwr")) { o+="/* fscrwr */\n"; return false; }
    if(is("stop")||is("stopd")) { o+=F("spu_stop(c,0x%x); return;\n",d.raw&0x3fff); return true; }

    if(is("roth"))  { o+=F("for(int i=0;i<8;i++){ uint32_t s=%s.h[i]&15; %s.h[i]=(uint16_t)((%s.h[i]<<s)|(s?(%s.h[i]>>(16-s)):0)); }\n",RB(d).c_str(),RT(d).c_str(),RA(d).c_str(),RA(d).c_str()); return false; }
    if(is("rothi")) { uint32_t s=(uint32_t)imm&15; o+=half8(d, F("(uint16_t)((%s.h[i]<<%u)|(%u?(%s.h[i]>>((16-%u)&15)):0))",RA(d).c_str(),s,s,RA(d).c_str(),s).c_str()); return false; }
    if(is("rotmah")){ o+=F("for(int i=0;i<8;i++){ uint32_t s=(0u-%s.h[i])&0x1f; %s.h[i]=(uint16_t)((s<16)?((int16_t)%s.h[i]>>s):((int16_t)%s.h[i]>>15)); }\n",RB(d).c_str(),RT(d).c_str(),RA(d).c_str(),RA(d).c_str()); return false; }
    if(is("rotmahi")){uint32_t s=(0u-(uint32_t)imm)&0x1f; o+=half8(d, F("(uint16_t)(%uu<16?((int16_t)%s.h[i]>>%uu):((int16_t)%s.h[i]>>15))",s,RA(d).c_str(),s,RA(d).c_str()).c_str()); return false; }
    if(is("shlh"))  { o+=F("for(int i=0;i<8;i++){ uint32_t s=%s.h[i]&0x1f; %s.h[i]=(uint16_t)((s<16)?(%s.h[i]<<s):0); }\n",RB(d).c_str(),RT(d).c_str(),RA(d).c_str()); return false; }

    if(is("cgx"))  { o+=word4(d, F("(uint32_t)(((uint64_t)%s.w[i]+%s.w[i]+(%s.w[i]&1))>>32)",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("bgx"))  { o+=word4(d, F("(uint32_t)(((uint64_t)%s.w[i]+(uint32_t)~%s.w[i]+(%s.w[i]&1))>>32)",RB(d).c_str(),RA(d).c_str(),RT(d).c_str()).c_str()); return false; }

    if(is("mpyhha")) { o+=word4(d, F("%s.w[i]+(uint32_t)(((int32_t)(int16_t)(%s.w[i]>>16))*(int32_t)(int16_t)(%s.w[i]>>16))",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("mpyhhau")){ o+=word4(d, F("%s.w[i]+(%s.w[i]>>16)*(%s.w[i]>>16)",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }

    if(is("fcmeq")){ o+=word4(d, F("spu_fcmeq1(%s.w[i],%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("fcmgt")){ o+=word4(d, F("spu_fcmgt1(%s.w[i],%s.w[i])?~0u:0u",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }

    auto df2=[&](const char* expr)->void{
        o+=F("for(int j=0;j<2;j++) spu_setdf(&%s,j,%s);\n", RT(d).c_str(), expr);
    };
    if(is("dfa")) { df2(F("spu_getdf(&%s,j)+spu_getdf(&%s,j)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("dfs")) { df2(F("spu_getdf(&%s,j)-spu_getdf(&%s,j)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("dfm")) { df2(F("spu_getdf(&%s,j)*spu_getdf(&%s,j)",RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("dfma")){ df2(F("spu_getdf(&%s,j)*spu_getdf(&%s,j)+spu_getdf(&%s,j)",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("dfms")){ df2(F("spu_getdf(&%s,j)*spu_getdf(&%s,j)-spu_getdf(&%s,j)",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("dfnms")){df2(F("spu_getdf(&%s,j)-spu_getdf(&%s,j)*spu_getdf(&%s,j)",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()).c_str()); return false; }
    if(is("dfnma")){df2(F("-(spu_getdf(&%s,j)*spu_getdf(&%s,j)+spu_getdf(&%s,j))",RA(d).c_str(),RB(d).c_str(),RT(d).c_str()).c_str()); return false; }
    if(is("dfceq")) { o+=F("for(int j=0;j<2;j++) spu_setd64(&%s,j,(spu_getdf(&%s,j)==spu_getdf(&%s,j))?~0ull:0ull);\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("dfcgt")) { o+=F("for(int j=0;j<2;j++) spu_setd64(&%s,j,(spu_getdf(&%s,j)>spu_getdf(&%s,j))?~0ull:0ull);\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("dfcmeq")){ o+=F("for(int j=0;j<2;j++) spu_setd64(&%s,j,(__builtin_fabs(spu_getdf(&%s,j))==__builtin_fabs(spu_getdf(&%s,j)))?~0ull:0ull);\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("dfcmgt")){ o+=F("for(int j=0;j<2;j++) spu_setd64(&%s,j,(__builtin_fabs(spu_getdf(&%s,j))>__builtin_fabs(spu_getdf(&%s,j)))?~0ull:0ull);\n",RT(d).c_str(),RA(d).c_str(),RB(d).c_str()); return false; }
    if(is("dftsv")) { o+=F("{ int m=%d; for(int j=0;j<2;j++){ uint64_t u=spu_getd64(&%s,j); int e=(int)((u>>52)&0x7ff); uint64_t fr=u&0xfffffffffffffull; int ng=(int)(u>>63); uint64_t r=0;"
        " if((m&0x40)&&e==0x7ff&&fr) r=~0ull; if((m&0x20)&&e==0x7ff&&!fr&&!ng) r=~0ull; if((m&0x10)&&e==0x7ff&&!fr&&ng) r=~0ull;"
        " if((m&0x08)&&!e&&!fr&&!ng) r=~0ull; if((m&0x04)&&!e&&!fr&&ng) r=~0ull; if((m&0x02)&&!e&&fr&&!ng) r=~0ull; if((m&0x01)&&!e&&fr&&ng) r=~0ull;"
        " spu_setd64(&%s,j,r); } }\n", imm&0x7f, RA(d).c_str(), RT(d).c_str()); return false; }
    if(is("fesd")) { o+=F("{ double d0=(double)%s.fp[0], d1=(double)%s.fp[2]; spu_setdf(&%s,0,d0); spu_setdf(&%s,1,d1); }\n",RA(d).c_str(),RA(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("frds")) { o+=F("{ float f0=(float)spu_getdf(&%s,0), f1=(float)spu_getdf(&%s,1); %s.fp[0]=f0; %s.w[1]=0; %s.fp[2]=f1; %s.w[3]=0; }\n",RA(d).c_str(),RA(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }

    if(is("bisled")){ o+=F("%s.w[0]=0x%x;%s.w[1]=%s.w[2]=%s.w[3]=0; /* external event: never taken */\n",RT(d).c_str(),next,RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("mfspr")) { o+=F("%s.w[0]=(%u==0)?c->srr0:0; %s.w[1]=%s.w[2]=%s.w[3]=0;\n",RT(d).c_str(),d.ra,RT(d).c_str(),RT(d).c_str(),RT(d).c_str()); return false; }
    if(is("mtspr")) { o+=F("if(%u==0) c->srr0=%s.w[0];\n",d.ra,RT(d).c_str()); return false; }
    if(is("heq")||is("hgt")||is("hlgt")) { o+="/* halt-if (assert) */\n"; return false; }

    o+=F("spu_unimpl(\"%s\",0x%x);\n", m, pc);
    return false;
}

static std::string lanes_unrolled(const std::string& s){
    static const char* const pfx[] = {"for(int i=0;i<4;i++)","for(int i=0;i<8;i++)","for(int i=0;i<16;i++)"};
    static const char* const mac[] = {"SPU_LANES4","SPU_LANES8","SPU_LANES16"};
    for(int k=0;k<3;k++){
        size_t n=strlen(pfx[k]);
        if(s.compare(0,n,pfx[k])!=0) continue;
        size_t e=s.size(); while(e>n && s[e-1]=='\n') e--;
        size_t b=n; while(b<e && s[b]==' ') b++;
        if(b>=e || s.find('\n',b)<e) return s;
        int par=0, br=0; size_t end=std::string::npos;
        for(size_t p=b;p<e;p++){ char ch=s[p];
            if(ch=='(') par++; else if(ch==')') par--;
            else if(ch=='{') br++;
            else if(ch=='}'){ if(--br==0 && par==0){ end=p; break; } }
            else if(ch==';' && par==0 && br==0){ end=p; break; } }
        if(end!=e-1) return s;
        return std::string(mac[k])+"("+s.substr(b,e-b)+");\n";
    }
    return s;
}

std::string spu_lift_image(const uint8_t* code, uint32_t base, uint32_t size, uint32_t entry,
                           const char* fname){
    g_lo = base; g_hi = base + (size & ~3u);
    std::string body;
    for(uint32_t off=0; off+4<=size; off+=4){
        uint32_t pc = base+off;
        uint32_t insn = ((uint32_t)code[off]<<24)|((uint32_t)code[off+1]<<16)|((uint32_t)code[off+2]<<8)|code[off+3];
        SpuInsn d = spu_decode(insn);
        body += F("loc_%x: ", pc);
        std::string one;
        lift_one(one, d, pc);
        body += lanes_unrolled(one);
    }

    uint32_t nslot = size >> 2;
    std::string tab = "    static const void* const labtab[] = {\n";
    for(uint32_t off=0; off+4<=size; off+=4) tab += F("&&loc_%x,", base+off);
    tab += "\n    };\n";

    std::string out = "#include \"spu_runtime.h\"\n#include <math.h>\n\n";
    out += F("void %s(SPUContext* c){\n", fname);
    out += tab;
    out += F("    if(!c->pc) c->pc=0x%x;\n", entry);
    out += F("dispatch: { uint32_t _i;"
             " if(c->pc_bias&&(c->pc<0x%xu||c->pc>=0x%xu)){"
             " uint32_t _rp=c->pc-(uint32_t)c->pc_bias;"
             " if(_rp>=0x%xu&&_rp<0x%xu) c->pc=_rp; }"
             " if(c->pc<0x%xu) return;"
             " _i=(c->pc-0x%xu)>>2; if(_i>=%uu) return;"
             " goto *labtab[_i]; }\n",
             base, base+(size&~3u), base, base+(size&~3u), base, base, nslot);
    out += body;
    out += F("    c->pc=0x%xu; return;\n", base+(size&~3u));
    out += "}\n";
    out += F("const uint32_t %s_range[2] = {0x%x, 0x%x};\n", fname, base, base+(size&~3u));
    uint32_t soff = (entry>=base && entry-base+16<=size) ? entry-base : 0;
    out += F("const uint32_t %s_sigat = 0x%x;\n", fname, base+soff);
    out += F("const uint8_t %s_sig[16] = {", fname);
    for (int k=0;k<16;k++) out += F("%s0x%02x", k?",":"", soff+(uint32_t)k<size?code[soff+k]:0);
    out += "};\n";
    return out;
}
