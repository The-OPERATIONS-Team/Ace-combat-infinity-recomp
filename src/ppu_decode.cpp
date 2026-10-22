#include "ppu_decode.hpp"
#include <cstdio>
#include <cstdarg>

static inline uint32_t OPCD(uint32_t i){ return i >> 26; }
static inline uint32_t XO_X (uint32_t i){ return (i >> 1) & 0x3FF; }
static inline uint32_t RT (uint32_t i){ return (i >> 21) & 0x1F; }
static inline uint32_t RA (uint32_t i){ return (i >> 16) & 0x1F; }
static inline uint32_t RB (uint32_t i){ return (i >> 11) & 0x1F; }
static inline uint32_t RC_(uint32_t i){ return (i >> 6)  & 0x1F; }
static inline uint32_t SH (uint32_t i){ return (i >> 11) & 0x1F; }
static inline uint32_t MB (uint32_t i){ return (i >> 6)  & 0x1F; }
static inline uint32_t ME (uint32_t i){ return (i >> 1)  & 0x1F; }
static inline uint32_t BO (uint32_t i){ return (i >> 21) & 0x1F; }
static inline uint32_t BI (uint32_t i){ return (i >> 16) & 0x1F; }
static inline uint32_t Rc (uint32_t i){ return i & 1; }
static inline uint32_t OE (uint32_t i){ return (i >> 10) & 1; }
static inline uint32_t LK (uint32_t i){ return i & 1; }
static inline uint32_t AA (uint32_t i){ return (i >> 1) & 1; }
static inline int32_t  D  (uint32_t i){ return (int16_t)(i & 0xFFFF); }
static inline uint32_t UI (uint32_t i){ return i & 0xFFFF; }
static inline uint32_t BF (uint32_t i){ return (i >> 23) & 7; }
static inline uint32_t Lbit(uint32_t i){ return (i >> 21) & 1; }

static std::string fmt(const char* f, ...) {
    char buf[160]; va_list ap; va_start(ap, f);
    vsnprintf(buf, sizeof buf, f, ap); va_end(ap);
    return buf;
}
static std::string raz(uint32_t ra){ return ra ? fmt("r%u", ra) : std::string("0"); }

static std::string crbit(uint32_t b){
    static const char* cc[4] = {"lt","gt","eq","so"};
    uint32_t n = b >> 2, c = b & 3;
    return n ? fmt("4*cr%u+%s", n, cc[c]) : std::string(cc[c]);
}

static const char* dot(uint32_t i){ return Rc(i) ? "." : ""; }
static const char* oe (uint32_t i){ return OE(i) ? "o" : ""; }

static inline uint32_t MB6(uint32_t i){ uint32_t m=(i>>5)&0x3F; return ((m&1)<<5)|(m>>1); }
static inline uint32_t SH6(uint32_t i){ return ((i>>11)&0x1F) | (((i>>1)&1)<<5); }

static void cond_branch(Instr& o, uint32_t i, uint32_t target, bool to_lr,
                        bool to_ctr, bool lk, bool aa = false) {
    uint32_t bo = BO(i), bi = BI(i);
    uint32_t cr = bi >> 2, cc = bi & 3;
    const char* suff = to_lr ? "lr" : (to_ctr ? "ctr" : "");
    std::string lksfx = std::string(lk ? "l" : "") + (aa ? "a" : "");
    bool test_cond = !(bo & 0x10);
    bool dec_ctr   = !(bo & 0x04);

    const char* cond_hint = (bo & 0x02) ? ((bo & 0x01) ? "+" : "-") : "";
    const char* ctr_hint  = (bo & 0x08) ? ((bo & 0x01) ? "+" : "-") : "";

    std::string m, ops;
    if (!test_cond && dec_ctr) {
        m = (bo & 0x02) ? "bdz" : "bdnz";
        m += suff; m += lksfx; m += ctr_hint;
        if (!suff[0]) ops = fmt("0x%x", target);
        o.mnem = m; o.ops = ops; return;
    }
    if (test_cond && !dec_ctr) {
        bool t = (bo & 0x08);
        const char* cmn = t ? (cc==0?"blt":cc==1?"bgt":cc==2?"beq":"bso")
                            : (cc==0?"bge":cc==1?"ble":cc==2?"bne":"bns");
        m = cmn; m += suff; m += lksfx; m += cond_hint;
        if (!suff[0]) ops = cr ? fmt("cr%u,0x%x", cr, target) : fmt("0x%x", target);
        else          ops = cr ? fmt("cr%u", cr) : "";
        o.mnem = m; o.ops = ops; return;
    }
    if (test_cond && dec_ctr) {
        bool ctr_zero = (bo & 0x02);
        bool cond_true = (bo & 0x08);
        const char* nm = cond_true ? (ctr_zero?"bdzt":"bdnzt") : (ctr_zero?"bdzf":"bdnzf");
        m = nm; m += suff; m += lksfx;
        if (!suff[0]) ops = fmt("%s,0x%x", crbit(bi).c_str(), target);
        else          ops = crbit(bi);
        o.mnem = m; o.ops = ops; return;
    }
    m = std::string("bc") + suff + lksfx;
    if (bo == 20) m += "-";
    if (!suff[0]) ops = fmt("%u,%s,0x%x", bo, crbit(bi).c_str(), target);
    else          ops = fmt("%u,%s", bo, crbit(bi).c_str());
    o.mnem = m; o.ops = ops;
}

static const char* spr_name(uint32_t spr) {
    switch (spr) { case 1: return "xer"; case 8: return "lr"; case 9: return "ctr";
                   case 256: return "vrsave"; }
    return nullptr;
}

static void decode_31(Instr& o, uint32_t i);
static void decode_19(Instr& o, uint32_t i, uint32_t addr);
static void decode_3f(Instr& o, uint32_t i);
static void decode_3b(Instr& o, uint32_t i);
static void decode_04(Instr& o, uint32_t i);
static void decode_3a(Instr& o, uint32_t i);
static void decode_3e(Instr& o, uint32_t i);

Instr ppu_decode(uint32_t raw, uint32_t addr) {
    Instr o; o.raw = raw; o.addr = addr; o.valid = true;
    uint32_t i = raw;
    uint32_t op = OPCD(i);

    auto dform = [&](const char* m){ o.mnem = m; o.ops = fmt("r%u,r%u,%d", RT(i), RA(i), D(i)); };
    auto dform_u = [&](const char* m){ o.mnem = m; o.ops = fmt("r%u,r%u,%d", RA(i), RT(i), (int)UI(i)); };
    auto load = [&](const char* m){ o.mnem = m; o.ops = fmt("r%u,%d(%s)", RT(i), D(i), raz(RA(i)).c_str()); };
    auto loadf= [&](const char* m){ o.mnem = m; o.ops = fmt("f%u,%d(%s)", RT(i), D(i), raz(RA(i)).c_str()); };
    auto store = [&](const char* m){ o.mnem = m; o.ops = fmt("r%u,%d(%s)", RT(i), D(i), raz(RA(i)).c_str()); };
    auto storef= [&](const char* m){ o.mnem = m; o.ops = fmt("f%u,%d(%s)", RT(i), D(i), raz(RA(i)).c_str()); };

    switch (op) {
        case 0:  if (((i>>1)&0x3FF)==256){ o.mnem="attn"; o.ops=""; } else { o.valid=false; o.mnem=fmt(".long 0x%08x",i); } break;
        case 2:  o.mnem="tdi";  o.ops=fmt("%u,r%u,%d",RT(i),RA(i),D(i)); break;
        case 3:  o.mnem="twi";  o.ops=fmt("%u,r%u,%d",RT(i),RA(i),D(i)); break;
        case 7:  o.mnem="mulli";o.ops=fmt("r%u,r%u,%d",RT(i),RA(i),D(i)); break;
        case 8:  o.mnem="subfic";o.ops=fmt("r%u,r%u,%d",RT(i),RA(i),D(i)); break;
        case 10: {
            uint32_t f=BF(i); o.mnem = Lbit(i)?"cmpldi":"cmplwi";
            o.ops = f? fmt("cr%u,r%u,%u",f,RA(i),UI(i)) : fmt("r%u,%u",RA(i),UI(i));
        } break;
        case 11: {
            uint32_t f=BF(i); o.mnem = Lbit(i)?"cmpdi":"cmpwi";
            o.ops = f? fmt("cr%u,r%u,%d",f,RA(i),D(i)) : fmt("r%u,%d",RA(i),D(i));
        } break;
        case 12: dform("addic"); break;
        case 13: dform("addic."); break;
        case 14:
            if (RA(i)==0){ o.mnem="li"; o.ops=fmt("r%u,%d",RT(i),D(i)); }
            else dform("addi");
            break;
        case 15:
            if (RA(i)==0){ o.mnem="lis"; o.ops=fmt("r%u,%d",RT(i),(int16_t)UI(i)); }
            else dform("addis");
            break;
        case 16: {
            int32_t bd = (int16_t)(i & 0xFFFC);
            uint32_t tgt = AA(i)? (uint32_t)bd : addr + bd;
            cond_branch(o, i, tgt, false, false, LK(i), AA(i));
        } break;
        case 17: o.mnem="sc"; o.ops=""; break;
        case 18: {
            int32_t li = (int32_t)(i & 0x03FFFFFC); li <<= 6; li >>= 6;
            uint32_t tgt = AA(i)? (uint32_t)li : addr + li;
            const char* m = AA(i)? (LK(i)?"bla":"ba") : (LK(i)?"bl":"b");
            o.mnem=m; o.ops=fmt("0x%x",tgt);
        } break;
        case 19: decode_19(o,i,addr); break;
        case 20: o.mnem=fmt("rlwimi%s",dot(i)); o.ops=fmt("r%u,r%u,%u,%u,%u",RA(i),RT(i),SH(i),MB(i),ME(i)); break;
        case 21: {
            uint32_t sh=SH(i), mb=MB(i), me=ME(i);
            if (mb==0 && me==31)      { o.mnem=fmt("rotlwi%s",dot(i)); o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),sh); }
            else if (sh==0 && me==31) { o.mnem=fmt("clrlwi%s",dot(i)); o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),mb); }
            else { o.mnem=fmt("rlwinm%s",dot(i)); o.ops=fmt("r%u,r%u,%u,%u,%u",RA(i),RT(i),sh,mb,me); }
        } break;
        case 23:
            if (MB(i)==0 && ME(i)==31){ o.mnem=fmt("rotlw%s",dot(i)); o.ops=fmt("r%u,r%u,r%u",RA(i),RT(i),RB(i)); }
            else { o.mnem=fmt("rlwnm%s",dot(i)); o.ops=fmt("r%u,r%u,r%u,%u,%u",RA(i),RT(i),RB(i),MB(i),ME(i)); }
            break;
        case 24:
            if (RT(i)==0 && RA(i)==0 && UI(i)==0){ o.mnem="nop"; o.ops=""; }
            else { o.mnem="ori"; o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); }
            break;
        case 25: o.mnem="oris";  o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); break;
        case 26: o.mnem="xori";  o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); break;
        case 27: o.mnem="xoris"; o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); break;
        case 28: o.mnem="andi."; o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); break;
        case 29: o.mnem="andis.";o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),UI(i)); break;
        case 30: {
            uint32_t xo=(i>>2)&7; uint32_t sh=SH6(i), mb=MB6(i);
            const char* d=dot(i);
            if (xo==0){ if(sh==0){o.mnem=fmt("clrldi%s",d);o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),mb);}
                        else if(mb==0){o.mnem=fmt("rotldi%s",d);o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),sh);}
                        else {o.mnem=fmt("rldicl%s",d);o.ops=fmt("r%u,r%u,%u,%u",RA(i),RT(i),sh,mb);} }
            else if (xo==1){ o.mnem=fmt("rldicr%s",d); o.ops=fmt("r%u,r%u,%u,%u",RA(i),RT(i),sh,mb); }
            else if (xo==2){ o.mnem=fmt("rldic%s",d);  o.ops=fmt("r%u,r%u,%u,%u",RA(i),RT(i),sh,mb); }
            else if (xo==3){ o.mnem=fmt("rldimi%s",d); o.ops=fmt("r%u,r%u,%u,%u",RA(i),RT(i),sh,mb); }
            else { o.mnem=fmt("rldc%s",d); o.ops=fmt("r%u,r%u,r%u,%u",RA(i),RT(i),RB(i),mb); }
        } break;
        case 31: decode_31(o,i); break;
        case 32: load("lwz"); break;
        case 33: load("lwzu"); break;
        case 34: load("lbz"); break;
        case 35: load("lbzu"); break;
        case 36: store("stw"); break;
        case 37: store("stwu"); break;
        case 38: store("stb"); break;
        case 39: store("stbu"); break;
        case 40: load("lhz"); break;
        case 41: load("lhzu"); break;
        case 42: load("lha"); break;
        case 43: load("lhau"); break;
        case 44: store("sth"); break;
        case 45: store("sthu"); break;
        case 46: load("lmw"); break;
        case 47: store("stmw"); break;
        case 48: loadf("lfs"); break;
        case 49: loadf("lfsu"); break;
        case 50: loadf("lfd"); break;
        case 51: loadf("lfdu"); break;
        case 52: storef("stfs"); break;
        case 53: storef("stfsu"); break;
        case 54: storef("stfd"); break;
        case 55: storef("stfdu"); break;
        case 58: decode_3a(o,i); break;
        case 59: decode_3b(o,i); break;
        case 62: decode_3e(o,i); break;
        case 63: decode_3f(o,i); break;
        case 4:  decode_04(o,i); break;
        default: o.valid=false; o.mnem=fmt(".long 0x%08x",i); o.ops=""; break;
    }
    (void)dform_u;
    return o;
}

static void decode_19(Instr& o, uint32_t i, uint32_t addr) {
    uint32_t xo = XO_X(i);
    switch (xo) {
        case 16: {
            if (BO(i)==20 && BI(i)==0 && !LK(i)){ o.mnem="blr"; o.ops=""; return; }
            if (BO(i)==20 && BI(i)==0 && LK(i)){ o.mnem="blrl"; o.ops=""; return; }
            cond_branch(o, i, 0, true, false, LK(i));
        } break;
        case 528: {
            if (BO(i)==20 && BI(i)==0){ o.mnem=LK(i)?"bctrl":"bctr"; o.ops=""; return; }
            cond_branch(o, i, 0, false, true, LK(i));
        } break;
        case 0:   o.mnem="mcrf";  o.ops=fmt("cr%u,cr%u",BF(i),(i>>18)&7); break;
        case 33:  o.mnem="crnor"; o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 129: o.mnem="crandc";o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 150: o.mnem="isync"; o.ops=""; break;
        case 193: o.mnem="crxor"; o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 225: o.mnem="crnand";o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 257: o.mnem="crand"; o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 289: o.mnem="creqv"; o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 417: o.mnem="crorc"; o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        case 449: o.mnem="cror";  o.ops=fmt("%s,%s,%s",crbit(RT(i)).c_str(),crbit(RA(i)).c_str(),crbit(RB(i)).c_str()); break;
        default:  o.valid=false; o.mnem=fmt(".long 0x%08x",i); break;
    }
    (void)addr;
}

static void decode_31(Instr& o, uint32_t i) {
    uint32_t xo = XO_X(i);
    auto xo3 = [&](const char* m){ o.mnem=fmt("%s%s%s",m,oe(i),dot(i)); o.ops=fmt("r%u,r%u,r%u",RT(i),RA(i),RB(i)); };
    auto logic = [&](const char* m){ o.mnem=fmt("%s%s",m,dot(i)); o.ops=fmt("r%u,r%u,r%u",RA(i),RT(i),RB(i)); };
    auto idx  = [&](const char* m){ o.mnem=m; o.ops=fmt("r%u,%s,r%u",RT(i),raz(RA(i)).c_str(),RB(i)); };
    auto idxf = [&](const char* m){ o.mnem=m; o.ops=fmt("f%u,%s,r%u",RT(i),raz(RA(i)).c_str(),RB(i)); };
    auto sidx = [&](const char* m){ o.mnem=m; o.ops=fmt("r%u,%s,r%u",RT(i),raz(RA(i)).c_str(),RB(i)); };
    auto sidxf= [&](const char* m){ o.mnem=m; o.ops=fmt("f%u,%s,r%u",RT(i),raz(RA(i)).c_str(),RB(i)); };
    auto vidx = [&](const char* m){ o.mnem=m; o.ops=fmt("v%u,r%u,r%u",RT(i),RA(i),RB(i)); };

    switch (xo) {
        case 0:  { uint32_t f=BF(i); o.mnem=Lbit(i)?"cmpd":"cmpw"; o.ops=f?fmt("cr%u,r%u,r%u",f,RA(i),RB(i)):fmt("r%u,r%u",RA(i),RB(i)); } break;
        case 32: { uint32_t f=BF(i); o.mnem=Lbit(i)?"cmpld":"cmplw";o.ops=f?fmt("cr%u,r%u,r%u",f,RA(i),RB(i)):fmt("r%u,r%u",RA(i),RB(i)); } break;
        case 266: xo3("add"); break;
        case 10:  xo3("addc"); break;
        case 138: xo3("adde"); break;
        case 40:  xo3("subf"); break;
        case 8:   xo3("subfc"); break;
        case 136: xo3("subfe"); break;
        case 235: xo3("mullw"); break;
        case 75:  xo3("mulhw"); o.mnem=fmt("mulhw%s",dot(i)); break;
        case 11:  xo3("mulhwu");o.mnem=fmt("mulhwu%s",dot(i)); break;
        case 233: xo3("mulld"); break;
        case 73:  o.mnem=fmt("mulhd%s",dot(i)); o.ops=fmt("r%u,r%u,r%u",RT(i),RA(i),RB(i)); break;
        case 9:   o.mnem=fmt("mulhdu%s",dot(i));o.ops=fmt("r%u,r%u,r%u",RT(i),RA(i),RB(i)); break;
        case 491: xo3("divw"); break;
        case 459: xo3("divwu"); break;
        case 489: xo3("divd"); break;
        case 457: xo3("divdu"); break;
        case 104: o.mnem=fmt("neg%s%s",oe(i),dot(i)); o.ops=fmt("r%u,r%u",RT(i),RA(i)); break;
        case 234: o.mnem=fmt("addme%s%s",oe(i),dot(i)); o.ops=fmt("r%u,r%u",RT(i),RA(i)); break;
        case 202: o.mnem=fmt("addze%s%s",oe(i),dot(i)); o.ops=fmt("r%u,r%u",RT(i),RA(i)); break;
        case 232: o.mnem=fmt("subfme%s%s",oe(i),dot(i));o.ops=fmt("r%u,r%u",RT(i),RA(i)); break;
        case 200: o.mnem=fmt("subfze%s%s",oe(i),dot(i));o.ops=fmt("r%u,r%u",RT(i),RA(i)); break;
        case 28:  logic("and"); break;
        case 444: if (RT(i)==RB(i)){ o.mnem=fmt("mr%s",dot(i)); o.ops=fmt("r%u,r%u",RA(i),RT(i)); } else logic("or"); break;
        case 316: logic("xor"); break;
        case 476: logic("nand"); break;
        case 124: if (RT(i)==RB(i)){ o.mnem=fmt("not%s",dot(i)); o.ops=fmt("r%u,r%u",RA(i),RT(i)); } else logic("nor"); break;
        case 60:  logic("andc"); break;
        case 412: logic("orc"); break;
        case 284: logic("eqv"); break;
        case 954: o.mnem=fmt("extsb%s",dot(i)); o.ops=fmt("r%u,r%u",RA(i),RT(i)); break;
        case 922: o.mnem=fmt("extsh%s",dot(i)); o.ops=fmt("r%u,r%u",RA(i),RT(i)); break;
        case 986: o.mnem=fmt("extsw%s",dot(i)); o.ops=fmt("r%u,r%u",RA(i),RT(i)); break;
        case 26:  o.mnem=fmt("cntlzw%s",dot(i));o.ops=fmt("r%u,r%u",RA(i),RT(i)); break;
        case 58:  o.mnem=fmt("cntlzd%s",dot(i));o.ops=fmt("r%u,r%u",RA(i),RT(i)); break;
        case 24:  logic("slw"); break;
        case 536: logic("srw"); break;
        case 792: o.mnem=fmt("sraw%s",dot(i)); o.ops=fmt("r%u,r%u,r%u",RA(i),RT(i),RB(i)); break;
        case 824: o.mnem=fmt("srawi%s",dot(i));o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),SH(i)); break;
        case 27:  logic("sld"); break;
        case 539: logic("srd"); break;
        case 794: o.mnem=fmt("srad%s",dot(i)); o.ops=fmt("r%u,r%u,r%u",RA(i),RT(i),RB(i)); break;
        case 826: case 827: o.mnem=fmt("sradi%s",dot(i)); o.ops=fmt("r%u,r%u,%u",RA(i),RT(i),SH6(i)); break;
        case 339: { uint32_t spr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5); const char* s=spr_name(spr);
                    if(s){ o.mnem=fmt("mf%s",s); o.ops=fmt("r%u",RT(i)); } else { o.mnem="mfspr"; o.ops=fmt("r%u,%u",RT(i),spr);} } break;
        case 467: { uint32_t spr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5); const char* s=spr_name(spr);
                    if(s){ o.mnem=fmt("mt%s",s); o.ops=fmt("r%u",RT(i)); } else { o.mnem="mtspr"; o.ops=fmt("%u,r%u",spr,RT(i));} } break;
        case 19:
            if ((i>>20)&1){ o.mnem="mfocrf"; o.ops=fmt("r%u,%u",RT(i),(i>>12)&0xFF); }
            else { o.mnem="mfcr"; o.ops=fmt("r%u",RT(i)); }
            break;
        case 144: {
            uint32_t fxm=(i>>12)&0xFF;
            if ((i>>20)&1){ o.mnem="mtocrf"; o.ops=fmt("%u,r%u",fxm,RT(i)); }
            else { o.mnem="mtcrf"; o.ops=fmt("%u,r%u",fxm,RT(i)); }
        } break;
        case 23:  idx("lwzx"); break;
        case 55:  idx("lwzux"); break;
        case 87:  idx("lbzx"); break;
        case 119: idx("lbzux"); break;
        case 279: idx("lhzx"); break;
        case 311: idx("lhzux"); break;
        case 343: idx("lhax"); break;
        case 375: idx("lhaux"); break;
        case 341: idx("lwax"); break;
        case 21:  idx("ldx"); break;
        case 53:  idx("ldux"); break;
        case 151: sidx("stwx"); break;
        case 183: sidx("stwux"); break;
        case 215: sidx("stbx"); break;
        case 247: sidx("stbux"); break;
        case 407: sidx("sthx"); break;
        case 439: sidx("sthux"); break;
        case 149: sidx("stdx"); break;
        case 181: sidx("stdux"); break;
        case 790: idx("lhbrx"); break;
        case 534: idx("lwbrx"); break;
        case 918: sidx("sthbrx"); break;
        case 662: sidx("stwbrx"); break;
        case 535: idxf("lfsx"); break;
        case 567: idxf("lfsux"); break;
        case 599: idxf("lfdx"); break;
        case 631: idxf("lfdux"); break;
        case 663: sidxf("stfsx"); break;
        case 695: sidxf("stfsux"); break;
        case 727: sidxf("stfdx"); break;
        case 759: sidxf("stfdux"); break;
        case 983: sidxf("stfiwx"); break;
        case 20:  idx("lwarx"); break;
        case 84:  idx("ldarx"); break;
        case 150: sidx("stwcx."); break;
        case 214: sidx("stdcx."); break;
        case 371: { uint32_t tbr=((i>>16)&0x1F)|(((i>>11)&0x1F)<<5);
                    o.mnem = (tbr==269)?"mftbu":"mftb"; o.ops=fmt("r%u",RT(i)); } break;
        case 598: { uint32_t l=(i>>21)&3; o.mnem = l==1?"lwsync":(l==2?"ptesync":"sync"); o.ops=""; } break;
        case 854: o.mnem="eieio"; o.ops=""; break;
        case 982: o.mnem="icbi"; o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 1014:o.mnem="dcbz"; o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 54:  o.mnem="dcbst";o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 86:  o.mnem="dcbf"; o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 278: o.mnem="dcbt"; o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 246: o.mnem="dcbtst";o.ops=fmt("r%u,r%u",RA(i),RB(i)); break;
        case 4:   o.mnem="tw"; o.ops=fmt("%u,r%u,r%u",RT(i),RA(i),RB(i)); break;
        case 68:  o.mnem="td"; o.ops=fmt("%u,r%u,r%u",RT(i),RA(i),RB(i)); break;
        case 512: o.mnem="mcrxr"; o.ops=fmt("cr%u",BF(i)); break;
        case 6:   vidx("lvsl");   break;
        case 38:  vidx("lvsr");   break;
        case 7:   vidx("lvebx");  break;
        case 39:  vidx("lvehx");  break;
        case 71:  vidx("lvewx");  break;
        case 103: vidx("lvx");    break;
        case 359: vidx("lvxl");   break;
        case 135: vidx("stvebx"); break;
        case 167: vidx("stvehx"); break;
        case 199: vidx("stvewx"); break;
        case 231: vidx("stvx");   break;
        case 487: vidx("stvxl");  break;
        case 519: vidx("lvlx");   break;
        case 551: vidx("lvrx");   break;
        case 775: vidx("lvlxl");  break;
        case 807: vidx("lvrxl");  break;
        case 647: vidx("stvlx");  break;
        case 711: vidx("stvrx");  break;
        default:  o.valid=false; o.mnem=fmt(".long 0x%08x",i); break;
    }
}

static void decode_3a(Instr& o, uint32_t i) {
    int32_t ds = (int16_t)(i & 0xFFFC);
    switch (i & 3) {
        case 0: o.mnem="ld";  o.ops=fmt("r%u,%d(r%u)",RT(i),ds,RA(i)); break;
        case 1: o.mnem="ldu"; o.ops=fmt("r%u,%d(r%u)",RT(i),ds,RA(i)); break;
        case 2: o.mnem="lwa"; o.ops=fmt("r%u,%d(r%u)",RT(i),ds,RA(i)); break;
        default: o.valid=false; o.mnem=fmt(".long 0x%08x",i); break;
    }
}
static void decode_3e(Instr& o, uint32_t i) {
    int32_t ds = (int16_t)(i & 0xFFFC);
    switch (i & 3) {
        case 0: o.mnem="std";  o.ops=fmt("r%u,%d(r%u)",RT(i),ds,RA(i)); break;
        case 1: o.mnem="stdu"; o.ops=fmt("r%u,%d(r%u)",RT(i),ds,RA(i)); break;
        default: o.valid=false; o.mnem=fmt(".long 0x%08x",i); break;
    }
}

static void fp_abc(Instr& o, uint32_t i, const char* m){ o.mnem=fmt("%s%s",m,dot(i)); o.ops=fmt("f%u,f%u,f%u,f%u",RT(i),RA(i),RC_(i),RB(i)); }
static void fp_ab (Instr& o, uint32_t i, const char* m){ o.mnem=fmt("%s%s",m,dot(i)); o.ops=fmt("f%u,f%u,f%u",RT(i),RA(i),RB(i)); }
static void fp_ac (Instr& o, uint32_t i, const char* m){ o.mnem=fmt("%s%s",m,dot(i)); o.ops=fmt("f%u,f%u,f%u",RT(i),RA(i),RC_(i)); }
static void fp_b  (Instr& o, uint32_t i, const char* m){ o.mnem=fmt("%s%s",m,dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); }

static void decode_fp(Instr& o, uint32_t i, bool single) {
    uint32_t xo5 = (i >> 1) & 0x1F;
    const char* s = single ? "s" : "";
    switch (xo5) {
        case 21: fp_ab(o,i, single?"fadds":"fadd"); return;
        case 20: fp_ab(o,i, single?"fsubs":"fsub"); return;
        case 25: fp_ac(o,i, single?"fmuls":"fmul"); return;
        case 18: fp_ab(o,i, single?"fdivs":"fdiv"); return;
        case 22: o.mnem=fmt("fsqrt%s%s",s,dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); return;
        case 24: o.mnem=fmt("fres%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); return;
        case 26: o.mnem=fmt("frsqrte%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); return;
        case 29: fp_abc(o,i, single?"fmadds":"fmadd"); return;
        case 28: fp_abc(o,i, single?"fmsubs":"fmsub"); return;
        case 31: fp_abc(o,i, single?"fnmadds":"fnmadd"); return;
        case 30: fp_abc(o,i, single?"fnmsubs":"fnmsub"); return;
        case 23: fp_abc(o,i,"fsel"); return;
    }
    uint32_t xo = XO_X(i);
    switch (xo) {
        case 0:   o.mnem="fcmpu"; o.ops=fmt("cr%u,f%u,f%u",BF(i),RA(i),RB(i)); break;
        case 32:  o.mnem="fcmpo"; o.ops=fmt("cr%u,f%u,f%u",BF(i),RA(i),RB(i)); break;
        case 72:  fp_b(o,i,"fmr"); break;
        case 40:  fp_b(o,i,"fneg"); break;
        case 264: fp_b(o,i,"fabs"); break;
        case 136: fp_b(o,i,"fnabs"); break;
        case 12:  o.mnem=fmt("frsp%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 14:  o.mnem=fmt("fctiw%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 15:  o.mnem=fmt("fctiwz%s",dot(i));o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 814: o.mnem=fmt("fctid%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 815: o.mnem=fmt("fctidz%s",dot(i));o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 846: o.mnem=fmt("fcfid%s",dot(i)); o.ops=fmt("f%u,f%u",RT(i),RB(i)); break;
        case 583: o.mnem="mffs"; o.ops=fmt("f%u",RT(i)); break;
        case 711: o.mnem="mtfsf";o.ops=fmt("%u,f%u",(i>>17)&0xFF,RB(i)); break;
        case 38:  o.mnem="mtfsb1";o.ops=fmt("%u",RT(i)); break;
        case 70:  o.mnem="mtfsb0";o.ops=fmt("%u",RT(i)); break;
        case 64:  o.mnem="mcrfs"; o.ops=fmt("cr%u,cr%u",BF(i),(i>>18)&7); break;
        default:  o.valid=false; o.mnem=fmt(".long 0x%08x",i); break;
    }
}
static void decode_3b(Instr& o, uint32_t i){ decode_fp(o,i,true); }
static void decode_3f(Instr& o, uint32_t i){ decode_fp(o,i,false); }

static void decode_04(Instr& o, uint32_t i) {
    uint32_t vt=RT(i), va=RA(i), vb=RB(i), vc=RC_(i);
    uint32_t xo  = i & 0x7FF;
    uint32_t xo6 = i & 0x3F;
    auto vabc=[&](const char* m){ o.mnem=m; o.ops=fmt("v%u,v%u,v%u,v%u",vt,va,vb,vc); };
    auto vacb=[&](const char* m){ o.mnem=m; o.ops=fmt("v%u,v%u,v%u,v%u",vt,va,vc,vb); };
    auto vab =[&](const char* m){ o.mnem=m; o.ops=fmt("v%u,v%u,v%u",vt,va,vb); };
    auto vb_ =[&](const char* m){ o.mnem=m; o.ops=fmt("v%u,v%u",vt,vb); };
    auto vimm=[&](const char* m){ o.mnem=m; o.ops=fmt("v%u,v%u,%u",vt,vb,va); };

    switch (xo6) {
        case 46: vacb("vmaddfp");   return;
        case 47: vacb("vnmsubfp");  return;
        case 43: vabc("vperm");     return;
        case 42: vabc("vsel");      return;
        case 44: o.mnem="vsldoi"; o.ops=fmt("v%u,v%u,v%u,%u",vt,va,vb,(i>>6)&0xF); return;
        case 32: vabc("vmhaddshs"); return;
        case 33: vabc("vmhraddshs");return;
        case 34: vabc("vmladduhm"); return;
        case 36: vabc("vmsumubm");  return;
        case 37: vabc("vmsummbm");  return;
        case 38: vabc("vmsumuhm");  return;
        case 39: vabc("vmsumuhs");  return;
        case 40: vabc("vmsumshm");  return;
        case 41: vabc("vmsumshs");  return;
    }
    switch (xo) {
        case 10:   vab("vaddfp");    return;
        case 74:   vab("vsubfp");    return;
        case 1034: vab("vmaxfp");    return;
        case 1098: vab("vminfp");    return;
        case 970:  vimm("vctsxs");   return;
        case 906:  vimm("vctuxs");   return;
        case 842:  vimm("vcfsx");    return;
        case 778:  vimm("vcfux");    return;
        case 128:  vab("vadduwm");   return;
        case 266:  vb_("vrefp");     return;
        case 330:  vb_("vrsqrtefp"); return;
        case 394:  vb_("vexptefp");  return;
        case 458:  vb_("vlogefp");   return;
        case 1028: vab("vand");      return;
        case 1092: vab("vandc");     return;
        case 1156: vab("vor");       return;
        case 1220: vab("vxor");      return;
        case 1284: vab("vnor");      return;
        case 388:  vab("vslw");      return;
        case 452:  vab("vsl");       return;
        case 644:  vab("vsrw");      return;
        case 708:  vab("vsr");       return;
        case 900:  vab("vsraw");     return;
        case 140:  vab("vmrghw");    return;
        case 396:  vab("vmrglw");    return;
        case 652:  vimm("vspltw");   return;
        case 588:  vimm("vsplth");   return;
        case 524:  vimm("vspltb");   return;
        case 908:  o.mnem="vspltisw";o.ops=fmt("v%u,%d",vt,(int)(va<<27)>>27); return;
        case 844:  o.mnem="vspltish";o.ops=fmt("v%u,%d",vt,(int)(va<<27)>>27); return;
        case 780:  o.mnem="vspltisb";o.ops=fmt("v%u,%d",vt,(int)(va<<27)>>27); return;
        case 1024: vab("vsububm");   return;
        case 832:  vab("vaddshs");   return;
        case 1026: vab("vavgub");    return;
        case 902:  vab("vcmpgtsw");  return;
        case 386:  vab("vmaxsw");    return;
        case 12:   vab("vmrghb");    return;
        case 268:  vab("vmrglb");    return;
        case 520:  vab("vmuleub");   return;
        case 584:  vab("vmuleuh");   return;
        case 8:    vab("vmuloub");   return;
        case 72:   vab("vmulouh");   return;
        case 270:  vab("vpkshus");   return;
        case 260:  vab("vslb");      return;
        case 1036: vab("vslo");      return;
        case 772:  vab("vsrab");     return;
        case 516:  vab("vsrb");      return;
        case 1100: vab("vsro");      return;
        case 1920: vab("vsubsws");   return;
        case 1536: vab("vsububs");   return;
        case 1928: vab("vsumsws");   return;
        case 714:  vb_("vrfim");     return;
        case 522:  vb_("vrfin");     return;
        case 586:  vb_("vrfiz");     return;
        case 6:    vab("vcmpequb");  return;
        case 70:   vab("vcmpequh");  return;
        case 134:  vab("vcmpequw");  return;
        case 198:  vab("vcmpeqfp");  return;
        case 454:  vab("vcmpgefp");  return;
        case 710:  vab("vcmpgtfp");  return;
        case 6+1024:   vab("vcmpequb."); return;
        case 70+1024:  vab("vcmpequh."); return;
        case 134+1024: vab("vcmpequw."); return;
        case 198+1024: vab("vcmpeqfp."); return;
        case 454+1024: vab("vcmpgefp."); return;
        case 710+1024: vab("vcmpgtfp."); return;
    }
    o.valid=false; o.mnem=fmt(".long 0x%08x",i);
}
