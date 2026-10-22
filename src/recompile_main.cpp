#include "elf.hpp"
#include "ppu_module.hpp"
#include "ppu_lift.hpp"
#include "ppu_decode.hpp"
#include "spu_lift.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <cstdarg>

static std::string F(const char* f, ...){
    char b[1024]; va_list ap; va_start(ap,f); vsnprintf(b,sizeof b,f,ap); va_end(ap); return b;
}

static void sha1(const uint8_t* data, size_t len, uint8_t out[20]){
    uint32_t h[5] = {0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    std::vector<uint8_t> m(data, data+len);
    uint64_t bits = (uint64_t)len*8;
    m.push_back(0x80);
    while (m.size()%64 != 56) m.push_back(0);
    for (int i=7;i>=0;i--) m.push_back((uint8_t)(bits>>(i*8)));
    for (size_t c=0;c<m.size();c+=64){
        uint32_t w[80];
        for (int i=0;i<16;i++)
            w[i] = (uint32_t)m[c+4*i]<<24 | (uint32_t)m[c+4*i+1]<<16 | (uint32_t)m[c+4*i+2]<<8 | m[c+4*i+3];
        for (int i=16;i<80;i++){ uint32_t x=w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i]=(x<<1)|(x>>31); }
        uint32_t a=h[0], b=h[1], cc=h[2], d=h[3], e=h[4];
        for (int i=0;i<80;i++){
            uint32_t f, k;
            if (i<20)      { f=(b&cc)|(~b&d);         k=0x5A827999u; }
            else if (i<40) { f=b^cc^d;                k=0x6ED9EBA1u; }
            else if (i<60) { f=(b&cc)|(b&d)|(cc&d);   k=0x8F1BBCDCu; }
            else           { f=b^cc^d;                k=0xCA62C1D6u; }
            uint32_t t = ((a<<5)|(a>>27)) + f + e + k + w[i];
            e=d; d=cc; cc=(b<<30)|(b>>2); b=a; a=t;
        }
        h[0]+=a; h[1]+=b; h[2]+=cc; h[3]+=d; h[4]+=e;
    }
    for (int i=0;i<5;i++){
        out[4*i]=(uint8_t)(h[i]>>24); out[4*i+1]=(uint8_t)(h[i]>>16);
        out[4*i+2]=(uint8_t)(h[i]>>8); out[4*i+3]=(uint8_t)h[i];
    }
}

static uint32_t name_nid(const std::string& name){
    static const uint8_t suffix[16] = {0x67,0x59,0x65,0x99,0x04,0x25,0x04,0x90,
                                       0x56,0x64,0x27,0x49,0x94,0x89,0x74,0x1A};
    std::vector<uint8_t> b(name.begin(), name.end());
    b.insert(b.end(), suffix, suffix+16);
    uint8_t d[20]; sha1(b.data(), b.size(), d);
    return (uint32_t)d[0] | (uint32_t)d[1]<<8 | (uint32_t)d[2]<<16 | (uint32_t)d[3]<<24;
}

static std::map<uint32_t,std::string> g_nid_names;
static bool load_nid_db(const std::string& path){
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f,line)){
        if (!line.empty() && line.back()=='\r') line.pop_back();
        std::vector<std::string> col;
        std::stringstream ss(line); std::string c;
        while (std::getline(ss,c,',')) col.push_back(c);
        if (col.size()==3 && col[0].rfind("0x",0)==0)
            g_nid_names[(uint32_t)strtoul(col[0].c_str(),nullptr,0)] = col[2];
        else if (col.size()==2 && col[0]!="lib" && !col[1].empty())
            g_nid_names[name_nid(col[1])] = col[1];
    }
    return true;
}

struct Imp { uint32_t nid; std::string lib, fname; };

static std::vector<uint32_t> g_extra_seeds;

struct Mod {
    std::string path;
    uint32_t    base = 0;
    ElfImage    elf;
    PpuModule   m;
    std::map<uint32_t,Imp> imp;
    std::set<uint32_t> starts, called, missing;
    std::vector<std::string> bodies;
    std::vector<std::pair<uint32_t,uint32_t>> extents;
    uint64_t n_insn = 0;
};

static void process_module(Mod& mod){
    ElfImage& elf = mod.elf; PpuModule& m = mod.m;

    for (auto& lib : m.imports)
        for (auto& fn : lib.funcs){
            auto it=g_nid_names.find(fn.nid);
            mod.imp[fn.stub_addr] = { fn.nid, lib.name,
                it!=g_nid_names.end()?it->second:F("nid_%08x",fn.nid) };
        }
    auto& imp = mod.imp;
    auto& starts = mod.starts;

    for (auto& kv : m.func_seeds)
        if (kv.first>=elf.code_lo && kv.first<elf.code_hi && !(kv.first&3) && !imp.count(kv.first))
            starts.insert(kv.first);

    if (mod.base==0)
        for (uint32_t s : g_extra_seeds)
            if (s>=elf.code_lo && s<elf.code_hi && !(s&3) && !imp.count(s)) starts.insert(s);

    for (uint32_t a=(uint32_t)elf.code_lo; a+4<=elf.code_hi; a+=4){
        uint32_t i = elf.r32(a);
        if ((i>>26)==18 && (i&1) && !((i>>1)&1)){
            int32_t li=(int32_t)(i&0x03FFFFFC); li<<=6; li>>=6;
            uint32_t t=a+li;
            if (t>=elf.code_lo && t<elf.code_hi && !imp.count(t)) starts.insert(t);
        }
    }

    auto looks_code=[&](uint32_t v){
        return v>=elf.code_lo && v<elf.code_hi && !(v&3) && ppu_decode(elf.r32(v),v).valid;
    };
    for (const auto& s : elf.segments){
        if (s.type!=PT_LOAD || s.filesz==0) continue;
        uint32_t a=(uint32_t)s.vaddr, hi=(uint32_t)(s.vaddr+s.filesz);
        while (a+4<=hi){
            if (looks_code(elf.r32(a))){
                uint32_t run=a; while (run+4<=hi && looks_code(elf.r32(run))) run+=4;
                if ((run-a)/4 >= 3)
                    for (uint32_t p=a; p<run; p+=4){ uint32_t v=elf.r32(p); if(!imp.count(v)) starts.insert(v); }
                a=run;
            } else a+=4;
        }
    }

    auto is_term=[&](uint32_t a)->bool{
        if (a<elf.code_lo || a+4>elf.code_hi || (a&3)) return false;
        uint32_t w=elf.r32(a);
        if (w==0x4e800020u) return true;
        if ((w>>26)==18 && !(w&1)) return true;
        if ((w>>26)==19){ uint32_t xo=(w>>1)&0x3FF; if(xo==16||xo==528) return true; }
        return false;
    };
    for (const auto& s : elf.segments){
        if (s.type!=PT_LOAD || s.filesz==0) continue;
        uint32_t a=(uint32_t)s.vaddr, hi=(uint32_t)(s.vaddr+s.filesz);
        for (; a+4<=hi; a+=4){
            uint32_t v=elf.r32(a);
            if (looks_code(v) && !imp.count(v) && is_term(v-4)) starts.insert(v);
        }
    }

    auto lift_all=[&](){
        std::set<uint32_t> bounds = starts;
        for (auto& kv : imp) bounds.insert(kv.first);
        mod.called.clear(); mod.bodies.clear(); mod.bodies.reserve(starts.size());
        mod.extents.clear(); mod.extents.reserve(starts.size()); mod.n_insn=0;
        for (uint32_t s : starts){
            auto nb = bounds.upper_bound(s);
            uint32_t e = (nb==bounds.end()) ? (uint32_t)elf.code_hi : *nb;
            if (e<=s || e-s > 0x20000) e = s+0x20000;
            if (e>elf.code_hi) e=(uint32_t)elf.code_hi;
            mod.n_insn += (e-s)/4;
            mod.extents.emplace_back(s, e);
            mod.bodies.push_back(lift_function(elf, s, e, mod.called, m.all_tocs));
        }
    };
    const int MAX_ROUNDS=16;
    for (int round=0; ; ++round){
        lift_all();
        std::set<uint32_t> add;
        for (uint32_t c : mod.called)
            if (!starts.count(c) && !imp.count(c) && looks_code(c)) add.insert(c);
        if (add.empty()){ fprintf(stderr,"[%s] discovery converged after %d round(s)\n",mod.path.c_str(),round+1); break; }
        if (round+1>=MAX_ROUNDS){ fprintf(stderr,"[%s] discovery hit round cap; %zu straggler(s) -> stubs\n",mod.path.c_str(),add.size()); break; }
        fprintf(stderr,"[%s] round %d: +%zu tail-call/indirect function(s)\n",mod.path.c_str(),round,add.size());
        starts.insert(add.begin(), add.end());
    }

    std::set<uint32_t> defined = starts;
    for (auto& kv : imp) defined.insert(kv.first);
    for (uint32_t c : mod.called) if(!defined.count(c)) mod.missing.insert(c);

    fprintf(stderr,"[%s] %zu functions (%llu instrs), %zu imports, %zu missing\n",
            mod.path.c_str(), starts.size(),(unsigned long long)mod.n_insn,
            mod.imp.size(), mod.missing.size());
}

struct AutoSpu { std::string fname, src; uint32_t entry; };
static uint32_t rd32be(const uint8_t* p){
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void discover_spu_elfs(const Mod& mod, std::vector<AutoSpu>& out){
    for (const auto& s : mod.elf.segments){
        if (s.type!=PT_LOAD || s.filesz<0x40) continue;
        const uint8_t* d = mod.elf.at(s.vaddr, s.filesz);
        if (!d) continue;
        for (uint64_t off=0; off+52<=s.filesz; off+=4){
            const uint8_t* p = d+off;
            if (p[0]!=0x7f||p[1]!='E'||p[2]!='L'||p[3]!='F') continue;
            if (p[4]!=1 || p[5]!=2) continue;
            uint16_t etype=(uint16_t)((p[16]<<8)|p[17]), mach=(uint16_t)((p[18]<<8)|p[19]);
            if (mach!=23 || etype!=2) continue;
            uint32_t entry=rd32be(p+24), phoff=rd32be(p+28);
            uint16_t phentsize=(uint16_t)((p[42]<<8)|p[43]), phnum=(uint16_t)((p[44]<<8)|p[45]);
            if (!phnum || phnum>16 || phentsize!=32) continue;
            if (entry>=0x40000 || (entry&3)) continue;
            if (off+phoff+(uint64_t)phnum*32 > s.filesz) continue;
            std::vector<uint8_t> ls(0x40000,0);
            uint32_t lo=0x40000, hi=0; bool ok=true;
            for (int k=0;k<phnum;k++){
                const uint8_t* ph=p+phoff+(uint32_t)k*32;
                uint32_t ptype=rd32be(ph), poff=rd32be(ph+4), pva=rd32be(ph+8);
                uint32_t pfsz=rd32be(ph+16), pmsz=rd32be(ph+20);
                if (ptype!=1 || !pmsz) continue;
                if (pmsz<pfsz || (uint64_t)pva+pmsz>0x40000 || off+poff+pfsz>s.filesz){ ok=false; break; }
                memcpy(ls.data()+pva, p+poff, pfsz);
                if (pva<lo) lo=pva;
                if (pva+pmsz>hi) hi=pva+pmsz;
            }
            if (!ok || hi<=lo || entry<lo || entry>=hi) continue;
            AutoSpu a; a.entry=entry;
            a.fname=F("spu_auto_%llx",(unsigned long long)(s.vaddr+off));
            a.src = spu_lift_image(ls.data()+lo, lo, hi-lo, entry, a.fname.c_str());
            fprintf(stderr,"[spu-auto] %s: embedded SPU ELF at va 0x%llx entry=0x%x range=[0x%x,0x%x)\n",
                    mod.path.c_str(),(unsigned long long)(s.vaddr+off),entry,lo,hi);
            out.push_back(std::move(a));
            if (out.size()>=64){ fprintf(stderr,"[spu-auto] cap reached (64)\n"); return; }
        }
    }
}

int main(int argc, char** argv){
    if (argc < 3){
        fprintf(stderr,"usage: %s <elf> <outdir> [names.csv] [--prx <elf>[@0xBASE]]... [--patches <file>]\n"
                       "       [--entry-opd 0xADDR] [--seed 0xADDR]...\n",argv[0]);
        return 2;
    }
    std::string in=argv[1], out=argv[2];
    std::string nid_path, patch_path; uint32_t entry_opd_override=0;
    std::vector<std::pair<std::string,uint32_t>> prx_specs;
    uint32_t next_prx_base = 0x1e000000u;
    for (int k=3;k<argc;k++){
        std::string a=argv[k];
        if (a=="--entry-opd" && k+1<argc) entry_opd_override=(uint32_t)strtoul(argv[++k],nullptr,0);
        else if (a=="--seed" && k+1<argc) g_extra_seeds.push_back((uint32_t)strtoul(argv[++k],nullptr,0));
        else if (a=="--patches" && k+1<argc) patch_path=argv[++k];
        else if (a=="--prx" && k+1<argc){
            std::string spec=argv[++k]; uint32_t b=0;
            auto at=spec.find('@');
            if (at!=std::string::npos){ b=(uint32_t)strtoul(spec.c_str()+at+1,nullptr,0); spec=spec.substr(0,at); }
            if (!b){ b=next_prx_base; next_prx_base+=0x00800000u; }
            prx_specs.emplace_back(spec,b);
        }
        else if (a.rfind("--",0)!=0) nid_path=a;
    }
    if (!nid_path.empty() && !load_nid_db(nid_path)){ fprintf(stderr,"cannot read %s\n",nid_path.c_str()); return 1; }
    if (nid_path.empty()) fprintf(stderr,"warning: no import name list given; imports will be unnamed\n");
    if (!patch_path.empty()){
        std::string perr;
        if (!ppu_load_patches(patch_path, perr)){ fprintf(stderr,"%s\n",perr.c_str()); return 1; }
    }

    std::vector<Mod> mods(1+prx_specs.size());
    std::string err;
    mods[0].path = in;
    if(!mods[0].elf.load(in,err)){ fprintf(stderr,"load: %s\n",err.c_str()); return 1; }
    if(!mods[0].m.analyze(mods[0].elf,err)){ fprintf(stderr,"analyze: %s\n",err.c_str()); return 1; }
    for (size_t i=0;i<prx_specs.size();++i){
        Mod& p = mods[1+i];
        p.path = prx_specs[i].first; p.base = prx_specs[i].second;
        if(!p.elf.load(p.path,err)){ fprintf(stderr,"load %s: %s\n",p.path.c_str(),err.c_str()); return 1; }
        if(!p.elf.rebase_prx(p.base,err)){ fprintf(stderr,"rebase %s: %s\n",p.path.c_str(),err.c_str()); return 1; }
        if(!p.m.analyze(p.elf,err)){ fprintf(stderr,"analyze %s: %s\n",p.path.c_str(),err.c_str()); return 1; }
    }

    struct Exp { uint32_t entry, toc; std::string lib; };
    std::map<uint32_t,Exp> exports;
    std::vector<std::pair<uint32_t,uint32_t>> module_starts;
    for (size_t i=1;i<mods.size();++i){
        Mod& p = mods[i];
        auto fx=[&](uint32_t v){ return (v && v<p.base) ? v+p.base : v; };
        uint32_t mstart_entry=0, mstart_toc=0;
        for (auto& lib : p.m.exports)
            for (auto& fn : lib.funcs){
                uint32_t entry = fx(p.elf.r32(fn.second));
                uint32_t toc   = fx(p.elf.r32(fn.second+4));
                if (entry < p.elf.code_lo || entry >= p.elf.code_hi) continue;
                if (lib.name.empty()){
                    if (fn.first==0xBC9A0086u){ mstart_entry=entry; mstart_toc=toc; }
                    continue;
                }
                exports.emplace(fn.first, Exp{entry,toc,lib.name});
            }
        if (mstart_entry) module_starts.emplace_back(mstart_entry,mstart_toc);
        else fprintf(stderr,"[%s] warning: no module_start export found\n",p.path.c_str());
    }

    for (auto& mod : mods) process_module(mod);

    {
        std::string bad = ppu_patch_problems();
        if (!bad.empty()){ fprintf(stderr,"%sno output written\n",bad.c_str()); return 1; }
    }

    size_t bridged=0;
    for (auto& mod : mods)
        for (auto& kv : mod.imp)
            if (exports.count(kv.second.nid)) bridged++;
    fprintf(stderr,"imports bridged to recompiled PRX exports: %zu\n", bridged);

    std::set<uint32_t> g_defined, g_missing;
    for (auto& mod : mods){
        g_defined.insert(mod.starts.begin(), mod.starts.end());
        for (auto& kv : mod.imp) g_defined.insert(kv.first);
    }
    for (auto& mod : mods)
        for (uint32_t a : mod.missing)
            if (!g_defined.count(a)) g_missing.insert(a);

    auto W=[&](const std::string& name, const std::string& content){
        std::ofstream f(out+"/"+name); f<<content;
    };

    {
        std::string h = "#pragma once\n#include \"ppu_runtime.h\"\n";
        for (uint32_t a: g_defined) h += F("void sub_%x(PPUContext*, uint8_t*);\n", a);
        for (uint32_t a: g_missing) h += F("void sub_%x(PPUContext*, uint8_t*);\n", a);
        W("ppc_decls.h", h);
    }

    std::vector<std::string> group_files;
    {
        const size_t GROUP = 400;
        size_t g=0, k=0; std::string c;
        auto flush=[&](){
            if (c.empty()) return;
            std::string fn = F("ppc_func_%03zu.c", g++);
            W(fn, "#include \"ppc_decls.h\"\n\n"+c); group_files.push_back(fn); c.clear();
        };
        for (auto& mod : mods)
            for (auto& b : mod.bodies){
                c += b + "\n";
                if (++k % GROUP == 0) flush();
            }
        flush();
    }

    {
        std::string c = "#include \"ppc_decls.h\"\n#include <stdio.h>\n#include <stdlib.h>\n\n";
        for (auto& mod : mods)
            for (auto& kv: mod.imp){
                auto e = exports.find(kv.second.nid);
                if (e != exports.end()){
                    c += F("void sub_%x(PPUContext* ctx, uint8_t* base){\n"
                           "  PPU_STD(base,(uint32_t)(ctx->r[1]+40),ctx->r[2]);\n"
                           "  ctx->r[2]=0x%xull;\n"
                           "  sub_%x(ctx,base);\n}\n",
                           kv.first, e->second.toc, e->second.entry);
                } else {
                    c += F("void sub_%x(PPUContext* ctx, uint8_t* base){ ppu_hle(0x%xu, \"%s\", \"%s\", ctx, base); }\n",
                           kv.first, kv.second.nid, kv.second.lib.c_str(), kv.second.fname.c_str());
                }
            }
        for (uint32_t a: g_missing)
            c += F("void sub_%x(PPUContext* ctx, uint8_t* base){ (void)ctx;(void)base; ppu_miss(0x%xu); }\n", a, a);
        c += "static __thread uint32_t g_lookup_miss_ea;\n";
        c += "void sub_lookup_fallback(PPUContext* ctx, uint8_t* base){ (void)ctx;(void)base; ppu_lookup_miss(g_lookup_miss_ea); }\n";
        std::set<uint32_t> all = g_defined;
        all.insert(g_missing.begin(), g_missing.end());
        c += "\ntypedef struct { uint32_t a; PPCFunc f; } PPCEnt;\n";
        c += "static const PPCEnt g_tab[] = {\n";
        for (uint32_t a: all) c += F("  {0x%x, sub_%x},\n", a, a);
        c += "};\n";
        c += "static const unsigned g_tab_n = sizeof(g_tab)/sizeof(g_tab[0]);\n";
        c += R"(PPCFunc ppu_lookup(uint32_t a){
  unsigned lo=0, hi=g_tab_n;
  while(lo<hi){ unsigned mid=(lo+hi)/2; if(g_tab[mid].a<a) lo=mid+1; else hi=mid; }
  if(lo<g_tab_n && g_tab[lo].a==a) return g_tab[lo].f;
  g_lookup_miss_ea=a; return sub_lookup_fallback;
}
)";
        {
            std::map<uint32_t, std::pair<uint32_t,uint32_t>> ext;
            for (auto& mod : mods)
                for (auto& e : mod.extents)
                    if (e.second > e.first) ext[e.first] = { e.second, 0 };
            c += "\ntypedef struct { uint32_t a, e; PPCFunc f; } PPCExt;\n";
            c += "static const PPCExt g_ext[] = {\n";
            for (auto& kv : ext) c += F("  {0x%x, 0x%x, sub_%x},\n", kv.first, kv.second.first, kv.first);
            c += "};\n";
            c += "static const unsigned g_ext_n = sizeof(g_ext)/sizeof(g_ext[0]);\n";
            c += R"(PPCFunc ppu_lookup_ex(uint32_t a, PPUContext* ctx){
  PPCFunc f = ppu_lookup(a);
  if (f != sub_lookup_fallback) return f;
  unsigned lo=0, hi=g_ext_n;
  while(lo<hi){ unsigned mid=(lo+hi)/2; if(g_ext[mid].a<=a) lo=mid+1; else hi=mid; }
  if (lo>0){
    const PPCExt* e=&g_ext[lo-1];
    if (a>e->a && a<e->e && !(a&3)){ ctx->resume_pc=a; return e->f; }
  }
  g_lookup_miss_ea=a; return sub_lookup_fallback;
}
)";
        }
        W("ppc_hle.c", c);
    }

    std::vector<AutoSpu> auto_spus;
    for (auto& mod : mods) discover_spu_elfs(mod, auto_spus);
    for (auto& a : auto_spus) W(F("spu_body_%s.c", a.fname.c_str()), a.src);

    struct PrxSeg { std::string file; uint64_t vaddr, filesz; };
    std::vector<PrxSeg> prx_segs;
    for (size_t i=1;i<mods.size();++i){
        Mod& p = mods[i]; unsigned si=0;
        for (auto& s : p.elf.segments){
            if (s.type!=PT_LOAD || s.filesz==0) continue;
            const uint8_t* d = p.elf.at(s.vaddr, s.filesz);
            if (!d){ fprintf(stderr,"[%s] seg at 0x%llx unreadable\n",p.path.c_str(),(unsigned long long)s.vaddr); continue; }
            std::string fn = F("prx%zu_seg%u.bin", i-1, si++);
            std::ofstream f(out+"/"+fn, std::ios::binary);
            f.write((const char*)d,(std::streamsize)s.filesz);
            prx_segs.push_back({out+"/"+fn, s.vaddr, s.filesz});
        }
    }

    {
        ElfImage& elf = mods[0].elf; PpuModule& m = mods[0].m;
        uint32_t entry_opd  = entry_opd_override ? entry_opd_override : (uint32_t)elf.e_entry;
        uint32_t entry_code = elf.r32(entry_opd);
        uint32_t toc        = elf.r32(entry_opd+4) ? elf.r32(entry_opd+4) : m.module_toc;
        std::string c = "#include \"ppc_decls.h\"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
                        "#ifdef _WIN32\n#include <windows.h>\n#endif\n\n";
        c += "static const char* ELF_PATH = \"" + in + "\";\n";
        c += "typedef struct { unsigned long long off,vaddr,filesz,memsz; } Seg;\n";
        c += "static const Seg SEGS[] = {\n";
        for (auto& s : elf.segments)
            if (s.type==PT_LOAD && s.filesz)
                c += F("  {0x%llxull,0x%llxull,0x%llxull,0x%llxull},\n",
                       (unsigned long long)s.offset,(unsigned long long)s.vaddr,
                       (unsigned long long)s.filesz,(unsigned long long)s.memsz);
        c += "};\n";
        c += "static const unsigned NSEG = sizeof(SEGS)/sizeof(SEGS[0]);\n";
        c += "typedef struct { const char* path; unsigned long long vaddr, filesz; } PrxSeg;\n";
        c += "static const PrxSeg PRXSEGS[] = {\n";
        for (auto& s : prx_segs)
            c += F("  {\"%s\",0x%llxull,0x%llxull},\n", s.file.c_str(),
                   (unsigned long long)s.vaddr,(unsigned long long)s.filesz);
        c += "  {0,0,0}\n};\n";
        c += "typedef struct { uint32_t entry, toc; } PrxStart;\n";
        c += "static const PrxStart PRXSTART[] = {\n";
        for (auto& ms : module_starts) c += F("  {0x%x,0x%x},\n", ms.first, ms.second);
        c += "  {0,0}\n};\n";
        c += F("#define GUEST_SIZE 0x%llxull\n", 0x50000000ull);
        c += F("#define ENTRY 0x%xu\n#define TOCV 0x%xu\n", entry_code, toc);
        c += R"(
extern int g_cap_writewatch;

int main(void){
#ifdef _WIN32
  uint8_t* base = NULL;
  if(!getenv("PS3_NOWRITEWATCH")){
    base = (uint8_t*)VirtualAlloc(NULL, 0x100000000ull,
                                  MEM_RESERVE|MEM_COMMIT|MEM_WRITE_WATCH, PAGE_READWRITE);
    if(base) g_cap_writewatch = 1;
  }
  if(!base)
    base = (uint8_t*)VirtualAlloc(NULL, 0x100000000ull, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
#else
  uint8_t* base = (uint8_t*)calloc(GUEST_SIZE,1);
#endif
  if(!base){ fprintf(stderr,"alloc failed\n"); return 1; }
  FILE* f = fopen(ELF_PATH,"rb");
  if(!f){ fprintf(stderr,"open %s failed\n",ELF_PATH); return 1; }
  for(unsigned i=0;i<NSEG;i++){
    fseek(f, (long)SEGS[i].off, SEEK_SET);
    if (SEGS[i].vaddr + SEGS[i].filesz <= GUEST_SIZE)
      fread(base + SEGS[i].vaddr, 1, SEGS[i].filesz, f);
  }
  fclose(f);
  for(unsigned i=0;PRXSEGS[i].path;i++){
    FILE* p = fopen(PRXSEGS[i].path,"rb");
    if(!p){ fprintf(stderr,"open %s failed\n",PRXSEGS[i].path); return 1; }
    fread(base + PRXSEGS[i].vaddr, 1, PRXSEGS[i].filesz, p);
    fclose(p);
  }
  ppu_rt_init(base, GUEST_SIZE);
  PPUContext ctx; memset(&ctx,0,sizeof ctx);
  ctx.r[1] = GUEST_SIZE - 0x100000;
  for(unsigned i=0;PRXSTART[i].entry;i++){
    ctx.r[2] = PRXSTART[i].toc;
    ctx.r[3] = 0; ctx.r[4] = 0;
    fprintf(stderr,"[boot] prx module_start entry=0x%x toc=0x%x\n",PRXSTART[i].entry,PRXSTART[i].toc);
    ppu_lookup(PRXSTART[i].entry)(&ctx, base);
    fprintf(stderr,"[boot] prx module_start -> 0x%x\n",(uint32_t)ctx.r[3]);
  }
  ctx.r[2] = TOCV;
  PPCFunc fn = ppu_lookup(ENTRY);
  if(!fn){ fprintf(stderr,"entry 0x%x not recompiled\n",ENTRY); return 1; }
  fprintf(stderr,"[boot] entry=0x%x toc=0x%x\n", ENTRY, TOCV);
  fn(&ctx, base);
  printf("[exit] r3=%llu (0x%llx)\n",(unsigned long long)ctx.r[3],(unsigned long long)ctx.r[3]);
  return 0;
}
)";
        W("ppc_main.c", c);
    }

    size_t tot_fn=0; uint64_t tot_insn=0;
    for (auto& mod : mods){ tot_fn+=mod.starts.size(); tot_insn+=mod.n_insn; }
    fprintf(stderr,"total: %zu functions (%llu instrs) across %zu module(s), %zu bridged imports -> %s\n",
            tot_fn,(unsigned long long)tot_insn,mods.size(),bridged,out.c_str());
    fprintf(stderr,"groups=%zu  entry_code=0x%x toc=0x%x\n", group_files.size(),
            mods[0].elf.r32((uint32_t)mods[0].elf.e_entry), mods[0].m.module_toc);
    return 0;
}
