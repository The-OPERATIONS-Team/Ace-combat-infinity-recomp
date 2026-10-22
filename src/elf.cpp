#include "elf.hpp"
#include <cstdio>
#include <fstream>

bool ElfImage::load(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { err = "cannot open " + path; return false; }
    auto sz = (size_t)f.tellg();
    f.seekg(0);
    raw_.resize(sz);
    f.read((char*)raw_.data(), (std::streamsize)sz);
    if (sz < 64) { err = "file too small"; return false; }

    const uint8_t* b = raw_.data();
    if (!(b[0]==0x7f && b[1]=='E' && b[2]=='L' && b[3]=='F')) { err = "bad ELF magic"; return false; }
    if (b[4] != 2) { err = "not ELF64"; return false; }
    if (b[5] != 2) { err = "not big-endian"; return false; }

    e_type    = be16(b + 0x10);
    e_machine = be16(b + 0x12);
    e_entry   = be64(b + 0x18);
    e_phoff   = be64(b + 0x20);
    e_shoff   = be64(b + 0x28);
    e_phnum   = be16(b + 0x38);
    e_shnum   = be16(b + 0x3c);
    e_shstrndx= be16(b + 0x3e);

    if (e_machine != EM_PPC64) { err = "not PPC64"; return false; }

    for (uint16_t i = 0; i < e_phnum; ++i) {
        const uint8_t* p = b + e_phoff + (uint64_t)i * 0x38;
        if (p + 0x38 > b + sz) break;
        ElfSegment s{};
        s.type   = be32(p + 0x00);
        s.flags  = be32(p + 0x04);
        s.offset = be64(p + 0x08);
        s.vaddr  = be64(p + 0x10);
        s.paddr  = be64(p + 0x18);
        s.filesz = be64(p + 0x20);
        s.memsz  = be64(p + 0x28);
        s.align  = be64(p + 0x30);
        segments.push_back(s);
    }

    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint8_t* p = b + e_shoff + (uint64_t)i * 0x40;
        if (p + 0x40 > b + sz) break;
        ElfSection s{};
        s.name_off  = be32(p + 0x00);
        s.type      = be32(p + 0x04);
        s.flags     = be64(p + 0x08);
        s.vaddr     = be64(p + 0x10);
        s.offset    = be64(p + 0x18);
        s.size      = be64(p + 0x20);
        s.link      = be32(p + 0x28);
        s.info      = be32(p + 0x2c);
        s.addralign = be64(p + 0x30);
        s.entsize   = be64(p + 0x38);
        sections.push_back(s);
    }

    resolve_section_names();
    compute_code_span();
    return true;
}

bool ElfImage::load_raw(const std::string& path, uint64_t base, std::string& err) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { err = "cannot open " + path; return false; }
    auto sz = (size_t)f.tellg();
    f.seekg(0);
    raw_.resize(sz);
    f.read((char*)raw_.data(), (std::streamsize)sz);
    ElfSegment s{};
    s.type = PT_LOAD; s.flags = 5; s.offset = 0; s.vaddr = base;
    s.filesz = sz; s.memsz = sz;
    segments.push_back(s);
    code_lo = base; code_hi = base + sz;
    return true;
}

bool ElfImage::rebase_prx(uint32_t base, std::string& err) {
    if (load_base) { err = "already rebased"; return false; }

    std::vector<const ElfSegment*> loads;
    for (const auto& s : segments) if (s.type == PT_LOAD) loads.push_back(&s);

    auto wat = [&](uint64_t vaddr, uint64_t need) -> uint8_t* {
        for (const auto* s : loads) {
            if (s->filesz == 0) continue;
            if (vaddr >= s->vaddr && vaddr + need <= s->vaddr + s->filesz) {
                uint64_t off = s->offset + (vaddr - s->vaddr);
                if (off + need <= raw_.size()) return raw_.data() + off;
            }
        }
        return nullptr;
    };
    auto w16 = [](uint8_t* p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; };
    auto w32 = [](uint8_t* p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; };
    auto w64 = [](uint8_t* p, uint64_t v){ for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(56-8*i)); };

    size_t applied = 0, unknown = 0;
    bool found = false;
    for (const auto& s : segments) {
        if (s.type != PT_SCE_PPURELA || s.filesz == 0) continue;
        found = true;
        for (uint64_t o = s.offset; o + 0x18 <= s.offset + s.filesz; o += 0x18) {
            const uint8_t* e = raw_.data() + o;
            uint64_t offset = be64(e + 0x00);
            uint8_t  idx_v  = e[0x0a], idx_a = e[0x0b];
            uint32_t type   = be32(e + 0x0c);
            uint64_t addend = be64(e + 0x10);
            if (type == 0) continue;
            if (idx_a >= loads.size()) { unknown++; continue; }
            uint64_t where = loads[idx_a]->vaddr + offset;
            uint64_t value = addend + (idx_v < loads.size()
                                       ? base + loads[idx_v]->vaddr : 0);
            uint8_t* p;
            switch (type) {
            case 1:    if ((p=wat(where,4))) { w32(p,(uint32_t)value); applied++; } break;
            case 4:    if ((p=wat(where,2))) { w16(p,(uint16_t)value); applied++; } break;
            case 5:    if ((p=wat(where,2))) { w16(p,(uint16_t)(value>>16)); applied++; } break;
            case 6:    if ((p=wat(where,2))) { w16(p,(uint16_t)((value+0x8000)>>16)); applied++; } break;
            case 38:   if ((p=wat(where,8))) { w64(p,value); applied++; } break;
            default: unknown++; break;
            }
        }
    }
    if (!found) { err = "no PT_SCE_PPURELA segment"; return false; }
    fprintf(stderr, "[prx] relocated at base 0x%x: %zu applied, %zu unknown/skipped\n",
            base, applied, unknown);

    for (auto& s : segments) s.vaddr += base;
    for (auto& s : sections) if (s.vaddr) s.vaddr += base;
    e_entry += base;
    if (code_hi) { code_lo += base; code_hi += base; }
    load_base = base;
    return true;
}

void ElfImage::resolve_section_names() {
    if (e_shstrndx >= sections.size()) return;
    const auto& strtab = sections[e_shstrndx];
    if (strtab.offset + strtab.size > raw_.size()) return;
    const char* base = (const char*)raw_.data() + strtab.offset;
    for (auto& s : sections) {
        if (s.name_off < strtab.size) s.name = std::string(base + s.name_off);
    }
}

void ElfImage::compute_code_span() {
    const uint32_t PF_X = 1;
    for (const auto& s : segments) {
        if (s.type != PT_LOAD || !(s.flags & PF_X) || s.filesz == 0) continue;
        if (code_lo == 0 || s.vaddr < code_lo) code_lo = s.vaddr;
        if (s.vaddr + s.filesz > code_hi) code_hi = s.vaddr + s.filesz;
    }
}

const uint8_t* ElfImage::at(uint64_t vaddr, uint64_t need) const {
    for (const auto& s : segments) {
        if (s.type != PT_LOAD && s.type != PT_TLS && s.type != PT_PROC_PARAM &&
            s.type != PT_PROC_PRX_PARAM)
            continue;
        if (s.filesz == 0) continue;
        if (vaddr >= s.vaddr && vaddr + need <= s.vaddr + s.filesz) {
            uint64_t off = s.offset + (vaddr - s.vaddr);
            if (off + need <= raw_.size()) return raw_.data() + off;
        }
    }
    return nullptr;
}

std::string ElfImage::cstr(uint64_t va) const {
    std::string out;
    for (uint64_t i = 0; i < 256; ++i) {
        const uint8_t* p = at(va + i, 1);
        if (!p || *p == 0) break;
        out.push_back((char)*p);
    }
    return out;
}
