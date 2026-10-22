#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "byteorder.hpp"

constexpr uint32_t PT_LOAD            = 1;
constexpr uint32_t PT_TLS             = 7;
constexpr uint32_t PT_PROC_PARAM      = 0x60000001;
constexpr uint32_t PT_PROC_PRX_PARAM  = 0x60000002;
constexpr uint32_t PT_SCE_PPURELA     = 0x700000a4;

constexpr uint16_t EM_PPC64 = 21;
constexpr uint16_t ET_EXEC  = 2;
constexpr uint16_t ET_DYN   = 3;

struct ElfSegment {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

struct ElfSection {
    uint32_t name_off;
    uint32_t type;
    uint64_t flags;
    uint64_t vaddr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
    std::string name;
};

class ElfImage {
public:
    bool load(const std::string& path, std::string& err);
    bool load_raw(const std::string& path, uint64_t base, std::string& err);

    bool rebase_prx(uint32_t base, std::string& err);
    uint32_t load_base = 0;

    uint16_t e_type    = 0;
    uint16_t e_machine = 0;
    uint64_t e_entry   = 0;
    uint64_t e_phoff   = 0, e_shoff = 0;
    uint16_t e_phnum   = 0, e_shnum = 0, e_shstrndx = 0;

    std::vector<ElfSegment> segments;
    std::vector<ElfSection> sections;

    const uint8_t* at(uint64_t vaddr, uint64_t need = 1) const;

    uint8_t  r8 (uint64_t va) const { auto p = at(va, 1); return p ? *p : 0; }
    uint16_t r16(uint64_t va) const { auto p = at(va, 2); return p ? be16(p) : 0; }
    uint32_t r32(uint64_t va) const { auto p = at(va, 4); return p ? be32(p) : 0; }
    uint64_t r64(uint64_t va) const { auto p = at(va, 8); return p ? be64(p) : 0; }

    std::string cstr(uint64_t va) const;

    uint64_t code_lo = 0, code_hi = 0;

    const std::vector<uint8_t>& bytes() const { return raw_; }

private:
    std::vector<uint8_t> raw_;
    void resolve_section_names();
    void compute_code_span();
};
