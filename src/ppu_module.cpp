#include "ppu_module.hpp"
#include <cstdio>

static constexpr uint32_t PROC_PARAM_MAGIC = 0x13bcc5f6;
static constexpr uint32_t PRX_PARAM_MAGIC  = 0x1b434cec;

static uint32_t fixva(const ElfImage& elf, uint32_t v) {
    return (elf.load_base && v && v < elf.load_base) ? v + elf.load_base : v;
}

static void parse_proc_param(const ElfImage& elf, ProcParam& pp) {
    for (const auto& s : elf.segments) {
        if (s.type != PT_PROC_PARAM) continue;
        uint64_t va = s.vaddr;
        pp.present           = true;
        pp.size              = elf.r32(va + 0x00);
        pp.magic             = elf.r32(va + 0x04);
        pp.version           = elf.r32(va + 0x08);
        pp.sdk_version       = elf.r32(va + 0x0c);
        pp.primary_prio      = elf.r32(va + 0x10);
        pp.primary_stacksize = elf.r32(va + 0x14);
        pp.malloc_pagesize   = elf.r32(va + 0x18);
        return;
    }
}

static void parse_prx_param(const ElfImage& elf, PrxParam& pp) {
    for (const auto& s : elf.segments) {
        if (s.type != PT_PROC_PRX_PARAM) continue;
        uint64_t va = s.vaddr;
        pp.present       = true;
        pp.size          = elf.r32(va + 0x00);
        pp.magic         = elf.r32(va + 0x04);
        pp.version       = elf.r32(va + 0x08);
        pp.libent_start  = elf.r32(va + 0x10);
        pp.libent_end    = elf.r32(va + 0x14);
        pp.libstub_start = elf.r32(va + 0x18);
        pp.libstub_end   = elf.r32(va + 0x1c);
        return;
    }
}

static void parse_module_info(const ElfImage& elf, PrxParam& pp, uint32_t& module_toc) {
    if (elf.e_type == ET_EXEC) return;
    if (elf.segments.empty()) return;
    const auto& s0 = elf.segments[0];
    uint64_t mi = s0.paddr - s0.offset + s0.vaddr;
    uint32_t gp = fixva(elf, elf.r32(mi + 0x20));
    if (gp < elf.code_hi) return;
    pp.present       = true;
    pp.magic         = PRX_PARAM_MAGIC;
    pp.libent_start  = fixva(elf, elf.r32(mi + 0x24));
    pp.libent_end    = fixva(elf, elf.r32(mi + 0x28));
    pp.libstub_start = fixva(elf, elf.r32(mi + 0x2c));
    pp.libstub_end   = fixva(elf, elf.r32(mi + 0x30));
    module_toc       = gp;
    fprintf(stderr, "[prx] sceModuleInfo: toc=0x%x libent=[0x%x..0x%x] libstub=[0x%x..0x%x]\n",
            gp, pp.libent_start, pp.libent_end, pp.libstub_start, pp.libstub_end);
}

static void parse_imports(const ElfImage& elf, const PrxParam& prx,
                          std::vector<ImportLib>& out) {
    if (!prx.present) return;
    for (uint32_t va = prx.libstub_start; va + 0x2c <= prx.libstub_end; ) {
        uint8_t  size      = elf.r8(va + 0x00);
        if (size == 0) break;
        uint16_t version   = elf.r16(va + 0x02);
        uint16_t attribute = elf.r16(va + 0x04);
        uint16_t num_func  = elf.r16(va + 0x06);
        uint16_t num_var   = elf.r16(va + 0x08);
        uint32_t name_addr = fixva(elf, elf.r32(va + 0x10));
        uint32_t fnid_tab  = fixva(elf, elf.r32(va + 0x14));
        uint32_t fstub_tab = fixva(elf, elf.r32(va + 0x18));
        uint32_t vnid_tab  = fixva(elf, elf.r32(va + 0x1c));
        uint32_t vstub_tab = fixva(elf, elf.r32(va + 0x20));

        ImportLib lib;
        lib.name      = name_addr ? elf.cstr(name_addr) : std::string();
        lib.version   = version;
        lib.attribute = attribute;
        for (uint16_t i = 0; i < num_func; ++i) {
            ImportFunc f;
            f.nid       = elf.r32(fnid_tab  + 4u * i);
            f.stub_addr = fixva(elf, elf.r32(fstub_tab + 4u * i));
            lib.funcs.push_back(f);
        }
        for (uint16_t i = 0; i < num_var; ++i) {
            lib.vars.emplace_back(elf.r32(vnid_tab + 4u * i),
                                  fixva(elf, elf.r32(vstub_tab + 4u * i)));
        }
        out.push_back(std::move(lib));
        va += size;
    }
}

static void parse_exports(const ElfImage& elf, const PrxParam& prx,
                          std::vector<ExportLib>& out) {
    if (!prx.present) return;
    for (uint32_t va = prx.libent_start; va + 0x1c <= prx.libent_end; ) {
        uint8_t  size      = elf.r8(va + 0x00);
        if (size == 0) break;
        uint16_t version   = elf.r16(va + 0x02);
        uint16_t attribute = elf.r16(va + 0x04);
        uint16_t num_func  = elf.r16(va + 0x06);
        uint16_t num_var   = elf.r16(va + 0x08);
        uint32_t name_addr = fixva(elf, elf.r32(va + 0x10));
        uint32_t nid_tab   = fixva(elf, elf.r32(va + 0x14));
        uint32_t stub_tab  = fixva(elf, elf.r32(va + 0x18));

        ExportLib lib;
        lib.name      = name_addr ? elf.cstr(name_addr) : std::string();
        lib.version   = version;
        lib.attribute = attribute;
        uint32_t total = (uint32_t)num_func + num_var;
        for (uint32_t i = 0; i < total; ++i) {
            uint32_t nid  = elf.r32(nid_tab  + 4u * i);
            uint32_t addr = fixva(elf, elf.r32(stub_tab + 4u * i));
            if (i < num_func) lib.funcs.emplace_back(nid, addr);
        }
        out.push_back(std::move(lib));
        va += size;
    }
}

static void discover_opd(const ElfImage& elf, PpuModule& m) {
    if (!m.module_toc) m.module_toc = elf.r32(elf.e_entry + 4);

    const uint32_t PF_X = 1;
    std::map<uint32_t,int> toc_count;
    for (const auto& s : elf.segments) {
        if (s.type != PT_LOAD || s.filesz == 0) continue;
        if (s.flags & PF_X) continue;
        for (uint64_t va = s.vaddr; va + 8 <= s.vaddr + s.filesz; va += 4) {
            uint32_t entry = elf.r32(va), toc = elf.r32(va + 4);
            if (entry < elf.code_lo || entry >= elf.code_hi) continue;
            if (entry & 3) continue;
            if (toc < elf.code_hi) continue;
            ++toc_count[toc];
        }
    }
    for (auto& kv : toc_count) if (kv.second >= 8) m.all_tocs.insert(kv.first);
    m.all_tocs.insert(m.module_toc);

    for (const auto& s : elf.segments) {
        if (s.type != PT_LOAD || s.filesz == 0) continue;
        if (s.flags & PF_X) continue;
        for (uint64_t va = s.vaddr; va + 8 <= s.vaddr + s.filesz; va += 4) {
            uint32_t entry = elf.r32(va), toc = elf.r32(va + 4);
            if (entry < elf.code_lo || entry >= elf.code_hi) continue;
            if (entry & 3) continue;
            if (!m.all_tocs.count(toc)) continue;
            m.opd.push_back(OpdEntry{ (uint32_t)va, entry, toc });
            m.func_seeds.emplace(entry, toc);
        }
    }
}

bool PpuModule::analyze(const ElfImage& elf, std::string& err) {
    parse_proc_param(elf, proc);
    parse_prx_param(elf, prx);
    if (!prx.present) parse_module_info(elf, prx, module_toc);
    if (prx.present && prx.magic != PRX_PARAM_MAGIC)
        fprintf(stderr, "warning: prx_param magic mismatch 0x%08x\n", prx.magic);
    if (proc.present && proc.magic != PROC_PARAM_MAGIC)
        fprintf(stderr, "warning: proc_param magic mismatch 0x%08x\n", proc.magic);
    parse_imports(elf, prx, imports);
    parse_exports(elf, prx, exports);
    discover_opd(elf, *this);

    for (const auto& lib : exports)
        for (const auto& f : lib.funcs) {
            uint32_t entry = fixva(elf, elf.r32(f.second));
            uint32_t toc   = fixva(elf, elf.r32(f.second + 4));
            if (entry >= elf.code_lo && entry < elf.code_hi && !(entry & 3))
                func_seeds.emplace(entry, toc);
        }
    (void)err;
    return true;
}
