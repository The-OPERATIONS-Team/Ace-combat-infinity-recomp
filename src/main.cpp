#include "elf.hpp"
#include "ppu_module.hpp"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_map>

static std::unordered_map<uint32_t, std::string> g_nid_names;

static void load_nid_db() {
    const char* tries[] = { "data/nid_db.csv", "../data/nid_db.csv",
                            "recomp/data/nid_db.csv", "../recomp/data/nid_db.csv" };
    for (const char* path : tries) {
        std::ifstream f(path);
        if (!f) continue;
        std::string line;
        std::getline(f, line);
        while (std::getline(f, line)) {
            std::stringstream ss(line);
            std::string nid_s, lib, name;
            if (!std::getline(ss, nid_s, ',')) continue;
            std::getline(ss, lib, ',');
            std::getline(ss, name, ',');
            if (!name.empty() && name.back() == '\r') name.pop_back();
            uint32_t nid = (uint32_t)strtoul(nid_s.c_str(), nullptr, 0);
            g_nid_names.emplace(nid, name);
        }
        fprintf(stderr, "loaded %zu NIDs from %s\n", g_nid_names.size(), path);
        return;
    }
    fprintf(stderr, "warning: nid_db.csv not found; imports will be unnamed\n");
}

static const char* nid_name(uint32_t nid) {
    auto it = g_nid_names.find(nid);
    return it == g_nid_names.end() ? "?" : it->second.c_str();
}

static const char* seg_type_name(uint32_t t) {
    switch (t) {
        case PT_LOAD:           return "LOAD";
        case PT_TLS:            return "TLS";
        case PT_PROC_PARAM:     return "PROC_PARAM";
        case PT_PROC_PRX_PARAM: return "PRX_PARAM";
        default:                return "other";
    }
}

static void print_report(const ElfImage& elf, const PpuModule& m) {
    printf("== ELF ==\n");
    printf("  type=%u machine=%u entry=0x%llx\n", elf.e_type, elf.e_machine,
           (unsigned long long)elf.e_entry);
    printf("  code span: 0x%llx .. 0x%llx (%llu bytes)\n",
           (unsigned long long)elf.code_lo, (unsigned long long)elf.code_hi,
           (unsigned long long)(elf.code_hi - elf.code_lo));
    printf("  segments: %zu  sections: %zu\n", elf.segments.size(), elf.sections.size());
    for (const auto& s : elf.segments)
        printf("    %-10s off=0x%08llx vaddr=0x%08llx filesz=0x%08llx memsz=0x%08llx %c%c%c\n",
               seg_type_name(s.type), (unsigned long long)s.offset,
               (unsigned long long)s.vaddr, (unsigned long long)s.filesz,
               (unsigned long long)s.memsz,
               (s.flags & 4) ? 'r' : '-', (s.flags & 2) ? 'w' : '-',
               (s.flags & 1) ? 'x' : '-');

    printf("\n== proc_param ==\n");
    if (m.proc.present)
        printf("  magic=0x%08x sdk=0x%08x prio=%u stack=0x%x malloc_pg=0x%x\n",
               m.proc.magic, m.proc.sdk_version, m.proc.primary_prio,
               m.proc.primary_stacksize, m.proc.malloc_pagesize);
    else printf("  (none)\n");

    printf("\n== prx_param ==\n");
    if (m.prx.present)
        printf("  magic=0x%08x libent=[0x%x..0x%x] libstub=[0x%x..0x%x] module_toc=0x%08x\n",
               m.prx.magic, m.prx.libent_start, m.prx.libent_end,
               m.prx.libstub_start, m.prx.libstub_end, m.module_toc);
    else printf("  (none)\n");

    uint32_t total_imp = 0, named_imp = 0;
    printf("\n== imports (%zu libs) ==\n", m.imports.size());
    for (const auto& lib : m.imports) {
        uint32_t named = 0;
        for (const auto& fn : lib.funcs)
            if (g_nid_names.count(fn.nid)) ++named;
        printf("  %-20s v=%u attr=0x%x  funcs=%zu (named %u) vars=%zu\n",
               lib.name.c_str(), lib.version, lib.attribute,
               lib.funcs.size(), named, lib.vars.size());
        total_imp += (uint32_t)lib.funcs.size();
        named_imp += named;
    }
    printf("  total imported funcs: %u (named %u, %.1f%%)\n", total_imp, named_imp,
           total_imp ? 100.0 * named_imp / total_imp : 0.0);

    uint32_t total_exp = 0;
    printf("\n== exports (%zu libs) ==\n", m.exports.size());
    for (const auto& lib : m.exports) {
        printf("  %-20s v=%u attr=0x%x  funcs=%zu\n",
               lib.name.empty() ? "(module)" : lib.name.c_str(),
               lib.version, lib.attribute, lib.funcs.size());
        total_exp += (uint32_t)lib.funcs.size();
    }
    printf("  total exported funcs: %u\n", total_exp);

    printf("\n== OPD / function seeds ==\n");
    printf("  opd descriptors (toc-matched): %zu\n", m.opd.size());
    printf("  function seeds (unique entries): %zu\n", m.func_seeds.size());
}

static void emit_imports_csv(const PpuModule& m, const std::string& path) {
    std::ofstream f(path);
    f << "lib,nid,stub_addr,name\n";
    char line[192];
    for (const auto& lib : m.imports)
        for (const auto& fn : lib.funcs) {
            snprintf(line, sizeof line, "%s,0x%08x,0x%08x,%s\n",
                     lib.name.c_str(), fn.nid, fn.stub_addr, nid_name(fn.nid));
            f << line;
        }
}

static void emit_toml(const ElfImage& elf, const PpuModule& m,
                      const std::string& in_path, const std::string& path) {
    std::ofstream f(path);
    f << "# Auto-generated by ppu-analyze. Fill the TODO fields manually.\n";
    f << "[main]\n";
    f << "file_path = \"" << in_path << "\"\n";
    f << "out_directory_path = \"out/\"\n";
    f << "entry = 0x" << std::hex << elf.e_entry << "\n";
    f << "module_toc = 0x" << m.module_toc << std::dec << "\n\n";

    f << "[registers] # TODO: locate save/restore helpers by signature\n";
    f << "# restgprlr_14 = 0x...\n# savegprlr_14 = 0x...\n\n";

    f << "[optimizations]\n";
    f << "skip_lr = false\ncr_as_local = true\nxer_as_local = true\nctr_as_local = true\n\n";

    char line[64];
    f << "# function seeds discovered via OPD (" << m.func_seeds.size() << ")\n";
    f << "functions = [\n";
    for (const auto& [entry, toc] : m.func_seeds) {
        snprintf(line, sizeof line, "  { address = 0x%08x },\n", entry);
        f << line;
    }
    f << "]\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input.elf> [out_dir]\n", argv[0]);
        return 2;
    }
    std::string in = argv[1];
    std::string outdir = (argc >= 3) ? argv[2] : ".";

    load_nid_db();

    ElfImage elf;
    std::string err;
    if (!elf.load(in, err)) { fprintf(stderr, "load error: %s\n", err.c_str()); return 1; }

    PpuModule m;
    if (!m.analyze(elf, err)) { fprintf(stderr, "analyze error: %s\n", err.c_str()); return 1; }

    print_report(elf, m);
    emit_imports_csv(m, outdir + "/imports.csv");
    emit_toml(elf, m, in, outdir + "/config.toml");
    printf("\nwrote %s/imports.csv and %s/config.toml\n", outdir.c_str(), outdir.c_str());
    return 0;
}
