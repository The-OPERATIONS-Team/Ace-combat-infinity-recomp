#pragma once
#include "elf.hpp"
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct ProcParam {
    bool     present = false;
    uint32_t size = 0, magic = 0, version = 0, sdk_version = 0;
    uint32_t primary_prio = 0, primary_stacksize = 0, malloc_pagesize = 0;
};

struct PrxParam {
    bool     present = false;
    uint32_t size = 0, magic = 0, version = 0;
    uint32_t libent_start = 0, libent_end = 0;
    uint32_t libstub_start = 0, libstub_end = 0;
};

struct ImportFunc {
    uint32_t nid = 0;
    uint32_t stub_addr = 0;
};

struct ImportLib {
    std::string name;
    uint16_t    version = 0, attribute = 0;
    std::vector<ImportFunc> funcs;
    std::vector<std::pair<uint32_t,uint32_t>> vars;
};

struct ExportLib {
    std::string name;
    uint16_t    version = 0, attribute = 0;
    std::vector<std::pair<uint32_t,uint32_t>> funcs;
};

struct OpdEntry {
    uint32_t opd_addr = 0;
    uint32_t entry    = 0;
    uint32_t toc      = 0;
};

struct PpuModule {
    ProcParam proc;
    PrxParam  prx;
    uint32_t  module_toc = 0;
    std::vector<ImportLib> imports;
    std::vector<ExportLib> exports;
    std::vector<OpdEntry>  opd;
    std::map<uint32_t,uint32_t> func_seeds;
    std::set<uint32_t> all_tocs;

    bool analyze(const ElfImage& elf, std::string& err);
};
