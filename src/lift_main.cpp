#include "elf.hpp"
#include "ppu_lift.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>

int main(int argc, char** argv){
    if (argc < 5){ fprintf(stderr,"usage: %s <elf> <start_hex> <end_hex> <out.c>\n",argv[0]); return 2; }
    ElfImage elf; std::string err;
    uint32_t start = (uint32_t)strtoul(argv[2],nullptr,0);
    uint32_t end   = (uint32_t)strtoul(argv[3],nullptr,0);
    std::ifstream probe(argv[1], std::ios::binary); char mg[4]={0};
    if (probe) probe.read(mg,4);
    bool is_elf = (mg[0]==0x7f&&mg[1]=='E'&&mg[2]=='L'&&mg[3]=='F');
    bool ok = is_elf ? elf.load(argv[1],err) : elf.load_raw(argv[1],start,err);
    if (!ok){ fprintf(stderr,"load: %s\n",err.c_str()); return 1; }

    std::set<uint32_t> called;
    std::string fn = lift_function(elf, start, end, called);

    std::ofstream f(argv[4]);
    f << "#include \"ppu_runtime.h\"\n\n";
    for (uint32_t a : called)
        if (a != start) f << "void sub_" << std::hex << a << "(PPUContext*, uint8_t*);\n";
    f << "\n" << fn;
    fprintf(stderr, "lifted sub_%x  [%u bytes range]  calls=%zu\n", start, end-start, called.size());
    return 0;
}
