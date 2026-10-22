#include "spu_lift.hpp"
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>

static uint32_t be32(const uint8_t* p){ return (uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3]; }
static uint16_t be16(const uint8_t* p){ return (uint16_t)(p[0]<<8|p[1]); }

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s <image.elf> <out.c> [funcname] [--raw 0xBASE 0xENTRY]\n"
                       "  --raw: input is a headerless LS blob loaded at BASE (e.g. a SPURS\n"
                       "         policy module DMA'd to 0xa00), not an SPU ELF.\n",argv[0]); return 2; }
    const char* fname = (argc>3 && argv[3][0]!='-') ? argv[3] : "spu_run";
    uint32_t raw_base=0, raw_entry=0; bool raw=false;
    for(int i=3;i<argc;i++)
        if(!strcmp(argv[i],"--raw") && i+2<argc){ raw=true;
            raw_base=(uint32_t)strtoul(argv[i+1],0,0); raw_entry=(uint32_t)strtoul(argv[i+2],0,0); }
    FILE* f=fopen(argv[1],"rb"); if(!f){ perror("open"); return 1; }
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<uint8_t> buf(n); if(fread(buf.data(),1,n,f)!=(size_t)n){return 1;} fclose(f);
    const uint8_t* b=buf.data();
    if(raw){
        std::string c=spu_lift_image(b, raw_base, (uint32_t)n, raw_entry, fname);
        FILE* o=fopen(argv[2],"wb"); if(!o){ perror("out"); return 1; }
        fwrite(c.data(),1,c.size(),o); fclose(o);
        fprintf(stderr,"lifted raw %ld bytes @0x%x (entry 0x%x) -> %s\n",n,raw_base,raw_entry,argv[2]);
        return 0;
    }
    if(!(b[0]==0x7f&&b[1]=='E'&&b[2]=='L'&&b[3]=='F'&&b[4]==1&&b[5]==2)){ fprintf(stderr,"not ELF32-BE\n"); return 1; }
    uint32_t entry=be32(b+24), phoff=be32(b+28);
    uint16_t phentsize=be16(b+42), phnum=be16(b+44);
    uint32_t base=0,off=0,sz=0; bool found=false;
    for(int i=0;i<phnum;i++){
        const uint8_t* ph=b+phoff+i*phentsize;
        uint32_t type=be32(ph), p_off=be32(ph+4), p_va=be32(ph+8), p_fsz=be32(ph+16), p_flags=be32(ph+24);
        if(type==1 && (p_flags&1)){ base=p_va; off=p_off; sz=p_fsz; found=true; break; }
    }
    if(!found){ fprintf(stderr,"no executable LOAD segment\n"); return 1; }
    std::string c=spu_lift_image(b+off, base, sz, entry, fname);
    FILE* o=fopen(argv[2],"wb"); if(!o){ perror("out"); return 1; }
    fwrite(c.data(),1,c.size(),o); fclose(o);
    fprintf(stderr,"lifted %u bytes of SPU code @0x%x (entry 0x%x) -> %s (%zu bytes C)\n",
            sz,base,entry,argv[2],c.size());
    return 0;
}
