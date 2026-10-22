#include "spu_runtime.h"
#include <stdio.h>
#include <math.h>

static inline uint32_t ib32(const uint8_t* p){
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static inline int32_t sxt(uint32_t v, int bits){
    uint32_t m = 1u << (bits-1); return (int32_t)((v ^ m) - m);
}
#define getd  spu_getd64
#define setd  spu_setd64
#define getdf spu_getdf
#define setdf spu_setdf
static inline void set_pref(SpuReg* r, uint32_t v){
    r->w[0]=v; r->w[1]=r->w[2]=r->w[3]=0;
}

static void gen_controls(SpuReg* rt, uint32_t ea, int sz){
    uint8_t t[16];
    for (int k=0;k<16;k++) t[k]=(uint8_t)(0x10+k);
    uint32_t p = ea & 0xf; p &= ~(uint32_t)(sz-1);
    int first = sz<=4 ? 4-sz : 0;
    for (int j=0;j<sz;j++) t[p+j]=(uint8_t)(first+j);
    spu_set_bytes(rt, t);
}

static int interp_body_hit(uint32_t pc, const uint8_t* ls){
    if (spu_reloc_hit(pc, ls)) return 1;
    for (unsigned i=0;i<g_spu_nbodies;i++)
        if (spu_body_accept(i, pc, ls)) return 1;
    return 0;
}

void spu_interp(SPUContext* c){
    uint8_t* ls = c->ls;
    uint32_t pc = c->pc & 0x3fffc;
    uint32_t nohit[64]; memset(nohit, 0xff, sizeof nohit);
    {
        static volatile long n_enter; static uint32_t seen[64]; static int ns;
        int f=0; for (int k=0;k<ns;k++) if (seen[k]==pc){ f=1; break; }
        if (!f && ns<64){ seen[ns++]=pc;
            fprintf(stderr,"[SPU-INTERP] enter pc=0x%x ls[pc]=%02x%02x%02x%02x\n",
                    pc, ls[pc],ls[pc+1],ls[pc+2],ls[pc+3]); }
        (void)n_enter;
    }
    for(;;){
        uint32_t op   = ib32(ls + pc);
        uint32_t next = (pc + 4) & 0x3fffc;
        uint32_t op11 = op >> 21;
        uint32_t rt = op & 0x7f, ra = (op>>7)&0x7f, rb = (op>>14)&0x7f;
        SpuReg *T=&c->r[rt], *A=&c->r[ra], *B=&c->r[rb];
        int32_t i7  = sxt((op>>14)&0x7f, 7);
        int32_t i10 = sxt((op>>14)&0x3ff, 10);
        int32_t i16 = sxt((op>>7)&0xffff, 16);
        c->pc = pc;

        {
            static uint32_t tlo, thi; static long tmax; static int ton=-1;
            static FILE* tf; static long tn; static SPUContext* tctx;
            if (ton<0){ const char* e=getenv("PS3_SPUTRACE");
                ton = (e && sscanf(e,"%x:%x:%ld",&tlo,&thi,&tmax)==3) ? 1 : 0; }
            if (ton==1 && pc>=tlo && pc<thi && tn<tmax &&
                ib32(ls+0x4c00)==0x4350ae02u){
                if (!tctx) tctx=c;
                if (c==tctx){
                    if (!tf) tf=fopen("logs/sputrace.bin","wb");
                    if (tf){
                        struct { uint32_t pc,op,t[4],a[4],b[4]; } rec;
                        rec.pc=pc; rec.op=op;
                        memcpy(rec.t,c->r[op&0x7f].w,16);
                        memcpy(rec.a,c->r[(op>>7)&0x7f].w,16);
                        memcpy(rec.b,c->r[(op>>14)&0x7f].w,16);
                        fwrite(&rec,1,sizeof rec,tf);
                        if (++tn==tmax){ fflush(tf);
                            fprintf(stderr,"[SPUTRACE] %ld records done\n",tmax); }
                    }
                }
            }
        }

        #define TAKE(target) do{ uint32_t _t=(target)&0x3fffc; \
            if (nohit[(_t>>2)&63]!=_t){ \
                if (interp_body_hit(_t, ls)){ c->pc=_t; return; } \
                nohit[(_t>>2)&63]=_t; } \
            pc=_t; goto next_insn; }while(0)

        switch (op >> 28){
        case 0x8: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            for(int i=0;i<4;i++) Tr->w[i]=(Cr->w[i]&B->w[i])|(~Cr->w[i]&A->w[i]);
            pc=next; goto next_insn; }
        case 0xb: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            uint8_t a[16],b[16],cc[16],t[16];
            spu_get_bytes(A,a); spu_get_bytes(B,b); spu_get_bytes(Cr,cc);
            for(int k=0;k<16;k++){ uint8_t s=cc[k];
                if((s&0xc0)==0x80) t[k]=0; else if((s&0xe0)==0xc0) t[k]=0xff;
                else if((s&0xe0)==0xe0) t[k]=0x80; else t[k]=(s&0x10)?b[s&0xf]:a[s&0xf]; }
            spu_set_bytes(Tr,t); pc=next; goto next_insn; }
        case 0xc: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            for(int i=0;i<4;i++) Tr->w[i]=(uint32_t)((int32_t)(int16_t)A->w[i]*(int32_t)(int16_t)B->w[i])+Cr->w[i];
            pc=next; goto next_insn; }
        case 0xd: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            for(int i=0;i<4;i++) Tr->fp[i]=Cr->fp[i]-A->fp[i]*B->fp[i];
            pc=next; goto next_insn; }
        case 0xe: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            for(int i=0;i<4;i++) Tr->fp[i]=A->fp[i]*B->fp[i]+Cr->fp[i];
            pc=next; goto next_insn; }
        case 0xf: { SpuReg* Cr=&c->r[op&0x7f]; SpuReg* Tr=&c->r[(op>>21)&0x7f];
            for(int i=0;i<4;i++) Tr->fp[i]=A->fp[i]*B->fp[i]-Cr->fp[i];
            pc=next; goto next_insn; }
        default: break;
        }

        switch (op >> 25){
        case 0x21: for(int i=0;i<4;i++) T->w[i]=(op>>7)&0x3ffff; pc=next; goto next_insn;
        case 0x08: case 0x09: pc=next; goto next_insn;
        default: break;
        }

        switch (op >> 24){
        case 0x04: for(int i=0;i<4;i++) T->w[i]=A->w[i]|(uint32_t)i10; pc=next; goto next_insn;
        case 0x05: for(int i=0;i<8;i++) T->h[i]=A->h[i]|(uint16_t)i10; pc=next; goto next_insn;
        case 0x06: for(int i=0;i<16;i++) T->b[i]=A->b[i]|(uint8_t)i10; pc=next; goto next_insn;
        case 0x0c: for(int i=0;i<4;i++) T->w[i]=(uint32_t)i10-A->w[i]; pc=next; goto next_insn;
        case 0x0d: for(int i=0;i<8;i++) T->h[i]=(uint16_t)i10-A->h[i]; pc=next; goto next_insn;
        case 0x14: for(int i=0;i<4;i++) T->w[i]=A->w[i]&(uint32_t)i10; pc=next; goto next_insn;
        case 0x15: for(int i=0;i<8;i++) T->h[i]=A->h[i]&(uint16_t)i10; pc=next; goto next_insn;
        case 0x16: for(int i=0;i<16;i++) T->b[i]=A->b[i]&(uint8_t)i10; pc=next; goto next_insn;
        case 0x1c: for(int i=0;i<4;i++) T->w[i]=A->w[i]+(uint32_t)i10; pc=next; goto next_insn;
        case 0x1d: for(int i=0;i<8;i++) T->h[i]=A->h[i]+(uint16_t)i10; pc=next; goto next_insn;
        case 0x24: { SpuReg v=*T; spu_stq(c,(A->w[0]+((uint32_t)i10<<4)),&v); pc=next; goto next_insn; }
        case 0x34: spu_lq(c,(A->w[0]+((uint32_t)i10<<4)),T); pc=next; goto next_insn;
        case 0x44: for(int i=0;i<4;i++) T->w[i]=A->w[i]^(uint32_t)i10; pc=next; goto next_insn;
        case 0x45: for(int i=0;i<8;i++) T->h[i]=A->h[i]^(uint16_t)i10; pc=next; goto next_insn;
        case 0x46: for(int i=0;i<16;i++) T->b[i]=A->b[i]^(uint8_t)i10; pc=next; goto next_insn;
        case 0x4c: for(int i=0;i<4;i++) T->w[i]=((int32_t)A->w[i]>i10)?~0u:0u; pc=next; goto next_insn;
        case 0x4d: for(int i=0;i<8;i++) T->h[i]=((int16_t)A->h[i]>(int16_t)i10)?0xffff:0; pc=next; goto next_insn;
        case 0x4e: for(int i=0;i<16;i++) T->b[i]=((int8_t)A->b[i]>(int8_t)i10)?0xff:0; pc=next; goto next_insn;
        case 0x4f: pc=next; goto next_insn;
        case 0x5c: for(int i=0;i<4;i++) T->w[i]=(A->w[i]>(uint32_t)i10)?~0u:0u; pc=next; goto next_insn;
        case 0x5d: for(int i=0;i<8;i++) T->h[i]=(A->h[i]>(uint16_t)i10)?0xffff:0; pc=next; goto next_insn;
        case 0x5e: for(int i=0;i<16;i++) T->b[i]=(A->b[i]>(uint8_t)i10)?0xff:0; pc=next; goto next_insn;
        case 0x5f: pc=next; goto next_insn;
        case 0x74: for(int i=0;i<4;i++) T->w[i]=(uint32_t)((int32_t)(int16_t)A->w[i]*i10); pc=next; goto next_insn;
        case 0x75: for(int i=0;i<4;i++) T->w[i]=(uint32_t)((A->w[i]&0xffff)*((uint32_t)i10&0xffff)); pc=next; goto next_insn;
        case 0x7c: for(int i=0;i<4;i++) T->w[i]=(A->w[i]==(uint32_t)i10)?~0u:0u; pc=next; goto next_insn;
        case 0x7d: for(int i=0;i<8;i++) T->h[i]=(A->h[i]==(uint16_t)i10)?0xffff:0; pc=next; goto next_insn;
        case 0x7e: for(int i=0;i<16;i++) T->b[i]=(A->b[i]==(uint8_t)i10)?0xff:0; pc=next; goto next_insn;
        case 0x7f: pc=next; goto next_insn;
        default: break;
        }

        switch (op >> 23){
        case 0x40: if (T->w[0]==0) TAKE(pc+((uint32_t)i16<<2)); pc=next; goto next_insn;
        case 0x41: { SpuReg v=*T; spu_stq(c,((uint32_t)i16<<2),&v); pc=next; goto next_insn; }
        case 0x42: if (T->w[0]!=0) TAKE(pc+((uint32_t)i16<<2)); pc=next; goto next_insn;
        case 0x44: if ((T->w[0]&0xffff)==0) TAKE(pc+((uint32_t)i16<<2)); pc=next; goto next_insn;
        case 0x46: if ((T->w[0]&0xffff)!=0) TAKE(pc+((uint32_t)i16<<2)); pc=next; goto next_insn;
        case 0x47: { SpuReg v=*T; spu_stq(c,(pc+((uint32_t)i16<<2)),&v); pc=next; goto next_insn; }
        case 0x60: TAKE((uint32_t)i16<<2);
        case 0x61: spu_lq(c,((uint32_t)i16<<2),T); pc=next; goto next_insn;
        case 0x62: set_pref(T,next); TAKE((uint32_t)i16<<2);
        case 0x64: TAKE(pc+((uint32_t)i16<<2));
        case 0x65: { uint8_t t[16]; uint32_t m=(op>>7)&0xffff;
            for(int k=0;k<16;k++) t[k]=((m>>(15-k))&1)?0xff:0x00;
            spu_set_bytes(T,t); pc=next; goto next_insn; }
        case 0x66: set_pref(T,next); TAKE(pc+((uint32_t)i16<<2));
        case 0x67: spu_lq(c,(pc+((uint32_t)i16<<2)),T); pc=next; goto next_insn;
        case 0x6b: pc=next; goto next_insn;
        case 0x81: for(int i=0;i<4;i++) T->w[i]=(uint32_t)i16; pc=next; goto next_insn;
        case 0x82: for(int i=0;i<4;i++) T->w[i]=(uint32_t)((op>>7)&0xffff)<<16; pc=next; goto next_insn;
        case 0x83: for(int i=0;i<8;i++) T->h[i]=(uint16_t)((op>>7)&0xffff); pc=next; goto next_insn;
        case 0xc1: for(int i=0;i<4;i++) T->w[i]|=(uint32_t)((op>>7)&0xffff); pc=next; goto next_insn;
        default: break;
        }

        switch (op >> 22){
        case 0x1d8: { int s=173-(int)((op>>14)&0xff);
            for(int i=0;i<4;i++){ double v=ldexp((double)A->fp[i],s);
                if (v>2147483647.0) v=2147483647.0; if (v<-2147483648.0) v=-2147483648.0;
                T->w[i]=(uint32_t)(int32_t)v; }
            pc=next; goto next_insn; }
        case 0x1d9: { int s=173-(int)((op>>14)&0xff);
            for(int i=0;i<4;i++){ double v=ldexp((double)A->fp[i],s);
                if (v>4294967295.0) v=4294967295.0; if (v<0) v=0;
                T->w[i]=(uint32_t)v; }
            pc=next; goto next_insn; }
        case 0x1da: { int s=(int)((op>>14)&0xff)-155;
            for(int i=0;i<4;i++) T->fp[i]=ldexpf((float)(int32_t)A->w[i],s);
            pc=next; goto next_insn; }
        case 0x1db: { int s=(int)((op>>14)&0xff)-155;
            for(int i=0;i<4;i++) T->fp[i]=ldexpf((float)A->w[i],s);
            pc=next; goto next_insn; }
        default: break;
        }

        switch (op11){
        case 0x000: c->pc=pc; spu_stop(c, op & 0x3fff); return;
        case 0x140: c->pc=pc; spu_stop(c, op & 0x3fff); return;
        case 0x001: case 0x201: pc=next; goto next_insn;
        case 0x002: case 0x003: pc=next; goto next_insn;
        case 0x00c: set_pref(T, ra==0 ? c->srr0 : 0); pc=next; goto next_insn;
        case 0x10c: if (ra==0) c->srr0=T->w[0]; pc=next; goto next_insn;
        case 0x00d: set_pref(T, spu_rdch(c, ra)); pc=next; goto next_insn;
        case 0x00f: set_pref(T, spu_rchcnt(c, ra)); pc=next; goto next_insn;
        case 0x10d: spu_wrch(c, ra, T->w[0]);
                    if (ra == 21) memset(nohit, 0xff, sizeof nohit);
                    pc=next; goto next_insn;

        case 0x040: for(int i=0;i<4;i++) T->w[i]=B->w[i]-A->w[i]; break;
        case 0x041: for(int i=0;i<4;i++) T->w[i]=A->w[i]|B->w[i]; break;
        case 0x042: for(int i=0;i<4;i++) T->w[i]=(B->w[i]>=A->w[i])?1u:0u; break;
        case 0x048: for(int i=0;i<8;i++) T->h[i]=B->h[i]-A->h[i]; break;
        case 0x049: for(int i=0;i<4;i++) T->w[i]=~(A->w[i]|B->w[i]); break;
        case 0x053: for(int i=0;i<16;i++) T->b[i]=(uint8_t)(A->b[i]>B->b[i]?A->b[i]-B->b[i]:B->b[i]-A->b[i]); break;
        case 0x0c0: for(int i=0;i<4;i++) T->w[i]=A->w[i]+B->w[i]; break;
        case 0x0c1: for(int i=0;i<4;i++) T->w[i]=A->w[i]&B->w[i]; break;
        case 0x0c2: for(int i=0;i<4;i++) T->w[i]=((A->w[i]+B->w[i])<A->w[i])?1u:0u; break;
        case 0x0c8: for(int i=0;i<8;i++) T->h[i]=A->h[i]+B->h[i]; break;
        case 0x0c9: for(int i=0;i<4;i++) T->w[i]=~(A->w[i]&B->w[i]); break;
        case 0x0d3: for(int i=0;i<16;i++) T->b[i]=(uint8_t)((A->b[i]+B->b[i]+1)>>1); break;
        case 0x340: for(int i=0;i<4;i++) T->w[i]=A->w[i]+B->w[i]+(T->w[i]&1); break;
        case 0x341: for(int i=0;i<4;i++) T->w[i]=B->w[i]-A->w[i]-1+(T->w[i]&1); break;
        case 0x342: for(int i=0;i<4;i++){ uint64_t s=(uint64_t)A->w[i]+B->w[i]+(T->w[i]&1); T->w[i]=(uint32_t)(s>>32); } break;
        case 0x343: for(int i=0;i<4;i++){ uint64_t s=(uint64_t)B->w[i]+(uint32_t)~A->w[i]+(T->w[i]&1); T->w[i]=(uint32_t)(s>>32); } break;

        case 0x3c4: for(int i=0;i<4;i++) T->w[i]=(uint32_t)((int32_t)(int16_t)A->w[i]*(int32_t)(int16_t)B->w[i]); break;
        case 0x3cc: for(int i=0;i<4;i++) T->w[i]=(A->w[i]&0xffff)*(B->w[i]&0xffff); break;
        case 0x3c5: for(int i=0;i<4;i++) T->w[i]=(uint32_t)(((int32_t)(int16_t)(A->w[i]>>16))*(int32_t)(int16_t)B->w[i])<<16; break;
        case 0x3c6: for(int i=0;i<4;i++) T->w[i]=(uint32_t)(((int32_t)(int16_t)(A->w[i]>>16))*(int32_t)(int16_t)(B->w[i]>>16)); break;
        case 0x3ce: for(int i=0;i<4;i++) T->w[i]=(A->w[i]>>16)*(B->w[i]>>16); break;
        case 0x346: for(int i=0;i<4;i++) T->w[i]+=(uint32_t)(((int32_t)(int16_t)(A->w[i]>>16))*(int32_t)(int16_t)(B->w[i]>>16)); break;
        case 0x34e: for(int i=0;i<4;i++) T->w[i]+=(A->w[i]>>16)*(B->w[i]>>16); break;
        case 0x3c7: for(int i=0;i<4;i++) T->w[i]=(uint32_t)(((int32_t)(int16_t)A->w[i]*(int32_t)(int16_t)B->w[i])>>16); break;

        case 0x3c0: for(int i=0;i<4;i++) T->w[i]=(A->w[i]==B->w[i])?~0u:0u; break;
        case 0x3c8: for(int i=0;i<8;i++) T->h[i]=(A->h[i]==B->h[i])?0xffff:0; break;
        case 0x3d0: for(int i=0;i<16;i++) T->b[i]=(A->b[i]==B->b[i])?0xff:0; break;
        case 0x240: for(int i=0;i<4;i++) T->w[i]=((int32_t)A->w[i]>(int32_t)B->w[i])?~0u:0u; break;
        case 0x248: for(int i=0;i<8;i++) T->h[i]=((int16_t)A->h[i]>(int16_t)B->h[i])?0xffff:0; break;
        case 0x250: for(int i=0;i<16;i++) T->b[i]=((int8_t)A->b[i]>(int8_t)B->b[i])?0xff:0; break;
        case 0x2c0: for(int i=0;i<4;i++) T->w[i]=(A->w[i]>B->w[i])?~0u:0u; break;
        case 0x2c8: for(int i=0;i<8;i++) T->h[i]=(A->h[i]>B->h[i])?0xffff:0; break;
        case 0x2d0: for(int i=0;i<16;i++) T->b[i]=(A->b[i]>B->b[i])?0xff:0; break;

        case 0x241: for(int i=0;i<4;i++) T->w[i]=A->w[i]^B->w[i]; break;
        case 0x249: for(int i=0;i<4;i++) T->w[i]=~(A->w[i]^B->w[i]); break;
        case 0x2c1: for(int i=0;i<4;i++) T->w[i]=A->w[i]&~B->w[i]; break;
        case 0x2c9: for(int i=0;i<4;i++) T->w[i]=A->w[i]|~B->w[i]; break;

        case 0x258: case 0x2d8: case 0x3d8: break;

        case 0x058: for(int i=0;i<4;i++){ uint32_t s=B->w[i]&31; T->w[i]=(A->w[i]<<s)|(s?(A->w[i]>>(32-s)):0);} break;
        case 0x078: { uint32_t s=(uint32_t)i7&31; for(int i=0;i<4;i++) T->w[i]=(A->w[i]<<s)|(s?(A->w[i]>>(32-s)):0);} break;
        case 0x059: for(int i=0;i<4;i++){ uint32_t s=(0u-B->w[i])&0x3f; T->w[i]=(s<32)?(A->w[i]>>s):0u; } break;
        case 0x079: { uint32_t s=(0u-(uint32_t)i7)&0x3f; for(int i=0;i<4;i++) T->w[i]=(s<32)?(A->w[i]>>s):0u; } break;
        case 0x05a: for(int i=0;i<4;i++){ uint32_t s=(0u-B->w[i])&0x3f; T->w[i]=(uint32_t)((s<32)?((int32_t)A->w[i]>>s):((int32_t)A->w[i]>>31)); } break;
        case 0x07a: { uint32_t s=(0u-(uint32_t)i7)&0x3f; for(int i=0;i<4;i++) T->w[i]=(uint32_t)((s<32)?((int32_t)A->w[i]>>s):((int32_t)A->w[i]>>31)); } break;
        case 0x05b: for(int i=0;i<4;i++){ uint32_t s=B->w[i]&0x3f; T->w[i]=(s<32)?(A->w[i]<<s):0u; } break;
        case 0x07b: { uint32_t s=(uint32_t)i7&0x3f; for(int i=0;i<4;i++) T->w[i]=(s<32)?(A->w[i]<<s):0u; } break;
        case 0x05c: for(int i=0;i<8;i++){ uint32_t s=B->h[i]&15; T->h[i]=(uint16_t)((A->h[i]<<s)|(s?(A->h[i]>>(16-s)):0)); } break;
        case 0x07c: { uint32_t s=(uint32_t)i7&15; for(int i=0;i<8;i++) T->h[i]=(uint16_t)((A->h[i]<<s)|(s?(A->h[i]>>(16-s)):0)); } break;
        case 0x05d: for(int i=0;i<8;i++){ uint32_t s=(0u-B->h[i])&0x1f; T->h[i]=(uint16_t)((s<16)?(A->h[i]>>s):0); } break;
        case 0x07d: { uint32_t s=(0u-(uint32_t)i7)&0x1f; for(int i=0;i<8;i++) T->h[i]=(uint16_t)((s<16)?(A->h[i]>>s):0); } break;
        case 0x05e: for(int i=0;i<8;i++){ uint32_t s=(0u-B->h[i])&0x1f; T->h[i]=(uint16_t)((s<16)?((int16_t)A->h[i]>>s):((int16_t)A->h[i]>>15)); } break;
        case 0x07e: { uint32_t s=(0u-(uint32_t)i7)&0x1f; for(int i=0;i<8;i++) T->h[i]=(uint16_t)((s<16)?((int16_t)A->h[i]>>s):((int16_t)A->h[i]>>15)); } break;
        case 0x05f: for(int i=0;i<8;i++){ uint32_t s=B->h[i]&0x1f; T->h[i]=(uint16_t)((s<16)?(A->h[i]<<s):0); } break;
        case 0x07f: { uint32_t s=(uint32_t)i7&0x1f; for(int i=0;i<8;i++) T->h[i]=(uint16_t)((s<16)?(A->h[i]<<s):0); } break;

        #define QOP(cnt, body) { uint8_t a[16],t[16]; spu_get_bytes(A,a); int n=(int)(cnt); body; spu_set_bytes(T,t); } break
        case 0x1dc: QOP(B->w[0]&0xf,   for(int k=0;k<16;k++) t[k]=a[(k+n)&0xf]);
        case 0x1fc: QOP(i7&0xf,        for(int k=0;k<16;k++) t[k]=a[(k+n)&0xf]);
        case 0x1dd: QOP((0-(int)B->w[0])&0x1f, for(int k=0;k<16;k++) t[k]=(k-n>=0&&k-n<16)?a[k-n]:0);
        case 0x1fd: QOP((0-i7)&0x1f,   for(int k=0;k<16;k++) t[k]=(k-n>=0&&k-n<16)?a[k-n]:0);
        case 0x1df: QOP(B->w[0]&0x1f,  for(int k=0;k<16;k++) t[k]=(k+n<16)?a[k+n]:0);
        case 0x1ff: QOP(i7&0x1f,       for(int k=0;k<16;k++) t[k]=(k+n<16)?a[k+n]:0);
        case 0x1cc: QOP((B->w[0]>>3)&0xf,        for(int k=0;k<16;k++) t[k]=a[(k+n)&0xf]);
        case 0x1cd: QOP((0-(int)(B->w[0]>>3))&0x1f, for(int k=0;k<16;k++) t[k]=(k-n>=0&&k-n<16)?a[k-n]:0);
        case 0x1cf: QOP((B->w[0]>>3)&0x1f,       for(int k=0;k<16;k++) t[k]=(k+n<16)?a[k+n]:0);
        case 0x1d8: QOP(B->w[0]&7, if(n){ uint8_t f=a[0]>>(8-n); for(int k=0;k<16;k++){ int nx=(k+1)&0xf; t[k]=(uint8_t)((a[k]<<n)|(a[nx]>>(8-n))); } t[15]=(uint8_t)((a[15]<<n)|f); } else memcpy(t,a,16));
        case 0x1f8: QOP(i7&7,      if(n){ uint8_t f=a[0]>>(8-n); for(int k=0;k<16;k++){ int nx=(k+1)&0xf; t[k]=(uint8_t)((a[k]<<n)|(a[nx]>>(8-n))); } t[15]=(uint8_t)((a[15]<<n)|f); } else memcpy(t,a,16));
        case 0x1d9: QOP((0-(int)B->w[0])&7, { uint8_t carry=0; for(int k=0;k<16;k++){ uint8_t v=a[k]; t[k]=(uint8_t)(n?((v>>n)|carry):v); carry=(uint8_t)(n?(v<<(8-n)):0); } });
        case 0x1f9: QOP((0-i7)&7,           { uint8_t carry=0; for(int k=0;k<16;k++){ uint8_t v=a[k]; t[k]=(uint8_t)(n?((v>>n)|carry):v); carry=(uint8_t)(n?(v<<(8-n)):0); } });
        case 0x1db: QOP(B->w[0]&7, { uint8_t carry=0; for(int k=15;k>=0;k--){ uint16_t v=(uint16_t)((uint16_t)a[k]<<n); t[k]=(uint8_t)(v|carry); carry=(uint8_t)(v>>8); } });
        case 0x1fb: QOP(i7&7,      { uint8_t carry=0; for(int k=15;k>=0;k--){ uint16_t v=(uint16_t)((uint16_t)a[k]<<n); t[k]=(uint8_t)(v|carry); carry=(uint8_t)(v>>8); } });
        #undef QOP

        case 0x2b6: for(int i=0;i<8;i++) T->h[i]=(uint16_t)(int16_t)(int8_t)A->h[i]; break;
        case 0x2ae: for(int i=0;i<4;i++) T->w[i]=(uint32_t)(int32_t)(int16_t)A->w[i]; break;
        case 0x2a6: { int64_t v0=(int64_t)(int32_t)A->w[1], v1=(int64_t)(int32_t)A->w[3];
            T->w[0]=(uint32_t)((uint64_t)v0>>32); T->w[1]=(uint32_t)v0;
            T->w[2]=(uint32_t)((uint64_t)v1>>32); T->w[3]=(uint32_t)v1; } break;
        case 0x2a5: for(int i=0;i<4;i++) T->w[i]=A->w[i]?(uint32_t)__builtin_clz(A->w[i]):32u; break;
        case 0x2b4: for(int i=0;i<16;i++) T->b[i]=(uint8_t)__builtin_popcount(A->b[i]); break;
        case 0x253: for(int i=0;i<4;i++){ uint32_t a=A->w[i],b=B->w[i];
            uint32_t sa=(a&0xff)+((a>>8)&0xff)+((a>>16)&0xff)+(a>>24);
            uint32_t sb=(b&0xff)+((b>>8)&0xff)+((b>>16)&0xff)+(b>>24);
            T->w[i]=(sb<<16)|(sa&0xffff); } break;

        case 0x1f0: { uint32_t v=A->w[0]|A->w[1]|A->w[2]|A->w[3]; set_pref(T,v); } break;
        case 0x1b0: { uint32_t mm=0; for(int i=0;i<4;i++) mm|=(A->w[i]&1u)<<(3-i); set_pref(T,mm); } break;
        case 0x1b1: { uint32_t mm=0; for(int i=0;i<4;i++){ mm|=((A->w[i]>>16)&1u)<<(7-2*i); mm|=(A->w[i]&1u)<<(6-2*i); } set_pref(T,mm); } break;
        case 0x1b2: { uint8_t a[16]; uint32_t mm=0; spu_get_bytes(A,a); for(int k=0;k<16;k++) mm|=(uint32_t)(a[k]&1u)<<(15-k); set_pref(T,mm); } break;
        case 0x1b4: { uint32_t mm=A->w[0]; for(int i=0;i<4;i++) T->w[i]=((mm>>(3-i))&1)?~0u:0u; } break;
        case 0x1b5: { uint32_t mm=A->w[0]; for(int i=0;i<4;i++) T->w[i]=(((mm>>(7-2*i))&1)?0xffff0000u:0u)|(((mm>>(6-2*i))&1)?0xffffu:0u); } break;
        case 0x1b6: { uint32_t mm=A->w[0]; uint8_t t[16]; for(int k=0;k<16;k++) t[k]=((mm>>(15-k))&1)?0xff:0; spu_set_bytes(T,t); } break;

        case 0x1f4: gen_controls(T, A->w[0]+(uint32_t)i7, 1); break;
        case 0x1f5: gen_controls(T, A->w[0]+(uint32_t)i7, 2); break;
        case 0x1f6: gen_controls(T, A->w[0]+(uint32_t)i7, 4); break;
        case 0x1f7: gen_controls(T, A->w[0]+(uint32_t)i7, 8); break;
        case 0x1d4: gen_controls(T, A->w[0]+B->w[0], 1); break;
        case 0x1d5: gen_controls(T, A->w[0]+B->w[0], 2); break;
        case 0x1d6: gen_controls(T, A->w[0]+B->w[0], 4); break;
        case 0x1d7: gen_controls(T, A->w[0]+B->w[0], 8); break;

        case 0x1c4: spu_lq(c, A->w[0]+B->w[0], T); break;
        case 0x144: { SpuReg v=*T; spu_stq(c, A->w[0]+B->w[0], &v); } break;

        case 0x2c4: for(int i=0;i<4;i++) T->fp[i]=A->fp[i]+B->fp[i]; break;
        case 0x2c5: for(int i=0;i<4;i++) T->fp[i]=A->fp[i]-B->fp[i]; break;
        case 0x2c6: for(int i=0;i<4;i++) T->fp[i]=A->fp[i]*B->fp[i]; break;
        case 0x1b8: for(int i=0;i<4;i++) T->fp[i]=1.0f/A->fp[i]; break;
        case 0x1b9: for(int i=0;i<4;i++){ float v=A->fp[i]; T->fp[i]=1.0f/sqrtf(v<0?-v:v); } break;
        case 0x3d4: for(int i=0;i<4;i++) T->fp[i]=B->fp[i]; break;
        case 0x3c2: for(int i=0;i<4;i++) T->w[i]=spu_fceq1(A->w[i],B->w[i])?~0u:0u; break;
        case 0x2c2: for(int i=0;i<4;i++) T->w[i]=spu_fcgt1(A->w[i],B->w[i])?~0u:0u; break;
        case 0x3ca: for(int i=0;i<4;i++) T->w[i]=spu_fcmeq1(A->w[i],B->w[i])?~0u:0u; break;
        case 0x2ca: for(int i=0;i<4;i++) T->w[i]=spu_fcmgt1(A->w[i],B->w[i])?~0u:0u; break;
        case 0x3b8: { double d0=(double)A->fp[0], d1=(double)A->fp[2]; setdf(T,0,d0); setdf(T,1,d1); } break;
        case 0x3b9: { float f0=(float)getdf(A,0), f1=(float)getdf(A,1);
            uint32_t u0,u1; memcpy(&u0,&f0,4); memcpy(&u1,&f1,4);
            T->w[0]=u0; T->w[1]=0; T->w[2]=u1; T->w[3]=0; } break;
        case 0x398: for(int i=0;i<4;i++) T->w[i]=0; break;
        case 0x3ba: break;

        case 0x2cc: for(int j=0;j<2;j++) setdf(T,j,getdf(A,j)+getdf(B,j)); break;
        case 0x2cd: for(int j=0;j<2;j++) setdf(T,j,getdf(A,j)-getdf(B,j)); break;
        case 0x2ce: for(int j=0;j<2;j++) setdf(T,j,getdf(A,j)*getdf(B,j)); break;
        case 0x35c: for(int j=0;j<2;j++) setdf(T,j,getdf(A,j)*getdf(B,j)+getdf(T,j)); break;
        case 0x35d: for(int j=0;j<2;j++) setdf(T,j,getdf(A,j)*getdf(B,j)-getdf(T,j)); break;
        case 0x35e: for(int j=0;j<2;j++) setdf(T,j,getdf(T,j)-getdf(A,j)*getdf(B,j)); break;
        case 0x35f: for(int j=0;j<2;j++) setdf(T,j,-(getdf(A,j)*getdf(B,j)+getdf(T,j))); break;
        case 0x3c3: for(int j=0;j<2;j++) setd(T,j,(getdf(A,j)==getdf(B,j))?~0ull:0ull); break;
        case 0x2c3: for(int j=0;j<2;j++) setd(T,j,(getdf(A,j)>getdf(B,j))?~0ull:0ull); break;
        case 0x3cb: for(int j=0;j<2;j++) setd(T,j,(fabs(getdf(A,j))==fabs(getdf(B,j)))?~0ull:0ull); break;
        case 0x2cb: for(int j=0;j<2;j++) setd(T,j,(fabs(getdf(A,j))>fabs(getdf(B,j)))?~0ull:0ull); break;
        case 0x3bf: {
            for(int j=0;j<2;j++){ uint64_t u=getd(A,j); int exp=(int)((u>>52)&0x7ff); uint64_t frac=u&0xfffffffffffffull;
                int neg=(int)(u>>63); uint64_t r=0; int m=(int)((op>>14)&0x7f);
                int isnan=(exp==0x7ff&&frac), isinf=(exp==0x7ff&&!frac), iszero=(!exp&&!frac), isden=(!exp&&frac);
                if ((m&0x40)&&isnan) r=~0ull;
                if ((m&0x20)&&isinf&&!neg) r=~0ull;  if ((m&0x10)&&isinf&&neg) r=~0ull;
                if ((m&0x08)&&iszero&&!neg) r=~0ull; if ((m&0x04)&&iszero&&neg) r=~0ull;
                if ((m&0x02)&&isden&&!neg) r=~0ull;  if ((m&0x01)&&isden&&neg) r=~0ull;
                setd(T,j,r); } } break;

        case 0x1a8: TAKE(A->w[0]);
        case 0x1a9: { uint32_t t=A->w[0]; set_pref(T,next); TAKE(t); }
        case 0x1aa: TAKE(c->srr0);
        case 0x1ab: { set_pref(T,next); break; }
        case 0x128: if (T->w[0]==0) TAKE(A->w[0]); break;
        case 0x129: if (T->w[0]!=0) TAKE(A->w[0]); break;
        case 0x12a: if ((T->w[0]&0xffff)==0) TAKE(A->w[0]); break;
        case 0x12b: if ((T->w[0]&0xffff)!=0) TAKE(A->w[0]); break;
        case 0x1ac: break;

        default: {
            static volatile long n_unk;
            if (++n_unk<=32)
                fprintf(stderr,"[SPU-INTERP] unknown op=%08x op11=0x%03x pc=0x%x\n", op, op11, pc);
            break;
        }
        }
        pc = next;
next_insn:;
        #undef TAKE
    }
}
