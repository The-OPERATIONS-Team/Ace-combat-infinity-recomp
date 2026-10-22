#include "statecap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <direct.h>

static uint8_t*  g_base;
static uint64_t  g_size;
static char      g_dir[260];
static char      g_why[128];
static int       g_seq;
static volatile LONG g_busy;
static volatile LONG g_rsxpend;
static HANDLE    g_evt;
static FILE*     g_man;

#define NPROV 8
static struct { const char* name; void (*fn)(const char*); } g_prov[NPROV];
static int g_nprov;

const char* statecap_dir(void){ return g_dir; }
int  statecap_rsx_pending(void){ return g_rsxpend!=0; }
void statecap_rsx_done(void){ g_rsxpend=0; }

void statecap_register(const char* name, void (*fn)(const char* dir)){
    if(g_nprov<NPROV){ g_prov[g_nprov].name=name; g_prov[g_nprov].fn=fn; g_nprov++; }
}

static void man(const char* fmt, ...){
    va_list ap; va_start(ap,fmt);
    if(g_man){ vfprintf(g_man,fmt,ap); fputc('\n',g_man); }
    va_end(ap);
}

static int dump_ram(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/ram.bin",dir);
    FILE* f=fopen(p,"wb"); if(!f){ man("ram.bin: FAILED to open"); return 0; }
    const uint32_t shift=16, bsz=1u<<shift;
    uint32_t nblk=(uint32_t)(g_size>>shift);
    uint32_t* ids=(uint32_t*)malloc((size_t)nblk*4);
    if(!ids){ fclose(f); man("ram.bin: out of memory"); return 0; }
    uint32_t n=0;
    for(uint32_t b=0;b<nblk;b++){
        const uint64_t* q=(const uint64_t*)(g_base+((uint64_t)b<<shift));
        for(uint32_t i=0;i<bsz/8;i++) if(q[i]){ ids[n++]=b; break; }
    }
    uint8_t hdr[32]; memset(hdr,0,sizeof hdr);
    memcpy(hdr,"PS3RAM01",8);
    memcpy(hdr+8,&shift,4); memcpy(hdr+12,&nblk,4); memcpy(hdr+16,&n,4);
    memcpy(hdr+24,&g_size,8);
    fwrite(hdr,1,sizeof hdr,f);
    fwrite(ids,4,n,f);
    for(uint32_t i=0;i<n;i++) fwrite(g_base+((uint64_t)ids[i]<<shift),1,bsz,f);
    fclose(f);
    man("ram.bin        guest RAM, %u/%u blocks of 64KB present (%.0f MB), "
        "address space 0x%llx",n,nblk,(double)n*bsz/1048576.0,
        (unsigned long long)g_size);
    free(ids);
    return 1;
}

static void write_reader(const char* dir){
    char p[300]; snprintf(p,sizeof p,"%s/read_ram.py",dir);
    FILE* f=fopen(p,"w"); if(!f) return;
    fputs(
"#!/usr/bin/env python3\n"
"import struct, sys\n"
"\n"
"class Ram:\n"
"    def __init__(self, path):\n"
"        self.f = open(path, 'rb')\n"
"        h = self.f.read(32)\n"
"        assert h[:8] == b'PS3RAM01', 'not a statecap ram.bin'\n"
"        self.shift, self.nblk, self.npres = struct.unpack_from('<III', h, 8)\n"
"        self.mem_size, = struct.unpack_from('<Q', h, 24)\n"
"        self.bsz = 1 << self.shift\n"
"        ids = struct.unpack('<%dI' % self.npres, self.f.read(4 * self.npres))\n"
"        self.data0 = 32 + 4 * self.npres\n"
"        self.idx = {b: i for i, b in enumerate(ids)}\n"
"        self.blocks = ids\n"
"    def read(self, ea, n):\n"
"        out = bytearray()\n"
"        while n > 0:\n"
"            b, off = ea >> self.shift, ea & (self.bsz - 1)\n"
"            take = min(n, self.bsz - off)\n"
"            i = self.idx.get(b)\n"
"            if i is None:\n"
"                out += b'\\x00' * take\n"
"            else:\n"
"                self.f.seek(self.data0 + i * self.bsz + off)\n"
"                out += self.f.read(take)\n"
"            ea += take; n -= take\n"
"        return bytes(out)\n"
"    def u32(self, ea):\n"
"        return struct.unpack('>I', self.read(ea, 4))[0]\n"
"    def u64(self, ea):\n"
"        return struct.unpack('>Q', self.read(ea, 8))[0]\n"
"    def f32(self, ea):\n"
"        return struct.unpack('>f', self.read(ea, 4))[0]\n"
"\n"
"if __name__ == '__main__':\n"
"    r = Ram(sys.argv[1])\n"
"    if len(sys.argv) > 2 and sys.argv[2] == '--blocks':\n"
"        print('%d blocks of %d bytes' % (r.npres, r.bsz))\n"
"        for b in r.blocks: print('0x%08x' % (b << r.shift))\n"
"        raise SystemExit\n"
"    ea = int(sys.argv[2], 0); n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 256\n"
"    d = r.read(ea, n)\n"
"    for o in range(0, len(d), 16):\n"
"        row = d[o:o+16]\n"
"        print('%08x  %-48s %s' % (ea + o, ' '.join('%02x' % c for c in row),\n"
"              ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))\n", f);
    fclose(f);
}

static void take(const char* why){
    SYSTEMTIME st; GetLocalTime(&st);
    snprintf(g_dir,sizeof g_dir,"out/snap_%03d_%02d%02d%02d",++g_seq,
             st.wHour,st.wMinute,st.wSecond);
    _mkdir("out"); _mkdir(g_dir);
    char p[300]; snprintf(p,sizeof p,"%s/manifest.txt",g_dir);
    g_man=fopen(p,"w");
    DWORD t0=GetTickCount();
    man("statecap snapshot");
    man("  reason      %s",why?why:"(unspecified)");
    man("  taken       %04d-%02d-%02d %02d:%02d:%02d.%03d local",
        st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
    man("  uptime      %lu ms",(unsigned long)t0);
    man("  built       " __DATE__ " " __TIME__);
    man("");

    g_rsxpend=1;

    write_reader(g_dir);
    if(!getenv("PS3_SNAP_NORAM")){
        dump_ram(g_dir);
        man("               (RAM done at %lu ms, %lu ms after the trigger)",
            (unsigned long)GetTickCount(),(unsigned long)(GetTickCount()-t0));
    } else man("ram.bin        SKIPPED (PS3_SNAP_NORAM)");

    for(int i=0;i<g_nprov;i++){
        DWORD a=GetTickCount();
        g_prov[i].fn(g_dir);
        man("%-14s provider done at %lu ms (+%lu)",g_prov[i].name,
            (unsigned long)GetTickCount(),(unsigned long)(GetTickCount()-a));
    }

    DWORD r0=GetTickCount();
    for(int i=0;i<300 && g_rsxpend;i++) Sleep(10);
    if(!g_rsxpend){
        man("rsx            written at %lu ms (%lu ms waiting for a flip)",
            (unsigned long)(GetTickCount()-t0),(unsigned long)(GetTickCount()-r0));
    }
    if(g_rsxpend){
        g_rsxpend=0;
        man("rsx            no flip within 3s, skipped");
    }
    man("");
    man("total          %lu ms",(unsigned long)(GetTickCount()-t0));
    fclose(g_man); g_man=0;
    fprintf(stderr,"[SNAP] wrote %s (%lu ms)\n",g_dir,
            (unsigned long)(GetTickCount()-t0));
    fflush(stderr);
}

static DWORD WINAPI snap_thread(LPVOID p){
    (void)p;
    for(;;){
        WaitForSingleObject(g_evt,INFINITE);
        char why[128]; strncpy(why,g_why,sizeof why); why[sizeof why-1]=0;
        take(why);
        g_busy=0;
    }
}

void statecap_request(const char* why){
    if(!g_evt) return;
    if(InterlockedCompareExchange(&g_busy,1,0)!=0) return;
    strncpy(g_why,why?why:"",sizeof g_why); g_why[sizeof g_why-1]=0;
    fprintf(stderr,"[SNAP] requested: %s\n",why?why:"");
    fflush(stderr);
    SetEvent(g_evt);
}

static DWORD WINAPI hotkey_thread(LPVOID p){
    (void)p;
    int key=VK_F8;
    { const char* e=getenv("PS3_SNAP_KEY");
      if(e){ if((e[0]=='f'||e[0]=='F')&&e[1]){ int n=atoi(e+1);
                 if(n>=1&&n<=12) key=VK_F1+n-1; }
             else { int n=atoi(e); if(n>0) key=n; } } }
    GetAsyncKeyState(key);
    DWORD last=0;
    for(;;){
        Sleep(40);
        int fire=0; const char* why=0;
        if(GetAsyncKeyState(key)&1){ fire=1; why="hotkey"; }
        if(!fire){
            FILE* f=fopen("snap.on","rb");
            if(f){ char b[96]; size_t r=fread(b,1,sizeof b-1,f); b[r]=0; fclose(f);
                   remove("snap.on");
                   for(size_t i=0;i<r;i++) if(b[i]=='\n'||b[i]=='\r') b[i]=0;
                   static char sb[96]; snprintf(sb,sizeof sb,"snap.on %s",b);
                   fire=1; why=sb; }
        }
        if(!fire) continue;
        DWORD now=GetTickCount();
        if(last && now-last<2000) continue;
        last=now;
        statecap_request(why);
    }
}

void statecap_init(uint8_t* base, uint64_t size){
    g_base=base; g_size=size;
    g_evt=CreateEvent(0,FALSE,FALSE,0);
    CreateThread(0,0,snap_thread,0,0,0);
    if(!getenv("PS3_SNAP_NOKEY")) CreateThread(0,0,hotkey_thread,0,0,0);
    fprintf(stderr,"[SNAP] armed: press F8 in the game window (or drop snap.on) "
                   "for a full state snapshot into out/snap_NNN/\n");
}
