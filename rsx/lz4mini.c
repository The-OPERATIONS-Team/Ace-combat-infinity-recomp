#include "lz4mini.h"
#include <string.h>

int lz4m_bound(int s){ return s < 0 ? 0 : s + s / 255 + 16; }

static inline uint32_t rd32(const uint8_t* p){ uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint32_t hash4(uint32_t v){ return (v * 2654435761u) >> (32 - LZ4M_HLOG); }

int lz4m_compress(const void* srcv, int slen, void* dstv, int dcap, void* scratch){
    const uint8_t* src = (const uint8_t*)srcv;
    uint8_t*       dst = (uint8_t*)dstv;
    uint32_t*      ht  = (uint32_t*)scratch;
    if(slen < 0 || dcap <= 0 || !ht) return 0;
    memset(ht, 0, LZ4M_SCRATCH_BYTES);

    int ip = 0, anchor = 0, op = 0;
    const int mflimit    = slen - 12;
    const int matchlimit = slen - 5;

    while(ip < mflimit){
        uint32_t seq = rd32(src + ip);
        uint32_t h   = hash4(seq);
        int      ref = (int)ht[h] - 1;
        ht[h] = (uint32_t)(ip + 1);
        if(ref < 0 || ip - ref > 65535 || rd32(src + ref) != seq){ ip++; continue; }

        int m = 4;
        while(ip + m < matchlimit && src[ref + m] == src[ip + m]) m++;
        int lit = ip - anchor, ml = m - 4;

        int need = 1 + (lit >= 15 ? (lit - 15) / 255 + 1 : 0) + lit + 2
                     + (ml  >= 15 ? (ml  - 15) / 255 + 1 : 0);
        if(op + need > dcap) return 0;

        dst[op++] = (uint8_t)(((lit < 15 ? lit : 15) << 4) | (ml < 15 ? ml : 15));
        if(lit >= 15){ int r = lit - 15; while(r >= 255){ dst[op++] = 255; r -= 255; }
                       dst[op++] = (uint8_t)r; }
        memcpy(dst + op, src + anchor, (size_t)lit); op += lit;
        int off = ip - ref;
        dst[op++] = (uint8_t)(off & 0xff);
        dst[op++] = (uint8_t)(off >> 8);
        if(ml >= 15){ int r = ml - 15; while(r >= 255){ dst[op++] = 255; r -= 255; }
                      dst[op++] = (uint8_t)r; }
        ip += m; anchor = ip;
    }

    {
        int lit  = slen - anchor;
        int need = 1 + (lit >= 15 ? (lit - 15) / 255 + 1 : 0) + lit;
        if(op + need > dcap) return 0;
        dst[op++] = (uint8_t)((lit < 15 ? lit : 15) << 4);
        if(lit >= 15){ int r = lit - 15; while(r >= 255){ dst[op++] = 255; r -= 255; }
                       dst[op++] = (uint8_t)r; }
        memcpy(dst + op, src + anchor, (size_t)lit); op += lit;
    }
    return op;
}

int lz4m_decompress(const void* srcv, int slen, void* dstv, int dcap){
    const uint8_t* s = (const uint8_t*)srcv;
    uint8_t*       d = (uint8_t*)dstv;
    int ip = 0, op = 0;
    while(ip < slen){
        int tok = s[ip++];
        int ll  = tok >> 4;
        if(ll == 15){ int b;
            do{ if(ip >= slen) return -1; b = s[ip++]; ll += b;
                if(ll > dcap) return -1;
            }while(b == 255); }
        if(ip + ll > slen || op + ll > dcap) return -1;
        memcpy(d + op, s + ip, (size_t)ll); ip += ll; op += ll;
        if(ip >= slen) break;

        if(ip + 2 > slen) return -1;
        int off = (int)s[ip] | ((int)s[ip + 1] << 8); ip += 2;
        if(off <= 0 || off > op) return -1;
        int ml = tok & 15;
        if(ml == 15){ int b;
            do{ if(ip >= slen) return -1; b = s[ip++]; ml += b;
                if(ml > dcap) return -1;
            }while(b == 255); }
        ml += 4;
        if(op + ml > dcap) return -1;

        const uint8_t* m = d + op - off;
        if(off >= 8){
            int i = 0;
            for(; i + 8 <= ml; i += 8) memcpy(d + op + i, m + i, 8);
            for(; i < ml; i++) d[op + i] = m[i];
        } else {
            for(int i = 0; i < ml; i++) d[op + i] = m[i];
        }
        op += ml;
    }
    return op;
}

int lz4m_selftest(void){
    enum { N = 70000 };
    static uint8_t in[N], out[N + N / 255 + 16], back[N];
    static uint32_t ht[1u << LZ4M_HLOG];
    uint32_t r = 12345u;
    for(int i = 0; i < N; i++){
        r = r * 1103515245u + 12345u;
        if(i < N / 3)          in[i] = 0xAB;
        else if(i < 2 * N / 3) in[i] = (uint8_t)(i % 251);
        else                   in[i] = (uint8_t)(r >> 24);
    }
    int c = lz4m_compress(in, N, out, (int)sizeof out, ht);
    if(c <= 0) return 0;
    if(lz4m_decompress(out, c, back, N) != N) return 0;
    if(memcmp(in, back, N)) return 0;
    for(int n = 0; n <= 20; n++){
        c = lz4m_compress(in, n, out, (int)sizeof out, ht);
        if(c <= 0 && n > 0) return 0;
        if(n == 0 && c < 0) return 0;
        if(lz4m_decompress(out, c, back, n ? n : 1) != n) return 0;
        if(n && memcmp(in, back, (size_t)n)) return 0;
    }
    return 1;
}
