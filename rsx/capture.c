#include "capture.h"
#include "gcm_state.h"
#include "lz4mini.h"
#include "mtrace.h"
#include "ptrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <windows.h>
#include <direct.h>

int g_cap_recording  = 0;
int g_cap_disable    = 0;
int g_cap_writewatch = 0;

#define BLK_SHIFT   16
#define BLK         (1u << BLK_SHIFT)
#define CAPPG_SHIFT  12
#define CAPPG        (1u << CAPPG_SHIFT)
#define DIFF_CHUNK  128
#define NSLOT       3

typedef struct { uint8_t* p; size_t n, cap; } Buf;
static int g_oom;

static int buf_reserve(Buf* b, size_t need){
    if(b->cap >= need) return 1;
    size_t c = b->cap ? b->cap : 65536;
    while(c < need) c += c / 2 + 65536;
    uint8_t* np = (uint8_t*)realloc(b->p, c);
    if(!np){ g_oom = 1; return 0; }
    b->p = np; b->cap = c; return 1;
}
static int buf_put(Buf* b, const void* d, size_t n){
    if(!n) return 1;
    if(!buf_reserve(b, b->n + n)) return 0;
    memcpy(b->p + b->n, d, n); b->n += n; return 1;
}
static int buf_u32(Buf* b, uint32_t v){ return buf_put(b, &v, 4); }
static void buf_free(Buf* b){ free(b->p); b->p = 0; b->n = b->cap = 0; }

typedef struct { CapFrame h; Buf body; } Slot;

static FILE*     g_cf;
static char      g_path[300];
static uint8_t*  g_base;
static uint64_t  g_mem_size;
static uint32_t  g_local_ea, g_local_size;
static uint32_t  g_nblk;
static uint32_t  g_frameno;
static long      g_frames_left = -1;
static DWORD     g_t0;
static uint64_t  g_maxbytes = 24576ull << 20;
static int       g_use_lz4 = 1;
static uint32_t  g_fullscan_n;
static uint64_t  g_patch_total;
static int       g_use_trace = 1;

static Buf       g_io, g_dir, g_dat;
static uint32_t  g_npatch, g_patchbytes, g_nrec_frame;

static uint8_t** g_shadow;
static uint8_t*  g_vis;
static uint32_t* g_blkstamp;
static uint32_t* g_iopg;
static uint32_t  g_niopg;
static void**    g_wwbuf;
static ULONG_PTR g_wwcap;
static size_t    g_shadow_bytes, g_shadow_cap = (size_t)1024 << 20;

static Slot            g_slot[NSLOT];
static int             g_wslot, g_rslot;
static Slot*           g_cur;
static HANDLE          g_sem_free, g_sem_full, g_wthread;
static Buf             g_zbuf;
static void*           g_lz4scratch;
static volatile LONG   g_werr;
static volatile LONG64 g_bytes;

static volatile LONG g_req, g_stop_req;
static char          g_reqpath[300];
static long          g_reqframes;
static const char*   g_stop_why = "";

static char g_env_path[300] = "out/capture.rsxc";
static long g_env_frames = -1;

static DWORD WINAPI cap_writer(LPVOID p){
    (void)p;
    for(;;){
        WaitForSingleObject(g_sem_full, INFINITE);
        Slot* s = &g_slot[g_rslot];
        if(!s->h.magic){ ReleaseSemaphore(g_sem_free, 1, 0); break; }

        int         raw     = (int)s->body.n;
        const void* payload = s->body.p;
        int         comp    = raw;
        if(g_use_lz4 && raw > 0 && buf_reserve(&g_zbuf, (size_t)lz4m_bound(raw))){
            int c = lz4m_compress(s->body.p, raw, g_zbuf.p, (int)g_zbuf.cap, g_lz4scratch);
            if(c > 0 && c < raw){ payload = g_zbuf.p; comp = c; s->h.flags |= CAPF_LZ4; }
        }
        s->h.raw = (uint32_t)raw; s->h.comp = (uint32_t)comp;
        if(fwrite(&s->h, sizeof s->h, 1, g_cf) != 1 ||
           (comp && fwrite(payload, 1, (size_t)comp, g_cf) != (size_t)comp)){
            if(!g_werr) fprintf(stderr, "[CAP] write failed (disk full?) - stopping\n");
            g_werr = 1;
        }
        InterlockedExchangeAdd64(&g_bytes, (LONG64)(sizeof s->h + (size_t)comp));

        g_rslot = (g_rslot + 1) % NSLOT;
        ReleaseSemaphore(g_sem_free, 1, 0);
    }
    return 0;
}

static void vis_mark(uint32_t ea, uint32_t len){
    if(!len || (uint64_t)ea >= g_mem_size) return;
    uint64_t a = ea, b = (uint64_t)ea + len;
    if(b > g_mem_size) b = g_mem_size;
    for(uint64_t blk = a >> BLK_SHIFT; blk <= (b - 1) >> BLK_SHIFT; blk++)
        g_vis[blk] = 1;
}
static void vis_build(void){
    memset(g_vis, 0, g_nblk);
    vis_mark(g_local_ea, g_local_size);
    for(uint32_t i = 0; i < g_niopg; i++)
        if(g_iopg[i]) vis_mark(g_iopg[i], BLK);
}

static uint8_t* shadow_get(uint32_t blk, int* fresh){
    *fresh = 0;
    uint8_t* s = g_shadow[blk];
    if(s) return s;
    if(g_shadow_bytes + BLK > g_shadow_cap){
        static int warned;
        if(!warned++)
            fprintf(stderr, "[CAP] shadow budget (%.0f MB) reached - the rest of "
                            "the visible window is written a whole page at a "
                            "time; raise PS3_CAP_SHADOWMB\n",
                    (double)g_shadow_cap / 1048576.0);
        return NULL;
    }
    s = (uint8_t*)malloc(BLK);
    if(!s) return NULL;
    memcpy(s, g_base + ((uint64_t)blk << BLK_SHIFT), BLK);
    g_shadow[blk] = s; g_shadow_bytes += BLK;
    *fresh = 1;
    return s;
}

static void emit(uint32_t ea, uint32_t len){
    if(!buf_reserve(&g_dir, g_dir.n + 8) || !buf_reserve(&g_dat, g_dat.n + len)) return;
    buf_u32(&g_dir, ea); buf_u32(&g_dir, len);
    buf_put(&g_dat, g_base + ea, len);
    g_npatch++; g_patchbytes += len;
}

static void page_dirty(uint64_t off){
    uint32_t blk = (uint32_t)(off >> BLK_SHIFT);
    if(blk >= g_nblk || !g_vis[blk]) return;
    if(g_blkstamp[blk] == g_frameno + 1) return;

    int fresh = 0;
    uint8_t* sh = shadow_get(blk, &fresh);
    if(!sh){
        emit((uint32_t)off, CAPPG);
        return;
    }
    if(fresh){
        g_blkstamp[blk] = g_frameno + 1;
        emit(blk << BLK_SHIFT, BLK);
        return;
    }

    uint32_t in_blk = (uint32_t)(off & (BLK - 1));
    const uint8_t* g = g_base + off;
    uint8_t*       s = sh + in_blk;
    uint32_t run = UINT32_MAX;
    for(uint32_t c = 0; c < CAPPG; c += DIFF_CHUNK){
        if(memcmp(g + c, s + c, DIFF_CHUNK)){
            if(run == UINT32_MAX) run = c;
        } else if(run != UINT32_MAX){
            emit((uint32_t)(off + run), c - run);
            memcpy(s + run, g + run, c - run);
            run = UINT32_MAX;
        }
    }
    if(run != UINT32_MAX){
        emit((uint32_t)(off + run), CAPPG - run);
        memcpy(s + run, g + run, CAPPG - run);
    }
}

static void scan_run_full(uint64_t off, uint64_t len){
    for(uint64_t p = 0; p + CAPPG <= len; p += CAPPG) page_dirty(off + p);
}
static void scan_run_ww(uint64_t off, uint64_t len){
    while(len){
        uint64_t chunk = len, maxb = (uint64_t)g_wwcap << CAPPG_SHIFT;
        if(chunk > maxb) chunk = maxb;
        ULONG_PTR cnt = g_wwcap; ULONG gran = 0;
        UINT r = GetWriteWatch(WRITE_WATCH_FLAG_RESET, g_base + off, (SIZE_T)chunk,
                               g_wwbuf, &cnt, &gran);
        if(r != 0){
            static int warned;
            if(!warned++) fprintf(stderr, "[CAP] GetWriteWatch failed (%lu) - "
                                          "falling back to a full compare\n",
                                  (unsigned long)GetLastError());
            scan_run_full(off, chunk);
        } else {
            for(ULONG_PTR i = 0; i < cnt; i++)
                page_dirty((uint64_t)((uint8_t*)g_wwbuf[i] - g_base));
        }
        off += chunk; len -= chunk;
    }
}

static void scan_dirty(void){
    g_npatch = 0; g_patchbytes = 0;
    g_dir.n = 0; g_dat.n = 0;
    int full = !g_cap_writewatch ||
               (g_fullscan_n && (g_frameno % g_fullscan_n) == 0);
    for(uint32_t b = 0; b < g_nblk; ){
        if(!g_vis[b]){ b++; continue; }
        uint32_t e = b; while(e < g_nblk && g_vis[e]) e++;
        uint64_t a0 = (uint64_t)b << BLK_SHIFT, a1 = (uint64_t)e << BLK_SHIFT;
        if(a1 > g_mem_size) a1 = g_mem_size;
        if(a1 > a0){ if(full) scan_run_full(a0, a1 - a0);
                     else     scan_run_ww  (a0, a1 - a0); }
        b = e;
    }
}

static void wrec(uint32_t tag, uint32_t a0, uint32_t a1, uint32_t a2,
                 uint32_t a3, uint32_t a4){
    uint32_t r[6] = { tag, a0, a1, a2, a3, a4 };
    if(!g_cur) return;
    if(buf_put(&g_cur->body, r, 24)) g_nrec_frame++;
}

void cap_method(uint32_t m, uint32_t a){ if(g_cap_recording) wrec(1, m, a, 0, 0, 0); }
void cap_setdisp(uint32_t id, uint32_t off, uint32_t pitch, uint32_t w, uint32_t h){
    if(g_cap_recording) wrec(2, id, off, pitch, w, h);
}

static void frame_open(uint32_t (*ioff2ea)(uint32_t), const RsxDispBufCap* disp8){
    if(g_cur) return;
    WaitForSingleObject(g_sem_free, INFINITE);
    Slot* s = &g_slot[g_wslot];
    s->body.n = 0;
    memset(&s->h, 0, sizeof s->h);

    g_io.n = 0;
    uint32_t nio = 0;
    for(uint32_t i = 0; i < g_niopg; i++){
        uint32_t ea = ioff2ea ? ioff2ea(i << BLK_SHIFT) : 0;
        if(ea != g_iopg[i]){ g_iopg[i] = ea; buf_u32(&g_io, i); buf_u32(&g_io, ea); nio++; }
    }
    vis_build();
    scan_dirty();

    buf_put(&s->body, &g_rsx, sizeof(RsxState));
    buf_put(&s->body, disp8, sizeof(RsxDispBufCap) * 8);
    buf_put(&s->body, g_io.p, g_io.n);
    buf_put(&s->body, g_dir.p, g_dir.n);
    buf_put(&s->body, g_dat.p, g_dat.n);

    s->h.magic       = CAPFRAME_TAG;
    s->h.index       = g_frameno;
    s->h.nio         = nio;
    s->h.npatch      = g_npatch;
    s->h.patch_bytes = g_patchbytes;
    s->h.t_ms        = (uint32_t)(GetTickCount() - g_t0);
    g_patch_total   += g_patchbytes;
    g_nrec_frame     = 0;
    g_cur            = s;
}

static void frame_publish(void){
    if(!g_cur) return;
    g_cur->h.nrec = g_nrec_frame;
    g_cur->h.mt_bytes = 0;
    if(g_use_trace){
        uint32_t mtn = 0;
        const void* mt = mtrc_frame(&mtn);
        if(mt && mtn && buf_put(&g_cur->body, mt, mtn)) g_cur->h.mt_bytes = mtn;
    }
    g_cur->h.pt_bytes = 0;
    { uint32_t ptn = 0;
      const void* pt = ptrc_frame(&ptn);
      if(pt && ptn && buf_put(&g_cur->body, pt, ptn)) g_cur->h.pt_bytes = ptn; }
    size_t want = sizeof(RsxState) + sizeof(RsxDispBufCap) * 8
                + 8u * g_cur->h.nio + 8u * g_cur->h.npatch
                + g_cur->h.patch_bytes + 24u * g_cur->h.nrec + g_cur->h.mt_bytes
                + g_cur->h.pt_bytes;
    if(want != g_cur->body.n){
        fprintf(stderr, "[CAP] frame %u body is %zu bytes, sections claim %zu - "
                        "dropping its contents\n", g_cur->h.index, g_cur->body.n, want);
        g_cur->h.nio = g_cur->h.npatch = g_cur->h.patch_bytes = g_cur->h.nrec = 0;
        g_cur->h.mt_bytes = 0;
        g_cur->h.pt_bytes = 0;
        g_cur->body.n = sizeof(RsxState) + sizeof(RsxDispBufCap) * 8;
        g_oom = 1;
    }
    g_cur = NULL;
    g_wslot = (g_wslot + 1) % NSLOT;
    ReleaseSemaphore(g_sem_full, 1, 0);
}

static void trackers_free(void){
    if(g_shadow){ for(uint32_t i = 0; i < g_nblk; i++) free(g_shadow[i]);
                  free(g_shadow); g_shadow = 0; }
    free(g_vis);      g_vis = 0;
    free(g_blkstamp); g_blkstamp = 0;
    free(g_iopg);     g_iopg = 0;
    free(g_wwbuf);    g_wwbuf = 0;
    g_shadow_bytes = 0;
}

static void cap_finish(void){
    if(!g_cf) return;
    frame_publish();
    mtrc_stop();
    ptrc_stop();
    WaitForSingleObject(g_sem_free, INFINITE);
    memset(&g_slot[g_wslot].h, 0, sizeof(CapFrame));
    g_wslot = (g_wslot + 1) % NSLOT;
    ReleaseSemaphore(g_sem_full, 1, 0);
    WaitForSingleObject(g_wthread, INFINITE);
    CloseHandle(g_wthread);  g_wthread = 0;
    CloseHandle(g_sem_free); CloseHandle(g_sem_full);
    g_sem_free = g_sem_full = 0;

    CapHdr2 h;
    if(!fseek(g_cf, 0, SEEK_SET) && fread(&h, sizeof h, 1, g_cf) == 1){
        h.nframes     = g_frameno;
        h.total_bytes = (uint64_t)g_bytes + h.frames_off;
        h.patch_bytes = g_patch_total;
        fseek(g_cf, 0, SEEK_SET);
        fwrite(&h, sizeof h, 1, g_cf);
    }
    fclose(g_cf); g_cf = 0;
    g_cap_recording = 0;
    for(int i = 0; i < NSLOT; i++) buf_free(&g_slot[i].body);
    buf_free(&g_zbuf); buf_free(&g_io); buf_free(&g_dir); buf_free(&g_dat);
    free(g_lz4scratch); g_lz4scratch = 0;
    trackers_free();

    double mb = (double)(g_bytes) / 1048576.0;
    fprintf(stderr, "[CAP] stopped (%s): %u frames, %.1f MB, %.0f ms, "
                    "%.2f MB/frame -> %s\n",
            g_stop_why, g_frameno, mb, (double)(GetTickCount() - g_t0),
            g_frameno ? mb / g_frameno : 0.0, g_path);
    fflush(stderr);
}

void cap_stop(const char* why){
    if(!g_cap_recording) return;
    g_stop_why = why ? why : "requested";
    g_stop_req = 1;
}

void cap_flip(uint32_t bufid){
    if(!g_cap_recording) return;
    wrec(3, bufid, 0, 0, 0, 0);
    frame_publish();
    g_frameno++;

    if(g_frames_left > 0 && --g_frames_left == 0) cap_stop("frame limit");
    if((uint64_t)g_bytes >= g_maxbytes)           cap_stop("size limit");
    if(g_werr)                                    cap_stop("write error");
    if(g_oom)                                     cap_stop("out of memory");
    { static int n; if(++n >= 16){ n = 0;
        FILE* f = fopen("capture.off", "rb");
        if(f){ fclose(f); remove("capture.off"); cap_stop("capture.off"); } } }
    if(g_stop_req){ g_stop_req = 0; cap_finish(); }
}

static int cap_begin(const RsxDispBufCap* disp8, uint32_t (*ioff2ea)(uint32_t)){
    _mkdir("out");
    g_cf = fopen(g_path, "wb");
    if(!g_cf){ fprintf(stderr, "[CAP] cannot open %s\n", g_path); return 0; }
    setvbuf(g_cf, NULL, _IOFBF, 4u << 20);

    if(!lz4m_selftest()){
        fprintf(stderr, "[CAP] LZ4 self-test FAILED - storing frames raw\n");
        g_use_lz4 = 0;
    }

    g_nblk  = (uint32_t)(g_mem_size >> BLK_SHIFT);
    g_niopg = 0x20000000u >> BLK_SHIFT;
    g_vis      = (uint8_t*)calloc(g_nblk, 1);
    g_blkstamp = (uint32_t*)calloc(g_nblk, 4);
    g_shadow   = (uint8_t**)calloc(g_nblk, sizeof(uint8_t*));
    g_iopg     = (uint32_t*)calloc(g_niopg, 4);
    g_wwcap    = 1u << 18;
    g_wwbuf    = (void**)malloc((size_t)g_wwcap * sizeof(void*));
    if(!g_vis || !g_blkstamp || !g_shadow || !g_iopg || !g_wwbuf){
        fprintf(stderr, "[CAP] out of memory arming the capture\n");
        fclose(g_cf); g_cf = 0; trackers_free(); return 0;
    }

    if(g_cap_writewatch) ResetWriteWatch(g_base, (SIZE_T)g_mem_size);
    else fprintf(stderr, "[CAP] guest arena has no MEM_WRITE_WATCH - every frame "
                         "re-compares the whole visible window (slow but correct)\n");

    for(uint32_t i = 0; i < g_niopg; i++)
        g_iopg[i] = ioff2ea ? ioff2ea(i << BLK_SHIFT) : 0;
    vis_build();

    CapHdr2 h; memset(&h, 0, sizeof h);
    memcpy(h.magic, CAP2_MAGIC, 8);
    h.hdr_size   = (uint32_t)sizeof h;
    h.state_size = (uint32_t)sizeof(RsxState);
    h.mem_size   = g_mem_size;
    h.local_ea   = g_local_ea;  h.local_size = g_local_size;
    h.blk_shift  = BLK_SHIFT;   h.nblk       = g_nblk;
    h.niopg      = g_niopg;     h.ndisp      = 8;
    h.page_shift = CAPPG_SHIFT;
    h.flags      = g_cap_writewatch ? 1u : 0u;
    fwrite(&h, sizeof h, 1, g_cf);
    fwrite(&g_rsx, sizeof(RsxState), 1, g_cf);
    fwrite(disp8, sizeof(RsxDispBufCap), 8, g_cf);
    fwrite(g_iopg, 4, g_niopg, g_cf);

    DWORD tsnap = GetTickCount();
    uint32_t bmbytes = (g_nblk + 7) / 8;
    uint8_t* bm = (uint8_t*)calloc(bmbytes, 1);
    if(!bm){ fclose(g_cf); g_cf = 0; trackers_free(); return 0; }
    for(uint32_t b = 0; b < g_nblk; b++){
        int dummy;
        const uint8_t* src = g_vis[b] ? shadow_get(b, &dummy) : NULL;
        if(!src) src = g_base + ((uint64_t)b << BLK_SHIFT);
        const uint64_t* q = (const uint64_t*)src;
        for(uint32_t i = 0; i < BLK / 8; i++)
            if(q[i]){ bm[b >> 3] |= (uint8_t)(1u << (b & 7)); break; }
    }
    memset(g_blkstamp, 0, (size_t)g_nblk * 4);
    fwrite(bm, 1, bmbytes, g_cf);
    uint32_t nz = 0;
    for(uint32_t b = 0; b < g_nblk; b++){
        if(!(bm[b >> 3] & (1u << (b & 7)))) continue;
        const uint8_t* src = g_shadow[b] ? g_shadow[b]
                                         : g_base + ((uint64_t)b << BLK_SHIFT);
        fwrite(src, 1, BLK, g_cf);
        nz++;
    }
    free(bm);
    fflush(g_cf);
    h.frames_off = (uint64_t)_ftelli64(g_cf);
    fseek(g_cf, 0, SEEK_SET);
    fwrite(&h, sizeof h, 1, g_cf);
    _fseeki64(g_cf, (long long)h.frames_off, SEEK_SET);

    g_lz4scratch = malloc(LZ4M_SCRATCH_BYTES);
    if(!g_lz4scratch) g_use_lz4 = 0;
    g_sem_free = CreateSemaphore(0, NSLOT, NSLOT, 0);
    g_sem_full = CreateSemaphore(0, 0, NSLOT, 0);
    g_wslot = g_rslot = 0; g_bytes = 0; g_werr = 0; g_oom = 0;
    g_wthread = CreateThread(0, 0, cap_writer, 0, 0, 0);
    if(!g_sem_free || !g_sem_full || !g_wthread){
        fprintf(stderr, "[CAP] cannot start the writer thread\n");
        if(g_wthread){ CloseHandle(g_wthread); g_wthread = 0; }
        if(g_sem_free){ CloseHandle(g_sem_free); g_sem_free = 0; }
        if(g_sem_full){ CloseHandle(g_sem_full); g_sem_full = 0; }
        fclose(g_cf); g_cf = 0; trackers_free(); return 0;
    }

    g_frameno = 0; g_patch_total = 0; g_t0 = GetTickCount();
    if(g_use_trace) mtrc_start(g_t0);
    ptrc_start();
    g_cap_recording = 1;
    fprintf(stderr, "[CAP] recording -> %s\n"
                    "[CAP]   base image %u/%u blocks (%.0f MB) in %lu ms, "
                    "shadow %.0f MB, %s, limit %s\n",
            g_path, nz, g_nblk, (double)nz * BLK / 1048576.0,
            (unsigned long)(GetTickCount() - tsnap),
            (double)g_shadow_bytes / 1048576.0,
            g_use_lz4 ? "lz4" : "raw",
            g_frames_left > 0 ? "frames" : "none (F9 or capture.off to stop)");
    fflush(stderr);
    return 1;
}

static int cap_take_request(void){
    if(InterlockedExchange(&g_req, 0)){
        snprintf(g_path, sizeof g_path, "%s", g_reqpath);
        g_frames_left = g_reqframes;
        return 1;
    }
    { static DWORD last; DWORD now = GetTickCount();
      if(now - last < 500) return 0;
      last = now; }
    FILE* mk = fopen("capture.on", "rb");
    if(!mk) return 0;
    char buf[32] = {0};
    long frames = 1;
    if(fgets(buf, sizeof buf, mk)){ long v = atol(buf); if(v != 0) frames = v; }
    fclose(mk); remove("capture.on");
    snprintf(g_path, sizeof g_path, "%s", g_env_path);
    g_frames_left = frames > 0 ? frames : -1;
    return 1;
}

void cap_request(const char* path, int frames){
    if(g_cap_recording || g_cap_disable || g_req) return;
    g_reqframes = frames > 0 ? frames : -1;
    snprintf(g_reqpath, sizeof g_reqpath, "%s", path ? path : g_env_path);
    InterlockedExchange(&g_req, 1);
}

void cap_maybe_start(uint8_t* base, uint64_t mem_size, uint32_t local_ea,
                     uint32_t local_size, uint32_t (*ioff2ea)(uint32_t),
                     const RsxDispBufCap* disp8){
    if(g_cap_disable) return;
    if(!g_cap_recording){
        g_base = base; g_mem_size = mem_size;
        g_local_ea = local_ea; g_local_size = local_size;
        if(!cap_take_request()) return;
        if(!cap_begin(disp8, ioff2ea)) return;
    }
    frame_open(ioff2ea, disp8);
}

static DWORD WINAPI cap_hotkey(LPVOID p){
    (void)p;
    int key = VK_F9;
    { const char* e = getenv("PS3_CAP_KEY");
      if(e){ if((e[0] == 'f' || e[0] == 'F') && e[1]){ int n = atoi(e + 1);
                 if(n >= 1 && n <= 12) key = VK_F1 + n - 1; }
             else { int n = atoi(e); if(n > 0) key = n; } } }
    GetAsyncKeyState(key);
    DWORD last = 0;
    for(;;){
        Sleep(40);
        if(!(GetAsyncKeyState(key) & 1)) continue;
        DWORD now = GetTickCount();
        if(last && now - last < 500) continue;
        last = now;
        if(g_cap_recording) cap_stop("hotkey");
        else{
            cap_request(g_env_path, (int)g_env_frames);
            fprintf(stderr, "[CAP] hotkey: recording starts at the next flip "
                            "(%s)\n", g_env_path);
            fflush(stderr);
        }
    }
}

void cap_init(uint8_t* base, uint64_t mem_size){
    static int done;
    if(done || g_cap_disable) return;
    done = 1;
    g_base = base; g_mem_size = mem_size;

    const char* e;
    if((e = getenv("PS3_CAP_PATH")) && *e) snprintf(g_env_path, sizeof g_env_path, "%s", e);
    g_env_frames = (e = getenv("PS3_CAP_FRAMES")) ? atol(e) : -1;
    if(g_env_frames <= 0) g_env_frames = -1;
    g_maxbytes = (uint64_t)((e = getenv("PS3_CAP_MAXMB")) ? atol(e) : 24576) << 20;
    if(!g_maxbytes) g_maxbytes = ~(uint64_t)0;
    g_use_lz4   = getenv("PS3_CAP_NOLZ4")   ? 0 : 1;
    g_use_trace = getenv("PS3_CAP_NOTRACE") ? 0 : 1;
    g_fullscan_n = (e = getenv("PS3_CAP_FULLSCAN")) ? (uint32_t)atol(e) : 0;
    g_shadow_cap = (size_t)((e = getenv("PS3_CAP_SHADOWMB")) ? atol(e) : 1024) << 20;

    if(!getenv("PS3_CAP_NOKEY")) CreateThread(0, 0, cap_hotkey, 0, 0, 0);
    fprintf(stderr, "[CAP] armed: F9 starts/stops a gameplay recording -> %s "
                    "(%s%s)\n", g_env_path,
            g_env_frames > 0 ? "frame-limited" : "unlimited",
            g_cap_writewatch ? "" : ", NO write-watch - slow");
}
