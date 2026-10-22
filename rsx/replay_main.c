#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "rsx.h"
#include "gcm_state.h"
#include "capture.h"
#include "lz4mini.h"
#include "mtrace.h"
#include "ptrace.h"
#include "spu_polldet.h"
#include "vk_present.h"
#include "vk_draw.h"

#define BLK_SHIFT 16
#define BLK       (1u << BLK_SHIFT)

static const uint8_t* g_map;
static uint64_t       g_mapsz;
static uint8_t*       g_base;
static uint64_t       g_mem;

static uint32_t*      g_iopg;
static const uint32_t* g_iopg_base;
static uint32_t       g_niopg;

static uint32_t       g_nblk;
static const uint8_t* g_bm;
static const uint8_t* g_blocks;
static uint32_t*      g_blkslot;
static uint8_t*       g_touched;
static uint32_t       g_local_ea, g_local_size;

static const CapFrame** g_frames;
static uint32_t         g_nframes;

static uint32_t replay_ioff2ea(uint32_t o){
    uint32_t pg = o >> BLK_SHIFT;
    if(pg >= g_niopg || !g_iopg[pg]) return 0;
    return g_iopg[pg] + (o & 0xffffu);
}

static int map_file(const char* path){
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, 0);
    if(fh == INVALID_HANDLE_VALUE){
        fprintf(stderr, "[REPLAY] cannot open %s\n", path); return 0; }
    LARGE_INTEGER sz;
    if(!GetFileSizeEx(fh, &sz) || sz.QuadPart < 64){
        fprintf(stderr, "[REPLAY] %s is empty\n", path); return 0; }
    g_mapsz = (uint64_t)sz.QuadPart;
    HANDLE mh = CreateFileMappingA(fh, 0, PAGE_READONLY, 0, 0, 0);
    if(!mh){ fprintf(stderr, "[REPLAY] CreateFileMapping failed (%lu)\n",
                     (unsigned long)GetLastError()); return 0; }
    g_map = (const uint8_t*)MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
    if(!g_map){ fprintf(stderr, "[REPLAY] MapViewOfFile failed (%lu) - a capture "
                                "this large needs a 64-bit build\n",
                        (unsigned long)GetLastError()); return 0; }
    return 1;
}

static int base_index(uint32_t nblk, const uint8_t* bm, const uint8_t* blocks){
    g_nblk = nblk; g_bm = bm; g_blocks = blocks;
    g_blkslot = (uint32_t*)malloc((size_t)nblk * 4);
    g_touched = (uint8_t*)calloc(nblk, 1);
    if(!g_blkslot || !g_touched) return 0;
    uint32_t slot = 0;
    for(uint32_t b = 0; b < nblk; b++)
        g_blkslot[b] = (bm[b >> 3] & (1u << (b & 7))) ? slot++ : UINT32_MAX;
    return 1;
}
static uint32_t base_present(void){
    uint32_t n = 0;
    for(uint32_t b = 0; b < g_nblk; b++) if(g_blkslot[b] != UINT32_MAX) n++;
    return n;
}
static void block_restore(uint32_t b){
    uint8_t* dst = g_base + ((uint64_t)b << BLK_SHIFT);
    if(g_blkslot[b] != UINT32_MAX)
        memcpy(dst, g_blocks + (uint64_t)g_blkslot[b] * BLK, BLK);
    else
        memset(dst, 0, BLK);
}
static void base_load_all(void){
    for(uint32_t b = 0; b < g_nblk; b++)
        if(g_blkslot[b] != UINT32_MAX) block_restore(b);
    memset(g_touched, 0, g_nblk);
}
static void mark_touched(uint32_t ea, uint32_t len){
    if(!len) return;
    uint64_t a = ea, e = (uint64_t)ea + len;
    if(e > g_mem) e = g_mem;
    for(uint64_t b = a >> BLK_SHIFT; b <= (e - 1) >> BLK_SHIFT && b < g_nblk; b++)
        g_touched[b] = 1;
}
static void mark_visible_touched(const uint32_t* iopg){
    mark_touched(g_local_ea, g_local_size);
    for(uint32_t i = 0; i < g_niopg; i++) if(iopg[i]) mark_touched(iopg[i], BLK);
}
static void base_restore(void){
    mark_visible_touched(g_iopg);
    mark_visible_touched(g_iopg_base);
    for(uint32_t b = 0; b < g_nblk; b++) if(g_touched[b]) block_restore(b);
    memset(g_touched, 0, g_nblk);
    memcpy(g_iopg, g_iopg_base, (size_t)g_niopg * 4);
}

static uint8_t* g_body; static size_t g_bodycap;
static uint32_t g_state_size;

static const uint8_t* frame_body(const CapFrame* f){
    const uint8_t* src = (const uint8_t*)(f + 1);
    if(!(f->flags & CAPF_LZ4)){
        if(f->raw != f->comp){
            fprintf(stderr, "[REPLAY] frame %u: stored raw but raw=%u comp=%u\n",
                    f->index, f->raw, f->comp);
            return NULL;
        }
        return src;
    }
    if(g_bodycap < f->raw){
        size_t c = f->raw + (f->raw >> 1) + 65536;
        uint8_t* np = (uint8_t*)realloc(g_body, c);
        if(!np){ fprintf(stderr, "[REPLAY] out of memory for frame %u\n", f->index);
                 return NULL; }
        g_body = np; g_bodycap = c;
    }
    int n = lz4m_decompress(src, (int)f->comp, g_body, (int)f->raw);
    if(n != (int)f->raw){
        fprintf(stderr, "[REPLAY] frame %u: corrupt compressed body (%d/%u)\n",
                f->index, n, f->raw);
        return NULL;
    }
    return g_body;
}

typedef struct {
    const RsxState*      st;
    const RsxDispBufCap* disp;
    const uint32_t*      io;
    const uint32_t*      dir;
    const uint8_t*       dat;
    const uint8_t*       rec;
    const uint8_t*       mt;
    const uint8_t*       pt;
} FrameView;

static int frame_view(const CapFrame* f, FrameView* v){
    const uint8_t* p = frame_body(f);
    if(!p) return 0;
    uint64_t need = (uint64_t)g_state_size + sizeof(RsxDispBufCap) * 8
                  + 8ull * f->nio + 8ull * f->npatch + f->patch_bytes
                  + 24ull * f->nrec + f->mt_bytes + f->pt_bytes;
    if(need > f->raw){
        fprintf(stderr, "[REPLAY] frame %u: body is %u bytes, sections need %llu\n",
                f->index, f->raw, (unsigned long long)need);
        return 0;
    }
    v->st   = (const RsxState*)p;                       p += g_state_size;
    v->disp = (const RsxDispBufCap*)p;                  p += sizeof(RsxDispBufCap) * 8;
    v->io   = (const uint32_t*)p;                       p += 8ull * f->nio;
    v->dir  = (const uint32_t*)p;                       p += 8ull * f->npatch;
    v->dat  = p;                                        p += f->patch_bytes;
    v->rec  = p;                                        p += 24ull * f->nrec;
    v->mt   = f->mt_bytes ? p : NULL;                   p += f->mt_bytes;
    v->pt   = f->pt_bytes ? p : NULL;
    return 1;
}

typedef struct {
    const MtrcHdr*     h;
    const MtrcPpuRow*  ppu;
    const MtrcNameRow* hle;
    const MtrcScRow*   sc;
    const MtrcNameRow* spu;
    const MtrcFileEv*  ev;
    const uint8_t*     str;
    uint32_t           strn;
} MtView;

static int mt_view(const uint8_t* p, uint32_t n, MtView* v){
    if(!p || n < sizeof(MtrcHdr)) return 0;
    const MtrcHdr* h = (const MtrcHdr*)p;
    if(h->magic != MTRC_MAGIC) return 0;
    uint64_t need = sizeof(MtrcHdr)
                  + (uint64_t)h->nppu * sizeof(MtrcPpuRow)
                  + (uint64_t)h->nhle * sizeof(MtrcNameRow)
                  + (uint64_t)h->nsc  * sizeof(MtrcScRow)
                  + (uint64_t)h->nspu * sizeof(MtrcNameRow)
                  + (uint64_t)h->nev  * sizeof(MtrcFileEv);
    if(need > n) return 0;
    const uint8_t* q = p + sizeof(MtrcHdr);
    v->h   = h;
    v->ppu = (const MtrcPpuRow*)q;  q += (size_t)h->nppu * sizeof(MtrcPpuRow);
    v->hle = (const MtrcNameRow*)q; q += (size_t)h->nhle * sizeof(MtrcNameRow);
    v->sc  = (const MtrcScRow*)q;   q += (size_t)h->nsc  * sizeof(MtrcScRow);
    v->spu = (const MtrcNameRow*)q; q += (size_t)h->nspu * sizeof(MtrcNameRow);
    v->ev  = (const MtrcFileEv*)q;  q += (size_t)h->nev  * sizeof(MtrcFileEv);
    v->str = q; v->strn = (uint32_t)(n - (uint32_t)(q - p));
    return 1;
}

static const char* mt_str(const MtView* v, uint32_t id, char* buf, size_t cap){
    buf[0] = 0;
    if(!id || id > v->h->nstr) return buf;
    const uint8_t* p = v->str; const uint8_t* end = v->str + v->strn;
    for(uint32_t i = 1; i <= id; i++){
        if(p + 2 > end) return buf;
        uint16_t l; memcpy(&l, p, 2); p += 2;
        if(p + l > end) return buf;
        if(i == id){
            size_t n = l < cap - 1 ? l : cap - 1;
            memcpy(buf, p, n); buf[n] = 0;
            return buf;
        }
        p += l;
    }
    return buf;
}

static uint32_t mt_sum(const MtrcNameRow* r, uint32_t n){
    uint32_t s = 0; for(uint32_t i = 0; i < n; i++) s += r[i].us; return s;
}
static uint32_t mt_sum_sc(const MtrcScRow* r, uint32_t n){
    uint32_t s = 0; for(uint32_t i = 0; i < n; i++) s += r[i].us; return s;
}
static int mt_top(const MtrcNameRow* r, uint32_t n){
    int best = -1; uint32_t bu = 0;
    for(uint32_t i = 0; i < n; i++) if(r[i].us > bu){ bu = r[i].us; best = (int)i; }
    return best;
}

static const char* mt_cat_name(uint32_t c){
    switch(c){
    case MTRC_FIFO_DRAIN: return "fifo-drain";
    case MTRC_FIFO_STALL: return "fifo-STALL";
    case MTRC_FIFO_INTR:  return "fifo-intr";
    case MTRC_FIFO_FLIP:  return "flip";
    case MTRC_FS_OPEN:    return "fs-open";
    case MTRC_FS_READ:    return "fs-read";
    case MTRC_FS_SEEK:    return "fs-seek";
    case MTRC_SPU_INTERP: return "spu-interp";
    default:              return "?";
    }
}

static void mt_print(uint32_t idx, const CapFrame* f, const CapFrame* nextf,
                     const MtView* v){
    char nm[96];
    const MtrcHdr* h = v->h;
    uint32_t dt = nextf ? (nextf->t_ms > f->t_ms ? nextf->t_ms - f->t_ms : 0) : 0;
    fprintf(stderr, "[TRACE] frame %u  t=+%ums  frame time %u ms  "
                    "%u draws-records %u patches (%.2f MB)\n",
            idx, f->t_ms, dt, f->nrec, f->npatch, f->patch_bytes / 1048576.0);

    uint32_t spu_us = mt_sum(v->spu, h->nspu);
    fprintf(stderr, "  SPU   %.1f ms   wait %.1f  lock %.1f  resolve %.1f\n",
            spu_us / 1000.0, h->wait_us / 1000.0, h->lock_us / 1000.0,
            h->resolve_us / 1000.0);
    { uint32_t ord[128]; uint32_t no = h->nspu < 128 ? h->nspu : 128;
      for(uint32_t i = 0; i < no; i++) ord[i] = i;
      for(uint32_t i = 0; i < no; i++) for(uint32_t k = i + 1; k < no; k++)
          if(v->spu[ord[k]].us > v->spu[ord[i]].us){
              uint32_t t = ord[i]; ord[i] = ord[k]; ord[k] = t; }
      for(uint32_t j = 0; j < no; j++){
          const MtrcNameRow* r = &v->spu[ord[j]];
          if(r->us < 200) continue;
          mt_str(v, r->str, nm, sizeof nm);
          fprintf(stderr, "          %-16s %7.2f ms  x%u%s\n", nm,
                  r->us / 1000.0, r->calls,
                  strcmp(nm, "INTERP") ? "" : "   <-- no lifted body for this job");
      } }

    uint32_t hle_us = mt_sum(v->hle, h->nhle);
    fprintf(stderr, "  HLE   %.1f ms", hle_us / 1000.0);
    for(uint32_t i = 0; i < h->nhle; i++){
        if(v->hle[i].us < 200) continue;
        mt_str(v, v->hle[i].str, nm, sizeof nm);
        fprintf(stderr, "   %s %.2fms x%u", nm, v->hle[i].us / 1000.0, v->hle[i].calls);
    }
    fputc('\n', stderr);

    uint32_t sc_us = mt_sum_sc(v->sc, h->nsc);
    fprintf(stderr, "  SC    %.1f ms", sc_us / 1000.0);
    for(uint32_t i = 0; i < h->nsc; i++){
        if(v->sc[i].us < 200) continue;
        fprintf(stderr, "   sc%u %.2fms x%u", v->sc[i].num, v->sc[i].us / 1000.0,
                v->sc[i].calls);
    }
    fputc('\n', stderr);

    fprintf(stderr, "  PPU  ");
    for(uint32_t i = 0; i < h->nppu; i++){
        fprintf(stderr, " t%u=sub_%x", v->ppu[i].tid, v->ppu[i].curfn);
        if(v->ppu[i].sc >= 0) fprintf(stderr, "/sc%d", v->ppu[i].sc);
        if(v->ppu[i].str_hle){ mt_str(v, v->ppu[i].str_hle, nm, sizeof nm);
                               fprintf(stderr, "/%s", nm); }
    }
    fputc('\n', stderr);

    for(uint32_t i = 0; i < h->nev; i++){
        const MtrcFileEv* e = &v->ev[i];
        mt_str(v, e->str, nm, sizeof nm);
        switch(e->cat){
        case MTRC_FIFO_DRAIN:
            if(!(e->d >> 16)) continue;
            fprintf(stderr, "  FIFO  +%ums drain io 0x%x->0x%x put=0x%x STALLED\n",
                    e->t_ms, e->a, e->b, e->c);
            break;
        case MTRC_FIFO_STALL:
            fprintf(stderr, "  FIFO  +%ums %s %s off=0x%x want=0x%x  %u ms\n",
                    e->t_ms, mt_cat_name(e->cat), nm, e->b, e->c, e->d);
            break;
        case MTRC_FIFO_FLIP:
            if(e->b < 8) continue;
            fprintf(stderr, "  FIFO  +%ums flip buf=%u waited %u ms for vblank\n",
                    e->t_ms, e->a, e->b);
            break;
        case MTRC_FS_READ:
            fprintf(stderr, "  CRI   +%ums read %-14s off=0x%x nb=0x%x got=0x%x\n",
                    e->t_ms, nm, e->b, e->c, e->d);
            break;
        case MTRC_FS_OPEN:
            fprintf(stderr, "  CRI   +%ums open %-14s fd=%u flags=0x%x\n",
                    e->t_ms, nm, e->a, e->b);
            break;
        default:
            fprintf(stderr, "  %s  +%ums a=0x%x b=0x%x c=0x%x d=0x%x %s\n",
                    mt_cat_name(e->cat), e->t_ms, e->a, e->b, e->c, e->d, nm);
            break;
        }
    }
    if(h->dropped)
        fprintf(stderr, "  (%u events lost to ring overflow)\n", h->dropped);
    fflush(stderr);
}

typedef struct {
    uint64_t polls, fire_new, fire_old, park_new;
    uint64_t premature_new, premature_old;
    uint64_t work_after_fire_new;
    uint64_t ch_polls, ch_fire, ch_premature, ch_skipped_nonblocking;
    uint64_t dma, work, dropped;
    uint32_t line_hits_old[SPD_STRIPES_OLD / 8 + 1];
    uint32_t line_hits_new[SPD_STRIPES_NEW];
    uint8_t  line_mask_old[SPD_STRIPES_OLD / 8 + 1];
    uint8_t  line_mask_new[SPD_STRIPES_NEW];
    uint32_t distinct_lines;
} PollAgg;

#define WORKW 4

typedef struct { const PtHdr* h; const PtEv* ev; } PtView;
static int pt_view(const uint8_t* p, uint32_t n, PtView* v){
    if(!p || n < sizeof(PtHdr)) return 0;
    const PtHdr* h = (const PtHdr*)p;
    if(h->magic != PT_MAGIC) return 0;
    if((uint64_t)sizeof(PtHdr) + (uint64_t)h->nev * sizeof(PtEv) > n) return 0;
    v->h = h; v->ev = (const PtEv*)(p + sizeof(PtHdr));
    return 1;
}

static void pt_scan_frame(const PtView* v, PollAgg* g,
                          SpdLlNew* ln, SpdLlOld* lo, SpdCh* ch,
                          int yat, int pat, int cyat)
{
    const PtHdr* h = v->h;
    g->dropped += h->dropped;
    for(uint32_t i = 0; i < h->nev; i++){
        const PtEv* e = &v->ev[i];
        uint32_t sl = e->slot < PT_SLOTS ? e->slot : 0;
        switch(e->kind){
        case PT_DMA:  g->dma++;  spd_ll_new(&ln[sl],0,0); ln[sl].idle=0; ch[sl].n=0; break;
        case PT_WORK: g->work++; ln[sl].idle=0; ch[sl].n=0; break;
        case PT_PUTLLC: {
            uint32_t so = spd_stripe_old(e->a), sn = spd_stripe_new(e->a);
            g->line_mask_old[spd_stripe_line_old(so)] |= (uint8_t)(1u << (sl & 7));
            g->line_mask_new[spd_stripe_line_new(sn)] |= (uint8_t)(1u << (sl & 7));
            break; }
        case PT_GETLLAR: {
            g->polls++;
            uint32_t so = spd_stripe_old(e->a), sn = spd_stripe_new(e->a);
            uint32_t lold = spd_stripe_line_old(so), lnew = spd_stripe_line_new(sn);
            g->line_hits_old[lold]++; g->line_hits_new[lnew]++;
            g->line_mask_old[lold] |= (uint8_t)(1u << (sl & 7));
            g->line_mask_new[lnew] |= (uint8_t)(1u << (sl & 7));

            uint32_t sN = spd_ll_new(&ln[sl], e->a, e->b);
            uint32_t sO = spd_ll_old(&lo[sl], e->a, e->b);
            int aN = spd_action(sN, yat, pat), aO = spd_action(sO, yat, pat);
            if(aN != SPD_SPIN) g->fire_new++;
            if(aN == SPD_PARK) g->park_new++;
            if(aO != SPD_SPIN) g->fire_old++;

            if(aN != SPD_SPIN || aO != SPD_SPIN){
                int moved = 0, worked = 0, seen = 0;
                for(uint32_t k = i + 1; k < h->nev && seen < WORKW; k++){
                    if(v->ev[k].slot != e->slot) continue;
                    seen++;
                    if(v->ev[k].kind == PT_DMA || v->ev[k].kind == PT_WORK){ worked = 1; break; }
                    if(v->ev[k].kind == PT_GETLLAR && v->ev[k].a == e->a &&
                       v->ev[k].b != e->b){ moved = 1; break; }
                }
                if(aN != SPD_SPIN){ if(moved) g->premature_new++;
                                    if(worked) g->work_after_fire_new++; }
                if(aO != SPD_SPIN && moved) g->premature_old++;
            }
            break; }
        case PT_RCHCNT: {
            g->ch_polls++;
            if(!spd_ch_blocking(e->a)){ g->ch_skipped_nonblocking++; break; }
            uint32_t st = spd_ch(&ch[sl], e->a, e->b);
            if(cyat > 0 && st >= (uint32_t)cyat){
                g->ch_fire++;
                int moved = 0, seen = 0;
                for(uint32_t k = i + 1; k < h->nev && seen < WORKW; k++){
                    if(v->ev[k].slot != e->slot) continue;
                    seen++;
                    if(v->ev[k].kind == PT_RCHCNT && v->ev[k].a == e->a &&
                       v->ev[k].b != e->b){ moved = 1; break; }
                    if(v->ev[k].kind == PT_DMA || v->ev[k].kind == PT_WORK){ moved = 1; break; }
                }
                if(moved) g->ch_premature++;
            }
            break; }
        }
    }
}

static void pt_report(uint32_t a, uint32_t b){
    if(b >= g_nframes) b = g_nframes - 1;
    if(a > b) a = b;
    static PollAgg g; memset(&g, 0, sizeof g);
    static SpdLlNew ln[PT_SLOTS]; static SpdLlOld lo[PT_SLOTS]; static SpdCh ch[PT_SLOTS];
    memset(ln,0,sizeof ln); memset(lo,0,sizeof lo); memset(ch,0,sizeof ch);

    int yat = 16, pat = 64, cyat = 64;
    { const char* e = getenv("PS3_SPU_LLYIELD"); if(e) yat  = atoi(e);
                  e = getenv("PS3_SPU_LLPARK");  if(e) pat  = atoi(e);
                  e = getenv("PS3_SPU_CHYIELD"); if(e) cyat = atoi(e); }

    uint32_t traced = 0;
    for(uint32_t f = a; f <= b; f++){
        const CapFrame* fh = g_frames[f];
        FrameView v; PtView p;
        if(!fh->pt_bytes || !frame_view(fh, &v) || !pt_view(v.pt, fh->pt_bytes, &p)) continue;
        traced++;
        pt_scan_frame(&p, &g, ln, lo, ch, yat, pat, cyat);
    }
    if(!traced){
        fprintf(stderr,
            "\n[REPLAY] no poll trace in frames %u-%u (PS3_CAP_PTRACE=1)\n", a, b);
        return;
    }

    uint32_t lo_lines=0, lo_shared=0, nw_lines=0, nw_shared=0;
    uint32_t lo_hot=0, nw_hot=0;
    for(uint32_t i = 0; i < SPD_STRIPES_OLD/8+1; i++){
        if(g.line_hits_old[i]){ lo_lines++;
            if(g.line_hits_old[i] > lo_hot) lo_hot = g.line_hits_old[i]; }
        uint8_t m = g.line_mask_old[i];
        if(m && (m & (m-1))) lo_shared++;
    }
    for(uint32_t i = 0; i < SPD_STRIPES_NEW; i++){
        if(g.line_hits_new[i]){ nw_lines++;
            if(g.line_hits_new[i] > nw_hot) nw_hot = g.line_hits_new[i]; }
        uint8_t m = g.line_mask_new[i];
        if(m && (m & (m-1))) nw_shared++;
    }

    double P = g.polls ? (double)g.polls : 1.0;
    double C = g.ch_polls ? (double)g.ch_polls : 1.0;
    fprintf(stderr,
"\n================ [POLL] frames %u-%u (%u traced) ================\n"
"  events   %llu GETLLAR  %llu rchcnt  %llu DMA  %llu work-marker  (%llu dropped to the cap)\n",
        a, b, traced,
        (unsigned long long)g.polls, (unsigned long long)g.ch_polls,
        (unsigned long long)g.dma, (unsigned long long)g.work,
        (unsigned long long)g.dropped);
    if(g.dropped)
        fprintf(stderr,
"           (events capped per worker per frame)\n");

    fprintf(stderr,
"\n  lock-line backoff (yield>=%d park>=%d)\n"
"    old single-EA detector   fires on %6.2f%% of polls\n"
"    new idle-scan detector   fires on %6.2f%% of polls   (park %.2f%%)\n"
"    -> the change is worth %+.2f points of idle polls caught\n"
"    false positives: fired then the line moved on its next poll\n"
"      old %llu (%.3f%% of its fires)   new %llu (%.3f%% of its fires)\n"
"    fired then real work within %d events on that worker: new %llu (%.3f%%)\n",
        yat, pat,
        100.0 * (double)g.fire_old / P,
        100.0 * (double)g.fire_new / P,
        100.0 * (double)g.park_new / P,
        100.0 * ((double)g.fire_new - (double)g.fire_old) / P,
        (unsigned long long)g.premature_old,
        g.fire_old ? 100.0*(double)g.premature_old/(double)g.fire_old : 0.0,
        (unsigned long long)g.premature_new,
        g.fire_new ? 100.0*(double)g.premature_new/(double)g.fire_new : 0.0,
        WORKW, (unsigned long long)g.work_after_fire_new,
        g.fire_new ? 100.0*(double)g.work_after_fire_new/(double)g.fire_new : 0.0);

    fprintf(stderr,
"\n  channel-count backoff (yield>=%d)\n"
"    %llu polls, %llu on non-blocking channels SKIPPED by the gate (%.2f%%)\n"
"    fires on %.2f%% of the eligible ones; false positives %llu (%.3f%%)\n",
        cyat, (unsigned long long)g.ch_polls,
        (unsigned long long)g.ch_skipped_nonblocking,
        100.0 * (double)g.ch_skipped_nonblocking / C,
        100.0 * (double)g.ch_fire / C,
        (unsigned long long)g.ch_premature,
        g.ch_fire ? 100.0*(double)g.ch_premature/(double)g.ch_fire : 0.0);

    fprintf(stderr,
"\n  lock stripe table, over the recorded lock-line addresses\n"
"    old  %u/%u cache lines used, %u shared by >1 worker, busiest holds %.1f%% of polls\n"
"    new  %u/%u cache lines used, %u shared by >1 worker, busiest holds %.1f%% of polls\n"
"=========================================================================\n\n",
        lo_lines, (uint32_t)(SPD_STRIPES_OLD/8+1), lo_shared, 100.0*(double)lo_hot/P,
        nw_lines, (uint32_t)SPD_STRIPES_NEW,       nw_shared, 100.0*(double)nw_hot/P);
    fflush(stderr);
}

typedef struct { char name[40]; uint64_t us, calls; } AggRow;

static int agg_find(AggRow* t, int* n, int cap, const char* nm){
    if(!nm[0]) return -1;
    for(int i = 0; i < *n; i++) if(!strcmp(t[i].name, nm)) return i;
    if(*n >= cap) return -1;
    snprintf(t[*n].name, sizeof t[*n].name, "%s", nm);
    t[*n].us = t[*n].calls = 0;
    return (*n)++;
}
static int cmp_u32(const void* a, const void* b){
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}
static void agg_sort(AggRow* t, int n){
    for(int i = 0; i < n; i++) for(int k = i + 1; k < n; k++)
        if(t[k].us > t[i].us){ AggRow tmp = t[i]; t[i] = t[k]; t[k] = tmp; }
}

#define AGGCAP 256
static void mt_report(uint32_t a, uint32_t b, const char* csv){
    if(b >= g_nframes) b = g_nframes - 1;
    if(a > b) a = b;
    uint32_t n = b - a + 1;

    static AggRow spu[AGGCAP], hle[AGGCAP];
    int nspu = 0, nhle = 0;
    uint32_t* dt = (uint32_t*)malloc((size_t)n * 4);
    if(!dt){ fprintf(stderr, "[REPLAY] out of memory for the report\n"); return; }
    uint64_t tot_spu = 0, tot_hle = 0, tot_sc = 0, tot_wait = 0, tot_lock = 0;
    uint64_t tot_patch = 0, tot_rec = 0;
    uint32_t worst[8]; uint32_t worst_dt[8]; int nworst = 0;
    uint32_t traced = 0;
    FILE* cf = NULL;
    if(csv && *csv){
        cf = fopen(csv, "w");
        if(cf) fprintf(cf, "frame,t_ms,dt_ms,records,patches,patch_bytes,"
                           "spu_us,spu_wait_us,spu_lock_us,spu_resolve_us,"
                           "hle_us,sc_us,events,top_spu,top_spu_us,top_hle,top_hle_us\n");
        else fprintf(stderr, "[REPLAY] cannot write %s\n", csv);
    }

    fprintf(stderr, "[REPLAY] analysing frames %u-%u...\n", a, b);
    for(uint32_t f = a; f <= b; f++){
        const CapFrame* fh = g_frames[f];
        const CapFrame* nx = (f + 1 < g_nframes) ? g_frames[f + 1] : NULL;
        uint32_t d = nx && nx->t_ms > fh->t_ms ? nx->t_ms - fh->t_ms : 0;
        dt[f - a] = d;
        tot_patch += fh->patch_bytes; tot_rec += fh->nrec;

        if(nworst < 8){ worst[nworst] = f; worst_dt[nworst] = d; nworst++; }
        else{ int mi = 0;
              for(int i = 1; i < 8; i++) if(worst_dt[i] < worst_dt[mi]) mi = i;
              if(d > worst_dt[mi]){ worst[mi] = f; worst_dt[mi] = d; } }

        FrameView v; MtView m;
        char tspu[40] = "", thle[40] = "";
        uint32_t su = 0, hu = 0, cu = 0, wu = 0, lu = 0, ru = 0, nev = 0;
        uint32_t tsu = 0, thu = 0;
        if(fh->mt_bytes && frame_view(fh, &v) && mt_view(v.mt, fh->mt_bytes, &m)){
            traced++;
            su = mt_sum(m.spu, m.h->nspu);
            hu = mt_sum(m.hle, m.h->nhle);
            cu = mt_sum_sc(m.sc, m.h->nsc);
            wu = m.h->wait_us; lu = m.h->lock_us; ru = m.h->resolve_us;
            nev = m.h->nev;
            tot_spu += su; tot_hle += hu; tot_sc += cu;
            tot_wait += wu; tot_lock += lu;
            char nm[96];
            for(uint32_t i = 0; i < m.h->nspu; i++){
                mt_str(&m, m.spu[i].str, nm, sizeof nm);
                int k = agg_find(spu, &nspu, AGGCAP, nm);
                if(k >= 0){ spu[k].us += m.spu[i].us; spu[k].calls += m.spu[i].calls; }
            }
            for(uint32_t i = 0; i < m.h->nhle; i++){
                mt_str(&m, m.hle[i].str, nm, sizeof nm);
                int k = agg_find(hle, &nhle, AGGCAP, nm);
                if(k >= 0){ hle[k].us += m.hle[i].us; hle[k].calls += m.hle[i].calls; }
            }
            int ti = mt_top(m.spu, m.h->nspu);
            if(ti >= 0){ mt_str(&m, m.spu[ti].str, nm, sizeof nm);
                         snprintf(tspu, sizeof tspu, "%s", nm); tsu = m.spu[ti].us; }
            ti = mt_top(m.hle, m.h->nhle);
            if(ti >= 0){ mt_str(&m, m.hle[ti].str, nm, sizeof nm);
                         snprintf(thle, sizeof thle, "%s", nm); thu = m.hle[ti].us; }
        }
        if(cf) fprintf(cf, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%u,%s,%u\n",
                       f, fh->t_ms, d, fh->nrec, fh->npatch, fh->patch_bytes,
                       su, wu, lu, ru, hu, cu, nev, tspu, tsu, thle, thu);
    }
    if(cf){ fclose(cf); fprintf(stderr, "[REPLAY] per-frame CSV -> %s\n", csv); }

    qsort(dt, n, 4, cmp_u32);
    uint64_t sum = 0; for(uint32_t i = 0; i < n; i++) sum += dt[i];
    fprintf(stderr,
        "\n================ [REPLAY] frames %u-%u (%u frames, %.1f s recorded) ====\n",
        a, b, n, sum / 1000.0);
    fprintf(stderr, "  frame time  mean %.1f  p50 %u  p95 %u  p99 %u  max %u ms"
                    "   (%.1f fps)\n",
            n ? (double)sum / n : 0.0, dt[n / 2], dt[n * 95 / 100],
            dt[n * 99 / 100], dt[n - 1], sum ? n * 1000.0 / (double)sum : 0.0);
    fprintf(stderr, "  per frame   %.2f MB of guest memory changed, %.0f records\n",
            n ? (double)tot_patch / n / 1048576.0 : 0.0,
            n ? (double)tot_rec / n : 0.0);
    if(!traced){
        fprintf(stderr, "  no machine trace in this capture (recorded with "
                        "PS3_CAP_NOTRACE, or by an older build)\n");
        free(dt); return;
    }
    fprintf(stderr, "  guest cost  SPU %.1f ms/f (of which idle wait %.1f, "
                    "lock %.1f)  HLE %.1f ms/f  syscalls %.1f ms/f\n"
                    "              (wall time summed across threads, blocking "
                    "waits included - not CPU time)\n",
            (double)tot_spu / traced / 1000.0, (double)tot_wait / traced / 1000.0,
            (double)tot_lock / traced / 1000.0, (double)tot_hle / traced / 1000.0,
            (double)tot_sc / traced / 1000.0);
    if(a == 0)
        fprintf(stderr, "              frame 0 also carries the recording's own "
                        "base-snapshot stall - ignore it\n");

    agg_sort(spu, nspu); agg_sort(hle, nhle);
    fprintf(stderr, "\n  SPU bodies, summed over all six workers\n");
    for(int i = 0; i < nspu && i < 12; i++){
        if(!spu[i].us) break;
        fprintf(stderr, "    %-18s %8.2f ms/f  %10llu calls%s\n", spu[i].name,
                (double)spu[i].us / traced / 1000.0,
                (unsigned long long)spu[i].calls,
                strcmp(spu[i].name, "INTERP")
                    ? "" : "  <-- ISA interpreter: a hot job has no lifted body");
    }
    fprintf(stderr, "\n  HLE imports\n");
    for(int i = 0; i < nhle && i < 12; i++){
        if(!hle[i].us) break;
        fprintf(stderr, "    %-28s %8.2f ms/f  %10llu calls\n", hle[i].name,
                (double)hle[i].us / traced / 1000.0,
                (unsigned long long)hle[i].calls);
    }
    for(int i = 0; i < nworst; i++) for(int k = i + 1; k < nworst; k++)
        if(worst_dt[k] > worst_dt[i]){
            uint32_t t = worst_dt[i]; worst_dt[i] = worst_dt[k]; worst_dt[k] = t;
            t = worst[i]; worst[i] = worst[k]; worst[k] = t;
        }
    fprintf(stderr, "\n  worst frames (press T on one to see what it was doing)\n    ");
    for(int i = 0; i < nworst; i++) fprintf(stderr, " %u(%ums)", worst[i], worst_dt[i]);
    fprintf(stderr, "\n=========================================================="
                    "==============\n\n");
    fflush(stderr);
    free(dt);
}

typedef struct { uint32_t frame, valid; uint8_t* p; size_t n, cap; } Undo;
static Undo*    g_undo;
static uint32_t g_nundo;

static void undo_reset(void){
    for(uint32_t i = 0; i < g_nundo; i++) g_undo[i].valid = 0;
}
static void undo_put(Undo* u, const void* d, size_t n){
    if(!u) return;
    if(u->n + n > u->cap){
        size_t c = u->cap ? u->cap : 65536;
        while(c < u->n + n) c += c / 2 + 65536;
        uint8_t* np = (uint8_t*)realloc(u->p, c);
        if(!np){ u->valid = 0; return; }
        u->p = np; u->cap = c;
    }
    memcpy(u->p + u->n, d, n); u->n += n;
}
static Undo* undo_begin(uint32_t frame){
    if(!g_nundo) return NULL;
    Undo* u = &g_undo[frame % g_nundo];
    u->frame = frame; u->valid = 1; u->n = 0;
    return u;
}
static Undo* undo_find(uint32_t frame){
    if(!g_nundo) return NULL;
    Undo* u = &g_undo[frame % g_nundo];
    return (u->valid && u->frame == frame) ? u : NULL;
}
static void undo_apply(Undo* u){
    size_t o = 0;
    while(o + 12 <= u->n){
        uint32_t kind, a, b;
        memcpy(&kind, u->p + o, 4); memcpy(&a, u->p + o + 4, 4);
        memcpy(&b, u->p + o + 8, 4); o += 12;
        if(kind == 0){ if(a < g_niopg) g_iopg[a] = b; }
        else{
            if(o + b > u->n) break;
            if((uint64_t)a + b <= g_mem){ memcpy(g_base + a, u->p + o, b); mark_touched(a, b); }
            o += b;
        }
    }
    u->valid = 0;
}

static void apply_mem(const CapFrame* f, const FrameView* v){
    Undo* u = undo_begin(f->index);
    for(uint32_t i = 0; i < f->nio; i++){
        uint32_t pg = v->io[2 * i], ea = v->io[2 * i + 1];
        if(pg >= g_niopg) continue;
        if(u){ uint32_t r[3] = { 0, pg, g_iopg[pg] }; undo_put(u, r, 12); }
        g_iopg[pg] = ea;
    }
    uint64_t off = 0;
    for(uint32_t i = 0; i < f->npatch; i++){
        uint32_t ea = v->dir[2 * i], len = v->dir[2 * i + 1];
        if(off + len > f->patch_bytes) break;
        if((uint64_t)ea + len <= g_mem){
            if(u){ uint32_t r[3] = { 1, ea, len };
                   undo_put(u, r, 12); undo_put(u, g_base + ea, len); }
            memcpy(g_base + ea, v->dat + off, len);
            mark_touched(ea, len);
        }
        off += len;
    }
}

static uint32_t g_pos;
static RsxDispBufCap g_disp_cur[8];

static void load_state(const FrameView* v){
    for(uint32_t i = 0; i < 8; i++){
        const RsxDispBufCap* d = &v->disp[i];
        if(!d->valid) continue;
        if(memcmp(d, &g_disp_cur[i], sizeof *d) == 0) continue;
        g_disp_cur[i] = *d;
        rsx_set_display_buffer(i, d->offset, d->pitch, d->width, d->height);
    }
    memcpy(&g_rsx, v->st, sizeof g_rsx);
    g_vp_instr_epoch++;
}

static int goto_frame(uint32_t k){
    if(k >= g_nframes) k = g_nframes - 1;
    FrameView v; int have = 0;
    if(k > g_pos){
        for(uint32_t f = g_pos + 1; f <= k; f++){
            if(!frame_view(g_frames[f], &v)) return 0;
            apply_mem(g_frames[f], &v);
        }
        have = 1;
    } else if(k < g_pos){
        int have_all = 1;
        for(uint32_t f = g_pos; f > k; f--) if(!undo_find(f)){ have_all = 0; break; }
        if(have_all){
            for(uint32_t f = g_pos; f > k; f--) undo_apply(undo_find(f));
        } else {
            DWORD t0 = GetTickCount();
            fprintf(stderr, "[REPLAY] seeking to frame %u (replaying %u memory "
                            "deltas)...\n", k, k + 1);
            base_restore();
            undo_reset();
            for(uint32_t f = 0; f <= k; f++){
                if(!frame_view(g_frames[f], &v)) return 0;
                apply_mem(g_frames[f], &v);
            }
            have = 1;
            fprintf(stderr, "[REPLAY] seek done in %lu ms\n",
                    (unsigned long)(GetTickCount() - t0));
        }
    }
    g_pos = k;
    if(!have && !frame_view(g_frames[k], &v)) return 0;
    load_state(&v);
    return 1;
}

static int run_frame(void){
    const CapFrame* f = g_frames[g_pos];
    FrameView v;
    if(!frame_view(f, &v)) return 0;
    for(uint32_t i = 0; i < f->nrec; i++){
        uint32_t r[6];
        memcpy(r, v.rec + (size_t)i * 24, 24);
        switch(r[0]){
        case 1: rsx_method(r[1], r[2]); break;
        case 2: rsx_set_display_buffer(r[1], r[2], r[3], r[4], r[5]);
                if(r[1] < 8){ g_disp_cur[r[1]].valid = 1; g_disp_cur[r[1]].offset = r[2];
                              g_disp_cur[r[1]].pitch = r[3]; g_disp_cur[r[1]].width = r[4];
                              g_disp_cur[r[1]].height = r[5]; }
                break;
        case 3: rsx_flip(r[1]); break;
        default:
            fprintf(stderr, "[REPLAY] frame %u: bad record tag %u at #%u\n",
                    f->index, r[0], i);
            return 0;
        }
    }
    uint32_t next = g_pos + 1;
    if(next >= g_nframes) return 1;
    return goto_frame(next);
}

static int keyhit(int vk){ return (GetAsyncKeyState(vk) & 1) != 0; }

int main(int argc, char** argv){
    g_cap_disable = 1;
    const char* path = argc > 1 ? argv[1] : getenv("PS3_REPLAY_FILE");
    if(!path || !*path) path = "out/capture.rsxc";
    const char* range = argc > 2 ? argv[2] : getenv("PS3_REPLAY_RANGE");
    if(!map_file(path)) return 1;

    int v2 = memcmp(g_map, CAP2_MAGIC, 8) == 0;
    if(!v2 && memcmp(g_map, "RSXCAP1", 8) != 0){
        fprintf(stderr, "[REPLAY] %s: not an RSXCAP1/RSXCAP2 capture\n", path);
        return 1;
    }
    uint64_t off;
    uint32_t niopg, ndisp, nblk, blk_shift;
    const RsxState*      base_st;
    const RsxDispBufCap* base_disp;
    uint32_t hdr_nframes = 0, hdr_flags = 0, v1_nrec = 0;

    if(v2){
        const CapHdr2* h = (const CapHdr2*)g_map;
        g_state_size = h->state_size; g_mem = h->mem_size;
        g_local_ea = h->local_ea; g_local_size = h->local_size;
        niopg = h->niopg; ndisp = h->ndisp; nblk = h->nblk; blk_shift = h->blk_shift;
        hdr_nframes = h->nframes; hdr_flags = h->flags;
        off = h->hdr_size;
    } else {
        const CapHdr* h = (const CapHdr*)g_map;
        g_state_size = h->state_size; g_mem = h->mem_size;
        g_local_ea = h->local_ea; g_local_size = h->local_size;
        niopg = h->niopg; ndisp = h->ndisp; nblk = h->nblk; blk_shift = h->blk_shift;
        v1_nrec = h->nrec;
        off = sizeof(CapHdr);
    }
    if(g_state_size != sizeof(RsxState)){
        fprintf(stderr, "[REPLAY] RsxState size mismatch (capture %u, build %u)"
                        " - recapture with the current build\n",
                g_state_size, (uint32_t)sizeof(RsxState));
        return 1;
    }
    if(ndisp != 8 || blk_shift != BLK_SHIFT || !nblk){
        fprintf(stderr, "[REPLAY] unsupported base image (ndisp=%u shift=%u nblk=%u)\n",
                ndisp, blk_shift, nblk);
        return 1;
    }
    g_niopg = niopg;

    base_st   = (const RsxState*)(g_map + off);           off += g_state_size;
    base_disp = (const RsxDispBufCap*)(g_map + off);      off += sizeof(RsxDispBufCap) * 8;
    g_iopg_base = (const uint32_t*)(g_map + off);         off += 4ull * niopg;
    const uint8_t* bm = g_map + off;                      off += (nblk + 7) / 8;
    const uint8_t* blocks = g_map + off;
    if(off > g_mapsz){ fprintf(stderr, "[REPLAY] truncated base image\n"); return 1; }

    if(!base_index(nblk, bm, blocks)){
        fprintf(stderr, "[REPLAY] out of memory indexing %u blocks\n", nblk); return 1; }
    uint32_t npresent = base_present();
    off += (uint64_t)npresent * BLK;
    if(off > g_mapsz){
        fprintf(stderr, "[REPLAY] truncated base blocks (need %llu, file %llu)\n",
                (unsigned long long)off, (unsigned long long)g_mapsz);
        return 1;
    }

    g_base = (uint8_t*)VirtualAlloc(0, g_mem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!g_base){ fprintf(stderr, "[REPLAY] cannot alloc 0x%llx guest bytes\n",
                         (unsigned long long)g_mem); return 1; }
    g_iopg = (uint32_t*)malloc((size_t)niopg * 4);
    if(!g_iopg){ fprintf(stderr, "[REPLAY] out of memory\n"); return 1; }
    memcpy(g_iopg, g_iopg_base, (size_t)niopg * 4);
    base_load_all();
    fprintf(stderr, "[REPLAY] %s: %s, %u/%u blocks (%.0f MB) restored\n", path,
            v2 ? "RSXCAP2" : "RSXCAP1", npresent, nblk,
            (double)npresent * BLK / 1048576.0);

    rsx_init(g_base, g_local_ea, g_local_size, replay_ioff2ea, g_mem);
    for(uint32_t i = 0; i < 8; i++)
        if(base_disp[i].valid){
            g_disp_cur[i] = base_disp[i];
            rsx_set_display_buffer(i, base_disp[i].offset, base_disp[i].pitch,
                                   base_disp[i].width, base_disp[i].height);
        }
    memcpy(&g_rsx, base_st, sizeof g_rsx);
    g_vp_instr_epoch++;

    if(!v2){
        if(!getenv("PS3_RSXSHOT")) _putenv("PS3_RSXSHOT=1");
        const uint8_t* p = g_map + off;
        long n = 0, flips = 0;
        while((uint64_t)(p - g_map) + 24 <= g_mapsz && (!v1_nrec || n < (long)v1_nrec)){
            uint32_t r[6]; memcpy(r, p, 24); p += 24;
            switch(r[0]){
            case 1: rsx_method(r[1], r[2]); break;
            case 2: rsx_set_display_buffer(r[1], r[2], r[3], r[4], r[5]); break;
            case 3: rsx_flip(r[1]); flips++;
                    fprintf(stderr, "[REPLAY] flip %ld presented\n", flips); break;
            default: fprintf(stderr, "[REPLAY] bad record tag %u at #%ld\n", r[0], n);
                     return 1;
            }
            n++;
        }
        fprintf(stderr, "[REPLAY] done: %ld records, %ld flips; see out/rsxshot.bmp\n",
                n, flips);
        const char* hold = getenv("PS3_REPLAY_HOLD");
        Sleep(hold ? (DWORD)atoi(hold) : 300);
        return 0;
    }

    {
        uint32_t cap = 4096, n = 0;
        if(hdr_nframes && hdr_nframes < (1u << 24)) cap = hdr_nframes + 16;
        g_frames = (const CapFrame**)malloc((size_t)cap * sizeof(*g_frames));
        if(!g_frames){ fprintf(stderr, "[REPLAY] out of memory\n"); return 1; }
        uint64_t o = off;
        while(o + sizeof(CapFrame) <= g_mapsz){
            const CapFrame* f = (const CapFrame*)(g_map + o);
            if(f->magic != CAPFRAME_TAG) break;
            if(o + sizeof(CapFrame) + f->comp > g_mapsz) break;
            if(n == cap){
                cap *= 2;
                const CapFrame** np =
                    (const CapFrame**)realloc(g_frames, (size_t)cap * sizeof(*g_frames));
                if(!np){ fprintf(stderr, "[REPLAY] out of memory at frame %u\n", n); break; }
                g_frames = np;
            }
            g_frames[n++] = f;
            o += sizeof(CapFrame) + f->comp;
        }
        g_nframes = n;
        if(hdr_nframes && hdr_nframes != n)
            fprintf(stderr, "[REPLAY] header says %u frames, found %u - the "
                            "recording was cut short; playing what is there\n",
                    hdr_nframes, n);
    }
    if(!g_nframes){ fprintf(stderr, "[REPLAY] no frame chunks in %s\n", path); return 1; }

    uint32_t last = g_frames[g_nframes - 1]->t_ms;
    fprintf(stderr, "[REPLAY] %u frames, %.1f s recorded, %.0f MB, %.2f MB/frame, "
                    "deltas %s\n",
            g_nframes, last / 1000.0, (double)g_mapsz / 1048576.0,
            (double)(g_mapsz - off) / 1048576.0 / (g_nframes ? g_nframes : 1),
            (hdr_flags & 1) ? "write-watch" : "full-compare");

    if(!getenv("PS3_RSXSHOT") && g_nframes <= 2) _putenv("PS3_RSXSHOT=1");

    uint32_t a = 0, b = g_nframes - 1;
    if(range && *range){
        unsigned lo = 0, hi = 0;
        int k = sscanf(range, "%u-%u", &lo, &hi);
        if(k >= 1){ a = lo < g_nframes ? lo : g_nframes - 1;
                    b = (k == 2 && hi < g_nframes) ? hi : g_nframes - 1;
                    if(b < a) b = a; }
    }
    int paused = getenv("PS3_REPLAY_PAUSED") ? 1 : 0;
    int loop = g_nframes > 2;
    if(getenv("PS3_REPLAY_LOOP")) loop = 1;
    if(getenv("PS3_REPLAY_ONCE")) loop = 0;
    double speed = 1.0;
    { const char* e = getenv("PS3_REPLAY_SPEED"); if(e){ double s = atof(e); if(s >= 0) speed = s; } }
    g_nundo = (uint32_t)((getenv("PS3_REPLAY_UNDO")
                          ? atol(getenv("PS3_REPLAY_UNDO")) : 45));
    if(g_nundo > 4096) g_nundo = 4096;
    if(g_nundo) g_undo = (Undo*)calloc(g_nundo, sizeof(Undo));

    { const char* tf = getenv("PS3_REPLAY_TRACEFRAME");
      if(tf){
          uint32_t k = (uint32_t)atol(tf);
          if(k >= g_nframes) k = g_nframes - 1;
          FrameView tv; MtView tm; const CapFrame* fh = g_frames[k];
          if(fh->mt_bytes && frame_view(fh, &tv) && mt_view(tv.mt, fh->mt_bytes, &tm))
              mt_print(k, fh, k + 1 < g_nframes ? g_frames[k + 1] : NULL, &tm);
          else fprintf(stderr, "[TRACE] frame %u has no machine trace\n", k);
      } }

    { const char* rep = getenv("PS3_REPLAY_REPORT");
      if(rep || getenv("PS3_REPLAY_NOPLAY") || getenv("PS3_REPLAY_POLLREPORT")){
          if(rep || getenv("PS3_REPLAY_NOPLAY")) mt_report(a, b, rep);
          if(getenv("PS3_REPLAY_POLLREPORT") || getenv("PS3_REPLAY_NOPLAY"))
              pt_report(a, b);
          if(getenv("PS3_REPLAY_NOPLAY")) return 0;
      } }

    fprintf(stderr,
        "[REPLAY] Space pause | <- -> step | Up/Down +-1s | PgUp/PgDn +-10s | "
        "Home/End | L loop | [ ] range | +/- speed | 0 realtime | S shot | "
        "T trace | P profile | O polls | R reload | Esc\n");

    g_pos = 0;
    if(a && !goto_frame(a)) return 1;

    LARGE_INTEGER qpf; QueryPerformanceFrequency(&qpf);
    LONGLONG prev_host = 0; uint32_t prev_tms = 0; int pacing = 0;
    DWORD title_t = 0; long loops = 0;
    int started = 0;

    for(;;){
        if(started && rsxvk_has_focus()){
            if(keyhit(VK_ESCAPE)) break;
            if(keyhit(VK_SPACE)){ paused = !paused; pacing = 0; }
            if(keyhit('L'))      loop = !loop;
            if(keyhit('S'))      rsxd_shot_request();
            if(keyhit('C')){ a = 0; b = g_nframes - 1; }
            if(keyhit(VK_OEM_4)){ a = g_pos; if(b < a) b = g_nframes - 1; }
            if(keyhit(VK_OEM_6)){ b = g_pos; if(b < a) a = 0; }
            if(keyhit(VK_OEM_PLUS)  || keyhit(VK_ADD))      { speed = speed ? speed * 2 : 8; if(speed > 16) speed = 0; }
            if(keyhit(VK_OEM_MINUS) || keyhit(VK_SUBTRACT)) { speed = speed ? speed / 2 : 16; if(speed < 0.125) speed = 0.125; }
            if(keyhit('0')) speed = 1.0;
            if(keyhit('R')){ goto_frame(a); paused = 0; pacing = 0; }
            if(keyhit('T')){
                FrameView tv; MtView tm;
                const CapFrame* tf = g_frames[g_pos];
                if(!tf->mt_bytes)
                    fprintf(stderr, "[TRACE] frame %u has no machine trace\n", g_pos);
                else if(frame_view(tf, &tv) && mt_view(tv.mt, tf->mt_bytes, &tm))
                    mt_print(g_pos, tf,
                             g_pos + 1 < g_nframes ? g_frames[g_pos + 1] : NULL, &tm);
            }
            if(keyhit('P')) mt_report(a, b, NULL);
            if(keyhit('O')) pt_report(a, b);

            int jump = 0;
            if(keyhit(VK_RIGHT)){ paused = 1; if(!run_frame()) break; pacing = 0; }
            if(keyhit(VK_LEFT )){ paused = 1; jump = -1; }
            if(keyhit(VK_UP   )) jump =  60;
            if(keyhit(VK_DOWN )) jump = -60;
            if(keyhit(VK_PRIOR)) jump =  600;
            if(keyhit(VK_NEXT )) jump = -600;
            if(keyhit(VK_HOME)){ jump = 0; if(!goto_frame(a)) break; pacing = 0; }
            if(keyhit(VK_END )){ jump = 0; if(!goto_frame(b)) break; pacing = 0; }
            if(jump){
                long t = (long)g_pos + jump;
                if(t < (long)a) t = a;
                if(t > (long)b) t = b;
                if(!goto_frame((uint32_t)t)) break;
                pacing = 0;
            }
        }

        DWORD now = GetTickCount();
        if(now - title_t > 200){
            title_t = now;
            char t[192], sp[16];
            if(speed == 0) snprintf(sp, sizeof sp, "max");
            else           snprintf(sp, sizeof sp, "%gx", speed);
            snprintf(t, sizeof t,
                     "rsxreplay  frame %u/%u  [%u-%u]  %s  %s  %s  loops=%ld",
                     g_pos, g_nframes - 1, a, b, paused ? "PAUSED" : "play",
                     loop ? "loop" : "once", sp, loops);
            rsxvk_set_title(t);
        }

        if(paused && started){ rsxvk_pump_tick(); Sleep(8); continue; }

        uint32_t tms = g_frames[g_pos]->t_ms;
        LARGE_INTEGER q; QueryPerformanceCounter(&q);
        if(pacing && speed > 0 && tms >= prev_tms){
            double want = (double)(tms - prev_tms) / speed;
            double have = (double)(q.QuadPart - prev_host) * 1000.0 / (double)qpf.QuadPart;
            if(want > have){
                double d = want - have;
                if(d > 500) d = 500;
                Sleep((DWORD)d);
                QueryPerformanceCounter(&q);
            }
        }
        prev_tms = tms; prev_host = q.QuadPart; pacing = 1;

        uint32_t was = g_pos;
        if(!run_frame()) break;
        started = 1;
        if(g_pos > b || g_pos == was){
            loops++;
            if(!loop) break;
            if(!goto_frame(a)) break;
            pacing = 0;
        }
    }

    fprintf(stderr, "[REPLAY] stopped at frame %u after %ld pass%s\n",
            g_pos, loops, loops == 1 ? "" : "es");
    const char* hold = getenv("PS3_REPLAY_HOLD");
    Sleep(hold ? (DWORD)atoi(hold) : 300);
    return 0;
}
