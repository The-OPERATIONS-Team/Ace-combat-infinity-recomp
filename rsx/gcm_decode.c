#include "rsx.h"
#include "gcm_state.h"
#include "vk_draw.h"
#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

RsxState g_rsx;
uint32_t g_vp_const_epoch;

#include "gcm_method_names.inl"
#define NNAMES (sizeof gcm_method_names / sizeof gcm_method_names[0])

static const char* mth_name(uint32_t m, uint32_t* delta){
    int lo=0, hi=(int)NNAMES-1, best=0;
    while(lo<=hi){ int mid=(lo+hi)/2;
        if(gcm_method_names[mid].off<=m){ best=mid; lo=mid+1; } else hi=mid-1; }
    if(delta) *delta=m-gcm_method_names[best].off;
    return gcm_method_names[best].name;
}

static float f32(uint32_t u){ float f; memcpy(&f,&u,4); return f; }

static int g_trace=-1;
static uint32_t g_hist[NNAMES];
static uint32_t g_unk[64]; static int g_nunk;
static uint32_t g_ev_draws, g_ev_clears, g_ev_blits, g_ev_m2m, g_ev_inline;

static void trace_count(uint32_t m){
    int lo=0, hi=(int)NNAMES-1, best=0;
    while(lo<=hi){ int mid=(lo+hi)/2;
        if(gcm_method_names[mid].off<=m){ best=mid; lo=mid+1; } else hi=mid-1; }
    g_hist[best]++;
}

void rsx_decode_frame_mark(void){
    if(g_trace<0) g_trace=getenv("PS3_RSXTRACE")?1:0;
    if(!g_trace) return;
    static long frame; frame++;
    if(frame>3 && (frame&63)!=0){ memset(g_hist,0,sizeof g_hist);
        g_ev_draws=g_ev_clears=g_ev_blits=g_ev_m2m=g_ev_inline=0; return; }
    fprintf(stderr,"[RSXTRACE] frame %ld: draws=%u clears=%u blits=%u m2m=%u inline=%u\n",
            frame,g_ev_draws,g_ev_clears,g_ev_blits,g_ev_m2m,g_ev_inline);
    for(unsigned i=0;i<NNAMES;i++) if(g_hist[i])
        fprintf(stderr,"  %-44s %6u  (0x%04x)\n",
                gcm_method_names[i].name,g_hist[i],gcm_method_names[i].off);
    if(g_nunk){
        fprintf(stderr,"[RSXTRACE] UNKNOWN methods this run:");
        for(int i=0;i<g_nunk;i++) fprintf(stderr," 0x%04x",g_unk[i]);
        fprintf(stderr,"\n");
    }
    memset(g_hist,0,sizeof g_hist);
    g_ev_draws=g_ev_clears=g_ev_blits=g_ev_m2m=g_ev_inline=0;
}

static void unknown_method(uint32_t m, uint32_t arg){
    for(int i=0;i<g_nunk;i++) if(g_unk[i]==m) return;
    if(g_nunk<64) g_unk[g_nunk++]=m;
    uint32_t d; const char* nm=mth_name(m,&d);
    fprintf(stderr,"[RSX] UNKNOWN method 0x%04x arg=0x%08x (nearest %s+0x%x) - "
            "grep gcm_macros.h\n",m,arg,nm,d);
}

void rsx_method(uint32_t m, uint32_t arg){
    if(g_cap_recording) cap_method(m,arg);
    RsxState* s=&g_rsx;
    if(g_trace<0) g_trace=getenv("PS3_RSXTRACE")?1:0;
    if(g_trace) trace_count(m);

    if(m>=0x0b80&&m<0x0c00){
        uint32_t w=s->vp_cursor;
        if(w<512*4){ s->vp_instr[w>>2][w&3]=arg; }
        s->vp_cursor=w+1; return;
    }
    if(m>=0x1f00&&m<0x1f80){
        uint32_t w=s->vp_const_cursor;
        if(w<468*4){ ((uint32_t*)s->vp_const)[w]=arg;
                     s->vp_const_stamp[w>>2]=s->draw_serial;
                     g_vp_const_epoch++; }
        { static int lo=-2, hi;
          if(lo==-2){ const char* e=getenv("PS3_RSX_CONSTLOG");
              lo=-1; if(e){ lo=atoi(e); const char* d=strchr(e,'-');
                            hi=d?atoi(d+1):lo; } }
          if(lo>=0){ uint32_t ci=w>>2;
              if((int)ci>=lo&&(int)ci<=hi){ float f; memcpy(&f,&arg,4);
                  fprintf(stderr,"[CONSTLOG] c[%u].%c = %g (0x%08x) cursor=%u\n",
                          ci,"xyzw"[w&3],f,arg,w); } } }
        s->vp_const_cursor=w+1; return;
    }
    if(m>=0x1a00&&m<0x1c00){
        RsxTexture* t=&s->tex[(m-0x1a00)>>5];
        switch((m>>2)&7){
        case 0: t->offset=arg; break;      case 1: t->format=arg; break;
        case 2: t->address=arg; break;     case 3: t->control0=arg; break;
        case 4: t->control1=arg; break;    case 5: t->filter=arg; break;
        case 6: t->image_rect=arg; break;  case 7: t->border_color=arg; break;
        }
        return;
    }
    if(m>=0x0900&&m<0x0980){
        RsxTexture* t=&s->vtex[(m-0x0900)>>5];
        switch((m>>2)&7){
        case 0: t->offset=arg; break;      case 1: t->format=arg; break;
        case 2: t->address=arg; break;     case 3: t->control0=arg; break;
        case 4: t->control3=arg; break;    case 5: t->filter=arg; break;
        case 6: t->image_rect=arg; break;  case 7: t->border_color=arg; break;
        }
        return;
    }
    if(m>=0x1840&&m<0x1880){ s->tex[(m-0x1840)>>2].control3=arg; return; }
    if(m>=0x0b00&&m<0x0b40){ s->tex[(m-0x0b00)>>2].control2=arg; return; }
    if(m>=0x0b40&&m<0x0b68){ s->tex_coord_control[(m-0x0b40)>>2]=arg; return; }
    if(m>=0x1680&&m<0x16c0){ s->vtx[(m-0x1680)>>2].offset=arg; return; }
    if(m>=0x1740&&m<0x1780){ s->vtx[(m-0x1740)>>2].format=arg; return; }
    if(m>=0x1d00&&m<0x1d40){ s->color_key[(m-0x1d00)>>2]=arg; return; }
    if(m>=0x03c0&&m<0x0400){ s->aniso_spread[(m-0x03c0)>>2]=arg; return; }
    if(m>=0x1c00&&m<0x1d00){ s->imm4f[(m-0x1c00)>>4][(m>>2)&3]=arg; return; }
    if(m>=0x1500&&m<0x1600) return;
    if(m>=0x1880&&m<0x1900) return;
    if(m>=0x1900&&m<0x1940) return;
    if(m>=0x1940&&m<0x1980) return;
    if(m>=0x1980&&m<0x1a00) return;
    if(m>=0x1e40&&m<0x1e80) return;
    if(m>=0x0a80&&m<0x0b00) return;
    if(m>=0x1480&&m<0x1500) return;
    if(m>=0xa400&&m<0xa800){ g_ev_inline++; rsxd_i2d_word(arg); return; }

    switch(m){
    case 0x0000: case 0x0100: case 0x0104: case 0x0110: case 0x0140:
    case 0x0060: case 0x0180: case 0x0184: case 0x0188: case 0x0190:
    case 0x019c: case 0x01a0: case 0x01a4: case 0x01ac: case 0x01b0:
    case 0x1710: case 0x1714: case 0x1718: case 0x1fd8:
    case 0x2000: case 0x2180: case 0x6000: case 0x6180: case 0x8000:
    case 0x8180: case 0xa000: case 0xa180: case 0xc000: case 0xc180:
    case 0xc188: case 0xc18c: case 0xc190: case 0xc194:
    case 0xa184: case 0xa188: case 0xa18c: case 0xa190: case 0xa194: case 0xa198:
    case 0x0a1c: case 0x0234: case 0x1438: case 0x1450: case 0x1ef8:
        break;
    case 0x1fe8: case 0x1fec: s->shader_packer=arg; break;

    case 0x0194: s->ctx_dma_color[0]=arg; break;
    case 0x018c: s->ctx_dma_color[1]=arg; break;
    case 0x01b4: s->ctx_dma_color[2]=arg; break;
    case 0x01b8: s->ctx_dma_color[3]=arg; break;
    case 0x0198: s->ctx_dma_zeta=arg; break;
    case 0x01a8: s->ctx_dma_report=arg; break;
    case 0x0200: s->clip_h=arg; break;
    case 0x0204: s->clip_v=arg; break;
    case 0x0208: s->surface_format=arg; break;
    case 0x020c: s->color[0].pitch=arg; break;
    case 0x0210: s->color[0].offset=arg; break;
    case 0x0214: s->zeta.offset=arg; break;
    case 0x0218: s->color[1].offset=arg; break;
    case 0x021c: s->color[1].pitch=arg; break;
    case 0x0220: s->color_target=arg; break;
    case 0x022c: s->zeta.pitch=arg; break;
    case 0x0280: s->color[2].pitch=arg; break;
    case 0x0284: s->color[3].pitch=arg; break;
    case 0x0288: s->color[2].offset=arg; break;
    case 0x028c: s->color[3].offset=arg; break;
    case 0x02b8: s->window_offset=arg; break;
    case 0x02bc: case 0x02c0: case 0x02c4: break;
    case 0x1d80: break;
    case 0x1d88: s->shader_window=arg; break;
    case 0x0238: s->cylindrical_wrap[0]=arg; break;
    case 0x023c: s->cylindrical_wrap[1]=arg; break;

    case 0x0300: s->dither=arg; break;
    case 0x0304: s->alpha_test=arg; break;
    case 0x0308: s->alpha_func=arg; break;
    case 0x030c: s->alpha_ref=arg; break;
    case 0x0310: s->blend_enable=arg; break;
    case 0x0314: s->blend_sfactor=arg; break;
    case 0x0318: s->blend_dfactor=arg; break;
    case 0x031c: s->blend_color=arg; break;
    case 0x0320: s->blend_eq=arg; break;
    case 0x0324: s->color_mask=arg;
        { static long cmn; if(getenv("PS3_RSX_CMASKDBG")&&++cmn<=64)
            fprintf(stderr,"[GCMDEC] color_mask=0x%08x\n",arg); }
        break;
    case 0x0328: s->stencil_test=arg; break;
    case 0x032c: s->stencil_mask=arg; break;
    case 0x0330: s->stencil_func=arg; break;
    case 0x0334: s->stencil_ref=arg; break;
    case 0x0338: s->stencil_fmask=arg; break;
    case 0x033c: s->stencil_fail=arg; break;
    case 0x0340: s->stencil_zfail=arg; break;
    case 0x0344: s->stencil_zpass=arg; break;
    case 0x0348: s->stencil2_test=arg; break;
    case 0x034c: s->bstencil_mask=arg; break;
    case 0x0350: s->bstencil_func=arg; break;
    case 0x0354: s->bstencil_ref=arg; break;
    case 0x0358: s->bstencil_fmask=arg; break;
    case 0x035c: s->bstencil_fail=arg; break;
    case 0x0360: s->bstencil_zfail=arg; break;
    case 0x0364: s->bstencil_zpass=arg; break;
    case 0x0368: s->shade_mode=arg; break;
    case 0x036c: s->blend_enable_mrt=arg; break;
    case 0x0370: s->color_mask_mrt=arg; break;
    case 0x0374: s->logic_op_en=arg; break;
    case 0x0378: s->logic_op=arg; break;
    case 0x037c: s->blend_color2=arg; break;
    case 0x0380: s->depth_bounds_en=arg; break;
    case 0x0384: s->depth_bounds_min=f32(arg); break;
    case 0x0388: s->depth_bounds_max=f32(arg); break;
    case 0x0394: s->clip_min=f32(arg); break;
    case 0x0398: s->clip_max=f32(arg); break;
    case 0x03b0: s->control0=arg; break;
    case 0x03b8: s->line_width=arg; break;
    case 0x03bc: s->line_smooth=arg; break;
    case 0x08c0: s->scissor_h=arg; break;
    case 0x08c4: s->scissor_v=arg; break;
    case 0x08cc: s->fog_mode=arg; break;
    case 0x08d0: s->fog_params[0]=f32(arg); break;
    case 0x08d4: s->fog_params[1]=f32(arg); break;
    case 0x0a00: s->viewport_h=arg; break;
    case 0x0a04: s->viewport_v=arg; break;
    case 0x0a0c: s->point_center=arg; break;
    case 0x0a20: case 0x0a24: case 0x0a28: case 0x0a2c:
        s->vp_offset[(m-0x0a20)>>2]=f32(arg); break;
    case 0x0a30: case 0x0a34: case 0x0a38: case 0x0a3c:
        s->vp_scale[(m-0x0a30)>>2]=f32(arg); break;
    case 0x0a60: s->poly_offs_point=arg; break;
    case 0x0a64: s->poly_offs_line=arg; break;
    case 0x0a68: s->poly_offs_fill=arg; break;
    case 0x0a6c: s->depth_func=arg; break;
    case 0x0a70: s->depth_mask=arg; break;
    case 0x0a74: s->depth_test=arg; break;
    case 0x0a78: s->poly_offs_scale=f32(arg); break;
    case 0x0a7c: s->poly_offs_bias=f32(arg); break;
    case 0x1428: s->specular_en=arg; break;
    case 0x142c: s->two_side_light=arg; break;
    case 0x1454: s->flat_shade_op=arg; break;
    case 0x145c: s->edge_flag=arg; break;
    case 0x1478: s->user_clip_control=arg; break;
    case 0x147c: break;
    case 0x1828: s->front_poly_mode=arg; break;
    case 0x182c: s->back_poly_mode=arg; break;
    case 0x1830: s->cull_face=arg; break;
    case 0x1834: s->front_face=arg; break;
    case 0x1838: break;
    case 0x183c: s->cull_enable=arg; break;
    case 0x1d78: s->zmin_max_control=arg; break;
    case 0x1d7c: s->aa_control=arg; break;
    case 0x1da4: break;
    case 0x1db4: case 0x1db8: break;
    case 0x1ee0: s->point_size_u32=arg; break;
    case 0x1ee4: s->point_params_en=arg; break;
    case 0x1ee8: s->point_sprite=arg; break;
    case 0x1fe0: s->reduce_dst_color=arg; break;
    case 0x1fc4: case 0x1fc8: case 0x1fcc: case 0x1fd0: case 0x1fd4: break;

    case 0x1d8c: s->clear_zstencil=arg; break;
    case 0x1d90: s->clear_color=arg; break;
    case 0x1d94: g_ev_clears++; rsxd_clear(arg); break;
    case 0x1d98: s->clear_rect_h=arg; break;
    case 0x1d9c: s->clear_rect_v=arg; break;

    case 0x1738: s->vtx_base_off=arg; break;
    case 0x173c: s->vtx_base_idx=arg; break;
    case 0x17c8: break;
    case 0x17cc: s->zpass_count_en=arg; break;
    case 0x1800: rsxd_report(arg); break;
    case 0x1804: s->zcull_stats_en=arg; break;
    case 0x1808:
        if(arg){ s->prim=arg; rsxd_begin(arg); }
        else   { s->prim=0;   rsxd_end(); }
        break;
    case 0x180c: case 0x1810:
        { static int wn; if(wn++<8)
            fprintf(stderr,"[RSX] ARRAY_ELEMENT16/32 not implemented (m=0x%x)\n",m); }
        break;
    case 0x1814: g_ev_draws++; rsxd_draw_arrays(arg); break;
    case 0x1818: g_ev_draws++; rsxd_inline_word(arg); break;
    case 0x181c: s->index_addr=arg; break;
    case 0x1820: s->index_dma=arg; break;
    case 0x1824: g_ev_draws++; rsxd_draw_index(arg); break;
    case 0x1dac: s->restart_en=arg; break;
    case 0x1db0: s->restart_idx=arg; break;
    case 0x1fc0: s->freq_div_op=arg; break;

    case 0x1e94: s->vp_exec_mode=arg; break;
    case 0x1e98: s->render_enable=arg; break;
    case 0x1e9c: s->vp_load_slot=arg; s->vp_cursor=arg*4; break;
    case 0x1ea0: s->vp_start=arg; break;
    case 0x1ea4: s->zcull_control0=arg; break;
    case 0x1ea8: s->zcull_control1=arg; break;
    case 0x1eac: s->scull_control=arg; break;
    case 0x1efc: s->vp_const_load=arg; s->vp_const_cursor=arg*4;
        { static int lo=-2; if(lo==-2){ const char* e=getenv("PS3_RSX_CONSTLOG");
              lo=e?1:-1; }
          if(lo>0) fprintf(stderr,"[CONSTLOG] LOAD c[%u] (cursor=%u)\n",
                           arg,s->vp_const_cursor); }
        break;
    case 0x1ff0: s->vp_in_mask=arg; break;
    case 0x1ff4: s->vp_out_mask=arg; break;
    case 0x1ff8: s->vp_branch_bits=arg; break;
    case 0x1d64: s->indexed_const_limits=arg; break;

    case 0x08e4: s->fp_offset_raw=arg; break;
    case 0x1d60: s->fp_control=arg; break;

    case 0x1d84: s->zcull_en=arg; break;

    case 0x2184: s->m2m.dma_in=arg; break;
    case 0x2188: s->m2m.dma_out=arg; break;
    case 0x230c: s->m2m.off_in=arg; break;
    case 0x2310: s->m2m.off_out=arg; break;
    case 0x2314: s->m2m.pitch_in=arg; break;
    case 0x2318: s->m2m.pitch_out=arg; break;
    case 0x231c: s->m2m.line_len=arg; break;
    case 0x2320: s->m2m.line_cnt=arg; break;
    case 0x2324: s->m2m.format=arg; break;
    case 0x2328: g_ev_m2m++; rsxd_m2m(); break;

    case 0x6184: s->s2d.src_dma=arg; break;
    case 0x6188: s->s2d.dst_dma=arg; break;
    case 0x6300: s->s2d.format=arg; break;
    case 0x6304: s->s2d.pitch=arg; break;
    case 0x6308: s->s2d.off_src=arg; break;
    case 0x630c: s->s2d.off_dst=arg; break;

    case 0x8184: s->swz.dma=arg; break;
    case 0x8300: s->swz.format=arg; break;
    case 0x8304: s->swz.offset=arg; break;

    case 0xa19c: s->i2d.surface_ctx=arg; break;
    case 0xa2f8: case 0xa2fc: break;
    case 0xa300: s->i2d.format=arg; break;
    case 0xa304: s->i2d.point=arg; s->i2d.idx=0; break;
    case 0xa308: s->i2d.size_out=arg; break;
    case 0xa30c: s->i2d.size_in=arg; break;

    case 0xc184: s->blit.src_dma=arg; break;
    case 0xc198: s->blit.surface_ctx=arg; break;
    case 0xc2fc: s->blit.conv=arg; break;
    case 0xc300: s->blit.format=arg; break;
    case 0xc304: s->blit.op=arg; break;
    case 0xc308: s->blit.clip_pt=arg; break;
    case 0xc30c: s->blit.clip_sz=arg; break;
    case 0xc310: s->blit.out_pt=arg; break;
    case 0xc314: s->blit.out_sz=arg; break;
    case 0xc318: s->blit.ds_dx=arg; break;
    case 0xc31c: s->blit.dt_dy=arg; break;
    case 0xc400: s->blit.in_sz=arg; break;
    case 0xc404: s->blit.in_fmt=arg; break;
    case 0xc408: s->blit.in_off=arg; break;
    case 0xc40c: g_ev_blits++; rsxd_blit(); break;

    default: unknown_method(m,arg); break;
    }
}
