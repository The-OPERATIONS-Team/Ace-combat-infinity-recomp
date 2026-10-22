#pragma once
#include <stdint.h>

#define GCM_LOCATION_LOCAL   0
#define GCM_LOCATION_MAIN    1
#define GCM_CLEAR_Z 0x01
#define GCM_CLEAR_S 0x02
#define GCM_CLEAR_R 0x10
#define GCM_CLEAR_G 0x20
#define GCM_CLEAR_B 0x40
#define GCM_CLEAR_A 0x80

typedef struct { uint32_t offset, pitch, location; } RsxSurfaceRT;
typedef struct { uint32_t offset, format, address, control0, control1,
                          control2, control3, filter, image_rect, border_color; } RsxTexture;
typedef struct { uint32_t offset, format; } RsxVtxArray;

typedef struct {
    RsxSurfaceRT color[4];
    RsxSurfaceRT zeta;
    uint32_t surface_format;
    uint32_t color_target;
    uint32_t clip_h, clip_v;
    uint32_t window_offset;
    uint32_t ctx_dma_color[4], ctx_dma_zeta, ctx_dma_report;
    uint32_t shader_window;

    uint32_t color_mask, color_mask_mrt, blend_enable_mrt;
    uint32_t depth_test, depth_func, depth_mask;
    uint32_t depth_bounds_en; float depth_bounds_min, depth_bounds_max;
    float    clip_min, clip_max;
    uint32_t alpha_test, alpha_func, alpha_ref;
    uint32_t blend_enable, blend_sfactor, blend_dfactor, blend_eq;
    uint32_t blend_color, blend_color2;
    uint32_t stencil_test, stencil_mask, stencil_func, stencil_ref, stencil_fmask;
    uint32_t stencil_fail, stencil_zfail, stencil_zpass;
    uint32_t stencil2_test, bstencil_mask, bstencil_func, bstencil_ref, bstencil_fmask;
    uint32_t bstencil_fail, bstencil_zfail, bstencil_zpass;
    uint32_t logic_op_en, logic_op, dither, shade_mode;
    uint32_t cull_enable, cull_face, front_face;
    uint32_t front_poly_mode, back_poly_mode;
    uint32_t poly_offs_fill, poly_offs_line, poly_offs_point;
    float    poly_offs_scale, poly_offs_bias;
    uint32_t line_width, line_smooth;
    uint32_t scissor_h, scissor_v;
    uint32_t viewport_h, viewport_v;
    float    vp_scale[4], vp_offset[4];
    uint32_t zmin_max_control, aa_control, aniso_spread[16];
    uint32_t fog_mode; float fog_params[2];
    uint32_t user_clip_control;
    uint32_t point_size_u32, point_sprite, point_params_en, point_center;
    uint32_t control0;
    uint32_t two_side_light, specular_en, flat_shade_op;
    uint32_t cylindrical_wrap[2], reduce_dst_color;

    uint32_t clear_color, clear_zstencil, clear_rect_h, clear_rect_v;

    RsxVtxArray vtx[16];
    uint32_t vtx_base_off, vtx_base_idx;
    uint32_t index_addr, index_dma;
    uint32_t freq_div_op;
    uint32_t restart_en, restart_idx;
    uint32_t edge_flag;
    uint32_t prim;
    uint32_t imm4f[16][4];

    uint32_t vp_instr[512][4];
    uint32_t vp_load_slot, vp_cursor;
    uint32_t vp_start;
    float    vp_const[468][4];
    uint32_t vp_const_stamp[468];
    uint32_t draw_serial;
    uint32_t vp_const_load, vp_const_cursor;
    uint32_t vp_in_mask, vp_out_mask, vp_timeout, vp_branch_bits, vp_exec_mode;

    uint32_t fp_offset_raw;
    uint32_t fp_control;
    uint32_t shader_packer;
    uint32_t tex_coord_control[10];
    uint32_t indexed_const_limits;

    RsxTexture tex[16];
    RsxTexture vtex[4];
    uint32_t color_key[16];

    uint32_t render_enable;
    uint32_t zpass_count_en, zcull_stats_en, zcull_en;
    uint32_t zcull_control0, zcull_control1, scull_control;

    struct { uint32_t dma_in, dma_out, off_in, off_out;
             uint32_t pitch_in, pitch_out, line_len, line_cnt, format; } m2m;
    struct { uint32_t dst_dma, src_dma, format, pitch, off_src, off_dst; } s2d;
    struct { uint32_t src_dma, surface_ctx, conv, format, op;
             uint32_t clip_pt, clip_sz, out_pt, out_sz, ds_dx, dt_dy;
             uint32_t in_sz, in_fmt, in_off, in_pt; } blit;
    struct { uint32_t dma, format, offset; } swz;
    struct { uint32_t surface_ctx, format, point, size_out, size_in, idx; } i2d;
} RsxState;

extern RsxState g_rsx;

extern uint32_t g_vp_const_epoch;
extern uint32_t g_vp_instr_epoch;
