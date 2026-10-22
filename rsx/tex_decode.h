#pragma once
#include <stdint.h>

#define GCM_TEX_FMT(f)   ((f)&0x9f)
#define GCM_TEX_LN(f)    (((f)&0x20)!=0)

int tex_decode_level(const uint8_t* src, uint32_t* dst,
                     uint32_t fmt_byte, uint32_t w, uint32_t h, uint32_t pitch);

uint32_t tex_bpp(uint32_t fmt_byte);
int      tex_is_dxt(uint32_t fmt_byte);

uint32_t tex_level_bytes(uint32_t fmt_byte, uint32_t w, uint32_t h,
                         uint32_t d, uint32_t pitch);
uint32_t tex_cube_face_stride(uint32_t fmt_byte, uint32_t w, uint32_t h,
                              uint32_t nmip, uint32_t pitch);
uint32_t tex_total_bytes(uint32_t fmt_byte, uint32_t w, uint32_t h, uint32_t d,
                         uint32_t nmip, int cube, uint32_t pitch);
