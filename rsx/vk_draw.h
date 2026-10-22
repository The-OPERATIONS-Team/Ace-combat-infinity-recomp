#pragma once
#include <stdint.h>

void rsxd_begin(uint32_t prim);
void rsxd_end(void);
void rsxd_draw_arrays(uint32_t arg);
void rsxd_draw_index(uint32_t arg);
void rsxd_inline_word(uint32_t arg);
void rsxd_clear(uint32_t mask);
void rsxd_m2m(void);
void rsxd_blit(void);
void rsxd_report(uint32_t arg);
void rsxd_i2d_word(uint32_t arg);

int rsxd_flip_present(uint32_t disp_ea, uint32_t w, uint32_t h);

extern int g_shot_req;
static inline void rsxd_shot_request(void){ g_shot_req = 1; }

void rsxd_bench_reset(void);
double rsxd_bench_line(char* out, size_t cap, int frames);

void rsxd_init(uint8_t* base, uint32_t local_ea, uint32_t local_size,
               uint32_t (*ioff2ea)(uint32_t), uint64_t mem_size);
