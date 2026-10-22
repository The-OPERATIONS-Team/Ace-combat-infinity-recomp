#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void rsx_init(uint8_t* base, uint32_t local_ea, uint32_t local_size,
              uint32_t (*ioff2ea)(uint32_t), uint64_t mem_size);

void rsx_method(uint32_t mth, uint32_t arg);

void rsx_set_display_buffer(uint32_t id, uint32_t offset, uint32_t pitch,
                            uint32_t width, uint32_t height);

void rsx_flip(uint32_t bufid);

void rsx_sync_read(uint32_t ea, uint32_t size);

#ifdef __cplusplus
}
#endif
