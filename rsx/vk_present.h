#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rsxvk_init(void);

void rsxvk_present(const uint8_t* src, uint32_t w, uint32_t h, uint32_t pitch);

void rsxvk_pump_tick(void);

void rsxvk_set_title(const char* s);

int rsxvk_has_focus(void);

typedef struct {
    uint16_t d1, d2;
    int16_t  lx, ly, rx, ry;
    uint8_t  l2, r2;
} RsxvkPad;
int rsxvk_pad_read(RsxvkPad* out);

int  rsxvk_audio_push(const float* frames, int nframes);
void rsxvk_audio_ratio(float ratio);
void rsxvk_audio_clear(void);

int rsxvk_have_mirror_clamp(void);

#ifdef VK_VERSION_1_0
VkDevice          rsxvk_device(void);
VkPhysicalDevice  rsxvk_phys(void);
VkQueue           rsxvk_queue(void);
uint32_t          rsxvk_qfam(void);
void rsxvk_present_image(VkImage img, uint32_t w, uint32_t h);
#endif

#ifdef __cplusplus
}
#endif
