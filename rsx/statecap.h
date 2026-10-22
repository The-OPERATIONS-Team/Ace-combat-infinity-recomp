#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void statecap_init(uint8_t* base, uint64_t size);

void statecap_register(const char* name, void (*fn)(const char* dir));

void statecap_request(const char* why);

int         statecap_rsx_pending(void);
const char* statecap_dir(void);
void        statecap_rsx_done(void);

#ifdef __cplusplus
}
#endif
