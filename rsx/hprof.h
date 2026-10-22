#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*HprofLabeler)(unsigned long tid, char* out, unsigned cap);

void hprof_init(HprofLabeler labeler);

void hprof_frame(int vblanks);

#ifdef __cplusplus
}
#endif
