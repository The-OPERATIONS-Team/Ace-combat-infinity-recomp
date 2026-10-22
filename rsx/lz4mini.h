#pragma once
#include <stddef.h>
#include <stdint.h>

#define LZ4M_HLOG           16
#define LZ4M_SCRATCH_BYTES  ((size_t)(1u << LZ4M_HLOG) * sizeof(uint32_t))

int lz4m_bound(int srcSize);

int lz4m_compress(const void* src, int srcSize, void* dst, int dstCap,
                  void* scratch  );

int lz4m_decompress(const void* src, int srcSize, void* dst, int dstCap);

int lz4m_selftest(void);
