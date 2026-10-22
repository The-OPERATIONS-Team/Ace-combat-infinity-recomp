#pragma once
#include <cstdint>
#include <cstring>

inline uint16_t bswap16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }
inline uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}
inline uint64_t bswap64(uint64_t v) {
    return ((uint64_t)bswap32((uint32_t)v) << 32) | bswap32((uint32_t)(v >> 32));
}

template <class T> inline T rd_be(const uint8_t* p) {
    T v; std::memcpy(&v, p, sizeof(T));
    if constexpr (sizeof(T) == 2) return (T)bswap16((uint16_t)v);
    else if constexpr (sizeof(T) == 4) return (T)bswap32((uint32_t)v);
    else if constexpr (sizeof(T) == 8) return (T)bswap64((uint64_t)v);
    else return v;
}

inline uint8_t  be8 (const uint8_t* p) { return *p; }
inline uint16_t be16(const uint8_t* p) { return rd_be<uint16_t>(p); }
inline uint32_t be32(const uint8_t* p) { return rd_be<uint32_t>(p); }
inline uint64_t be64(const uint8_t* p) { return rd_be<uint64_t>(p); }
