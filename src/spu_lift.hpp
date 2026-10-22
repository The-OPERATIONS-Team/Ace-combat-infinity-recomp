#pragma once
#include <cstdint>
#include <string>

std::string spu_lift_image(const uint8_t* code, uint32_t base, uint32_t size,
                           uint32_t entry, const char* fname = "spu_run");
