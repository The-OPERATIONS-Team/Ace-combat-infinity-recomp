#pragma once
#include "elf.hpp"
#include <cstdint>
#include <set>
#include <string>

std::string lift_function(const ElfImage& elf, uint32_t start, uint32_t end,
                          std::set<uint32_t>& called,
                          const std::set<uint32_t>& tocs = {});

bool ppu_load_patches(const std::string& path, std::string& err);
std::string ppu_patch_problems();
