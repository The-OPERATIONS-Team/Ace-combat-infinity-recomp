#pragma once
#include <cstdint>
#include <string>

struct Instr {
    uint32_t raw  = 0;
    uint32_t addr = 0;
    bool     valid = false;
    std::string mnem;
    std::string ops;

    std::string text() const { return ops.empty() ? mnem : mnem + " " + ops; }
};

Instr ppu_decode(uint32_t raw, uint32_t addr);
