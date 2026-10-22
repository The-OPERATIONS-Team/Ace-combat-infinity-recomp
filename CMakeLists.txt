cmake_minimum_required(VERSION 3.20)
project(ps3recomp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W3 /EHsc)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

add_executable(ppu-analyze
  src/main.cpp
  src/elf.cpp
  src/ppu_module.cpp
)
target_include_directories(ppu-analyze PRIVATE src)

add_executable(ppu-lift
  src/lift_main.cpp
  src/ppu_lift.cpp
  src/ppu_decode.cpp
  src/elf.cpp
)
target_include_directories(ppu-lift PRIVATE src)

add_executable(ppu-recompile
  src/recompile_main.cpp
  src/ppu_lift.cpp
  src/ppu_decode.cpp
  src/ppu_module.cpp
  src/elf.cpp
  src/spu_lift.cpp
  src/spu_decode.cpp
)
target_include_directories(ppu-recompile PRIVATE src)

add_executable(spu-lift
  src/spu_lift_main.cpp
  src/spu_lift.cpp
  src/spu_decode.cpp
)
target_include_directories(spu-lift PRIVATE src)
