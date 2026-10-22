# ACE COMBAT INFINITY static recompilation

A static recompilation of the PS3 version of ACE COMBAT INFINITY (NPUB31347) to native x86-64 Windows code.

The game's PowerPC and SPU code is translated to C ahead of time and compiled like any other program, so nothing is interpreted or JIT-compiled while you play. The PS3 operating system and the system libraries the game calls are reimplemented by the runtime in `gen/`. Graphics run through a Vulkan renderer that translates the PS3 GPU's command stream and shaders as the game issues them.

The official servers shut down in 2018. The runtime answers the game's online calls locally and removes the fuel requirement, so the campaign can be played offline.

No game code or data is in this repository. You need your own copy of the game and you generate the recompiled sources yourself.

## Status

- The campaign boots, plays and moves between missions.
- Renders at the game's native 1280x720. There is no resolution scaling yet.
- Shaders are converted the first time they are used, so expect small hitches in new scenes.
- Progress is not saved between sessions yet.
- Multiplayer modes don't work.
- Windows only.

## Layout

| Folder | What's in it |
| --- | --- |
| `src/` | The recompiler (`ppu-recompile`) and the SPU lifter (`spu-lift`), plus two small analysis tools |
| `gen/` | The runtime: lv2 syscalls, SPU threads and DMA, HLE system libraries, input and audio. Generated code is written here too |
| `rsx/` | The Vulkan renderer, frame capture/replay, profiler and state snapshots |
| `game/` | Game-specific inputs: imported function names, the offline patches, and the list of SPU jobs to lift |
| `spu/` | The SPU opcode table used by the lifter |
| `tools/` | `generate.py`, which drives the whole generation step |

## What you need

Software:

- Windows 10 or 11, 64-bit, on a CPU with AVX2
- A GPU with Vulkan support
- [LLVM](https://github.com/llvm/llvm-project/releases) (clang). Built and tested with 22.1
- Visual Studio Build Tools with the Windows SDK, for the libraries clang links against
- CMake 3.20 or newer, and Ninja
- The [Vulkan SDK](https://vulkan.lunarg.com/). Its installer sets `VULKAN_SDK`, which the build uses
- [SDL3](https://github.com/libsdl-org/SDL/releases), the MSVC development package. The build looks in `C:\SDL3` unless you pass `-DRSX_SDL3_ROOT`
- Python 3

Game files:

- ACE COMBAT INFINITY, US PSN version NPUB31347, updated to 02.11. You need its `USRDIR` folder with the `DATA*.PAC` files and the `target` folder.
- The game's `EBOOT.BIN`, decrypted to an ELF. RPCS3 can do this under Utilities > Decrypt PS3 Binaries.
- `libsre.sprx` and `libspurs_jq.sprx` from PS3 firmware 4.93, also decrypted. They are in `dev_flash/sys/external`. If you install the 4.93 firmware in RPCS3 you'll find them there, and the same decrypt option works on them.

The generator checks every piece of code it takes from these files. A different game version or firmware fails with a clear message instead of producing a broken build.

## Building

All commands run from the repository root.

### 1. Build the tools

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++
ninja -C build
```

### 2. Generate the recompiled sources

```
python tools/generate.py --eboot C:\path\to\EBOOT.ELF --libsre C:\path\to\libsre.prx --libspurs-jq C:\path\to\libspurs_jq.prx
```

This recompiles the PPU code of the game and both firmware modules, applies the offline patches from `game/patches.txt`, and lifts the SPU jobs listed in `game/spu_lifts.csv`. It takes under a minute and writes everything into `gen/`.

The EBOOT path is stored in the build and the game loads it at startup, so leave `EBOOT.ELF` where it is.

### 3. Build the game

```
cmake -S gen -B gen/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_RC_COMPILER=llvm-rc
ninja -C gen/build
```

This is the long step: around 10 to 15 minutes on a 12-thread CPU. The SPU job files take the longest. When it finishes you have `gen\build\game.exe` with `SDL3.dll` next to it.

## Running

Point `PS3_FS_ROOT` at the game's `USRDIR` folder and start the exe:

```
set PS3_FS_ROOT=C:\path\to\NPUB31347\USRDIR
gen\build\game.exe 2> game.log
```

The runtime writes a lot of diagnostics to stderr, so redirect it to a file.

Controllers work through XInput and SDL3, so Xbox pads and a DualShock 4 both work. On the keyboard:

| Key | Button |
| --- | --- |
| W A S D | Left stick |
| I J K L | Right stick |
| Arrow keys | D-pad |
| X or Space | Cross |
| C | Circle |
| V | Square |
| T | Triangle |
| Q / E | L1 / R1 |
| 1 / 3 | L2 / R2 |
| Enter | Start |
| Backspace | Select |

A few environment variables you might want:

| Variable | Effect |
| --- | --- |
| `PS3_FS_ROOT` | The game's `USRDIR` folder |
| `PS3_FUEL` | Sortie tickets granted per refill (default 6). `0` turns the offline fuel patch off |
| `PS3_AUDIO_VOL` | Master volume, default `1.0` |
| `PS3_PRESENT` | `fifo` waits for your monitor's vsync. The default is `mailbox` when the driver offers it |
| `PS3_PROF=1` | Enables the profiler. F7 starts and stops a recording, written to `out/` |

F8 writes a full state snapshot to `out/` and F9 starts or stops a gameplay capture that `rsxreplay` can play back. Both are for debugging.

## Legal

This project contains no code or assets from the game. Every recompiled file is produced on your machine from files you supply. ACE COMBAT is a trademark of Bandai Namco Entertainment. This project is not affiliated with Bandai Namco or Sony.
