#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GAME = os.path.join(ROOT, "game")


def fwd(p):
    return os.path.abspath(p).replace("\\", "/")


def tool(tools, name):
    for cand in (name + ".exe", name):
        p = os.path.join(tools, cand)
        if os.path.isfile(p):
            return p
    sys.exit("error: %s not found in %s, build the tools first" % (name, tools))


def load_segments(data, what):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 2:
        sys.exit("error: %s is not a decrypted 64-bit big-endian ELF" % what)
    phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    phnum = struct.unpack(">H", data[0x38:0x3a])[0]
    segs = []
    for k in range(phnum):
        p = phoff + k * 0x38
        typ, _, off, va, _, fsz, _, _ = struct.unpack(">IIQQQQQQ", data[p:p + 0x38])
        if typ == 1 and fsz:
            segs.append((va, data[off:off + fsz]))
    return segs


class Memory:
    def __init__(self):
        self.segs = []

    def add(self, va, data):
        self.segs.append((va, data))

    def read(self, ea, n):
        for va, data in self.segs:
            if va <= ea and ea + n <= va + len(data):
                return data[ea - va:ea - va + n]
        sys.exit("error: 0x%x+0x%x is outside the loaded images" % (ea, n))


def check(blob, want, what):
    got = hashlib.sha1(blob).hexdigest()
    if got != want:
        sys.exit("error: %s does not match (sha1 %s, expected %s).\n"
                 "The EBOOT or firmware modules are not the versions this project targets." % (what, got, want))


def write_reloc_images(path, images):
    out = ["#include <stdint.h>"]
    for name, blob in images:
        out.append("const uint32_t %s_img_len = %du;" % (name, len(blob)))
        out.append("const uint8_t %s_img[] = {" % name)
        for i in range(0, len(blob), 16):
            out.append(", ".join("0x%02x" % b for b in blob[i:i + 16]) + ",")
        out.append("};")
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Generate the recompiled sources in gen/ from your own game files.")
    ap.add_argument("--eboot", required=True, help="decrypted EBOOT.ELF of NPUB31347")
    ap.add_argument("--libsre", required=True, help="decrypted libsre.sprx from firmware 4.93")
    ap.add_argument("--libspurs-jq", required=True, help="decrypted libspurs_jq.sprx from firmware 4.93")
    ap.add_argument("--tools", default=os.path.join(ROOT, "build"), help="folder with ppu-recompile and spu-lift")
    ap.add_argument("--out", default=os.path.join(ROOT, "gen"))
    a = ap.parse_args()

    for p in (a.eboot, a.libsre, a.libspurs_jq):
        if not os.path.isfile(p):
            sys.exit("error: %s not found" % p)
    recompile = tool(a.tools, "ppu-recompile")
    lift = tool(a.tools, "spu-lift")
    out = fwd(a.out)
    os.makedirs(out, exist_ok=True)

    print("recompiling PPU code, this takes a few minutes", flush=True)
    r = subprocess.run([recompile, fwd(a.eboot), out, os.path.join(GAME, "imports.csv"),
                        "--prx", fwd(a.libsre), "--prx", fwd(a.libspurs_jq),
                        "--patches", os.path.join(GAME, "patches.txt")])
    if r.returncode:
        sys.exit("error: ppu-recompile failed")

    mem = Memory()
    for va, data in load_segments(open(a.eboot, "rb").read(), a.eboot):
        mem.add(va, data)
    segs_c = open(os.path.join(out, "prx_segs.c")).read()
    for name, va in re.findall(r'\{(prx\d+_seg\d+),0x([0-9a-f]+)ull,0x[0-9a-f]+ull\}', segs_c):
        mem.add(int(va, 16), open(os.path.join(out, name + ".bin"), "rb").read())

    images = []
    reloc = {}
    for row in csv.DictReader(open(os.path.join(GAME, "reloc_images.csv"))):
        blob = bytearray(mem.read(int(row["address"], 16), int(row["length"], 16)))
        for item in filter(None, row["set"].split(";")):
            off, val = (int(x, 16) for x in item.split("="))
            blob[off:off + 4] = struct.pack(">I", val)
        blob = bytes(blob)
        check(blob, row["sha1"], "SPU image " + row["name"])
        images.append((row["name"], blob))
        reloc[row["name"]] = blob
    write_reloc_images(os.path.join(out, "spu_reloc_imgs.c"), images)

    rows = list(csv.DictReader(open(os.path.join(GAME, "spu_lifts.csv"))))
    with tempfile.TemporaryDirectory() as tmp:
        for k, row in enumerate(rows, 1):
            name = row["name"]
            if row["source"].startswith("reloc:"):
                blob = reloc[row["source"][6:]]
            else:
                blob = mem.read(int(row["address"], 16), int(row["length"], 16))
            check(blob, row["sha1"], "SPU code for " + name)
            bin_path = os.path.join(tmp, name + ".bin")
            open(bin_path, "wb").write(blob)
            print("lifting SPU %2d/%d  %s" % (k, len(rows), name), flush=True)
            r = subprocess.run([lift, bin_path, os.path.join(out, "spu_body_%s.c" % name), name,
                                "--raw", row["base"], row["entry"]], capture_output=True, text=True)
            if r.returncode:
                sys.exit("error: spu-lift failed on %s\n%s" % (name, r.stderr))

    print("done. gen/ is ready to build")


if __name__ == "__main__":
    main()
