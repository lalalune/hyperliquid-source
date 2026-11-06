#!/usr/bin/env python3
"""Whole-binary reference census for the wrapper at 0x5a00fc0.

Run from the repository root:

    python3 research/work-items/RE-001-spot-scale-roundup-fc0-115/census.py

Scans the materialised node binary at work/hl-node-115.bin and
prints, for the routine: every direct call site (E8 rel32 whose
target is the routine), every direct jump site (E9 rel32, i.e.
a tail jump), every 8-byte-aligned stored qword equal to the
routine address, and the number of R_X86_64_RELATIVE relocation
addends equal to the routine address. verify.py compares the
printed lines against callers.tsv.
"""

import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5A00FC0,)


def load_segments(data):
    segs = []
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        p_flags = struct.unpack_from("<I", data, off + 0x04)[0]
        segs.append((p_offset, p_vaddr, p_filesz, p_flags))
    return segs


def relative_addends():
    out = subprocess.run(["readelf", "-rW", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    values = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            try:
                values.append(int(parts[3], 16))
            except ValueError:
                pass
    return values


def main():
    data = BINARY.read_bytes()
    segs = load_segments(data)
    exec_segs = [(o, v, s) for o, v, s, f in segs if f & 1]
    addends = relative_addends()
    for target in TARGETS:
        calls, jumps = [], []
        for off, va, size in exec_segs:
            chunk = data[off:off + size]
            for opcode, acc in ((0xE8, calls), (0xE9, jumps)):
                start = 0
                while True:
                    i = chunk.find(bytes([opcode]), start)
                    if i < 0 or i + 5 > len(chunk):
                        break
                    rel = struct.unpack_from("<i", chunk, i + 1)[0]
                    if va + i + 5 + rel == target:
                        acc.append(va + i)
                    start = i + 1
        stored = []
        for i in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, i)[0] == target:
                stored.append(i)
        print("routine %#x: direct calls: %s"
              % (target, [hex(x) for x in sorted(calls)]))
        print("routine %#x: tail jumps: %s"
              % (target, [hex(x) for x in sorted(jumps)]))
        print("routine %#x: stored qwords: %s"
              % (target, [hex(x) for x in stored]))
        print("routine %#x: RELATIVE addends: %d"
              % (target, addends.count(target)))


if __name__ == "__main__":
    main()
