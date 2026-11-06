#!/usr/bin/env python3
"""Exhaustive direct-call / tail-jump census for the twin guarded queries.

Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is 0x5d553c0 or 0x5d55520, then
confirms each candidate by re-disassembling the site with objdump.
Also scans the data LOAD segments for stored qwords equal to either
address. Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
DATA = [(0x63F0BA0, 0x63F2BA0, 0x0FBE80), (0x64ECA20, 0x64EFA20, 0x0103E8)]
TARGETS = [0x5D553C0, 0x5D55520]


def main() -> None:
    data = open(BIN, "rb").read()
    ok = True
    for target in TARGETS:
        cands = []
        for off, base, size in EXEC:
            seg = data[off:off + size]
            for i in range(len(seg) - 5):
                op = seg[i]
                if op in (0xE8, 0xE9):
                    rel = struct.unpack_from("<i", seg, i + 1)[0]
                    if base + i + 5 + rel == target:
                        cands.append((base + i, op))
        confirmed = []
        for va, op in cands:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", BIN],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ((op == 0xE8 and "call" in line)
                             or (op == 0xE9 and "jmp" in line))):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        q = struct.pack("<Q", target)
        stored = []
        for off, base, size in DATA:
            seg = data[off:off + size]
            start = 0
            while True:
                i = seg.find(q, start)
                if i < 0:
                    break
                stored.append(base + i)
                start = i + 1
        print(f"target 0x{target:x}: confirmed {[(hex(v), k) for v, k in confirmed]} "
              f"stored-qwords {[hex(h) for h in stored]}")
        if stored:
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
