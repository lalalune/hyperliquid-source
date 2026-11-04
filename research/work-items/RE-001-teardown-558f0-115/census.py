#!/usr/bin/env python3
"""Exhaustive direct-call / tail-jump census for 0x5d558f0 and its
condition-variable wrapper 0x60d5470.

Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is either address, then confirms
each candidate by re-disassembling the site with objdump. Also scans
relocation addends for stored references to either target (none
expected). Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D558F0, 0x60D5470]
EXPECTED = {
    0x5D558F0: [(0x5D84C07, "call"), (0x5D886CB, "call")],
    0x60D5470: [(0x5D487CB, "call"), (0x5D487FB, "call"),
                (0x5D4CEF1, "call"), (0x5D4CF71, "call"),
                (0x5D55929, "call"), (0x5D84815, "call"),
                (0x5D84B67, "call"), (0x5D84B97, "call"),
                (0x5D85001, "call"), (0x5D879F3, "call"),
                (0x5D87DBB, "call"), (0x5D87DF2, "call"),
                (0x5D87EEF, "call"), (0x5D87F1F, "call"),
                (0x5D87FB4, "call"), (0x5D881F7, "call"),
                (0x5D88503, "call"), (0x5D8853A, "call"),
                (0x5D88637, "call"), (0x5D88667, "call"),
                (0x5F20803, "call"), (0x5F7478F, "call"),
                (0x5F74853, "call"), (0x5F74913, "call"),
                (0x5F74A3B, "call"), (0x5F98CAD, "call"),
                (0x5F98D1B, "call"), (0x602F241, "call"),
                (0x6032350, "call"), (0x604A590, "call"),
                (0x61C4C7A, "call"), (0x61C5A1F, "call"),
                (0x61C5AFB, "call"), (0x61C5E8D, "call")],
}
EXPECTED_RELOCS = {
    0x5D558F0: [],
    0x60D5470: [],
}


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
        relocs = subprocess.run(["readelf", "-r", BIN],
                                capture_output=True, text=True).stdout
        stored = []
        for line in relocs.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == "R_X86_64_RELATIVE":
                try:
                    if int(parts[-1], 16) == target:
                        stored.append(int(parts[0], 16))
                except ValueError:
                    pass
        print(f"target 0x{target:x}: confirmed {[(hex(v), k) for v, k in confirmed]} "
              f"relocation-stored {[hex(h) for h in stored]}")
        if confirmed != EXPECTED[target] or stored != EXPECTED_RELOCS[target]:
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
