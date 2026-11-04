#!/usr/bin/env python3
"""Exhaustive direct-call / tail-jump census for 0x5d55870.

Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is 0x5d55870, then confirms each
candidate by re-disassembling the site with objdump. Also scans
relocation addends for stored references to the target (none expected).
Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D55870]
EXPECTED = {
    0x5D55870: [(0x5D699F7, "call"), (0x5D72E90, "call"),
                (0x5D95297, "call"), (0x5DA867E, "call"),
                (0x5DD9B3C, "call"), (0x5DE7ED7, "call"),
                (0x5DECB2C, "call"), (0x5DED0BD, "call"),
                (0x5E663C4, "call"), (0x5E82CAA, "call"),
                (0x5E8A849, "call"), (0x5F94E35, "call"),
                (0x5F95221, "call"), (0x5F9523A, "call"),
                (0x5F95259, "call"), (0x5F95860, "call"),
                (0x5F987E3, "call"), (0x5F98CA1, "call"),
                (0x5F98D0F, "call"), (0x5F9FB39, "call"),
                (0x5FA4F35, "call"), (0x6087F2F, "call"),
                (0x6087FA2, "call"), (0x6087FC3, "call"),
                (0x60EB1F5, "call")],
}
EXPECTED_RELOCS = {
    0x5D55870: [],
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
