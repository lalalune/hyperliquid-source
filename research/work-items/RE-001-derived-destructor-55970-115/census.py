#!/usr/bin/env python3
"""Exhaustive direct-call / tail-jump census for the destructor pair.

Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is 0x5d55970, 0x5d559c0 or
0x5fe70b0, then confirms each candidate by re-disassembling the site
with objdump. Also scans relocation addends for stored references to
any target (the vtable slots live in .data.rel.ro, whose file bytes
are zeroed in this materialized binary, so a byte-pattern scan would
miss them; the relocation records are the stored references).
Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D55970, 0x5D559C0, 0x5FE70B0]
EXPECTED = {
    0x5D55970: [],
    0x5D559C0: [],
    0x5FE70B0: [(0x5D559B4, "jmp"), (0x5D55A03, "call"),
                (0x5D55A84, "jmp"), (0x5D5629B, "call"),
                (0x5E01C58, "call"), (0x5F74E3C, "call"),
                (0x5FB180E, "jmp"), (0x5FB183D, "jmp"),
                (0x5FB18C8, "call"), (0x5FE71E5, "call"),
                (0x5FE734E, "jmp"), (0x5FE737D, "jmp"),
                (0x5FE7408, "call"), (0x5FEEC96, "jmp"),
                (0x5FEECC5, "jmp"), (0x5FEED70, "call"),
                (0x5FF3040, "jmp"), (0x5FF308F, "call"),
                (0x5FFBFFE, "jmp"), (0x5FFC022, "call"),
                (0x5FFC052, "jmp"), (0x5FFC39B, "call"),
                (0x6028A3B, "call"), (0x6028CE5, "jmp"),
                (0x61EDBCE, "jmp"), (0x61EDBFD, "jmp"),
                (0x61EDC88, "call"), (0x61F040E, "jmp"),
                (0x61F043D, "jmp"), (0x61F04C8, "call")],
}
EXPECTED_RELOCS = {
    0x5D55970: [0x64D08A8, 0x64ED3F0],
    0x5D559C0: [0x64D08B0],
    0x5FE70B0: [],
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
