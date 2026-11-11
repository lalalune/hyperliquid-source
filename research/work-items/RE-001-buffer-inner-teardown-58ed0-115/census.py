#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Target: the buffer-inner teardown routine 0x5d58ed0.
Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is the routine, then confirms
each candidate by re-disassembling the site with objdump. The scan
walks E8/E9 byte positions with bytes.find (same candidate set as a
byte-by-byte walk, without the byte-by-byte cost). Also scans
relocation addends and the full file for stored qword references
to the routine.
Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D58ED0]
EXPECTED = {
    0x5D58ED0: [(0x5d60e4c, "call"), (0x5d60f30, "call"),
                (0x5d78a30, "call")],
}
EXPECTED_RELOCS = {
    0x5D58ED0: [],
}


def main() -> None:
    data = open(BIN, "rb").read()
    ok = True
    for target in TARGETS:
        cands = []
        for off, base, size in EXEC:
            seg = data[off:off + size]
            for op in (0xE8, 0xE9):
                i = seg.find(bytes([op]))
                while i != -1:
                    if i + 5 <= len(seg):
                        rel = struct.unpack_from("<i", seg, i + 1)[0]
                        if base + i + 5 + rel == target:
                            cands.append((base + i, op))
                    i = seg.find(bytes([op]), i + 1)
        confirmed = []
        for va, op in cands:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", BIN],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ("call" in line or "jmp" in line)):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        print(f"{target:#x}: {len(confirmed)} sites")
        for va, kind in confirmed:
            print(f"  {va:#x} {kind}")
        if confirmed != EXPECTED[target]:
            print(f"  MISMATCH vs recorded census: {EXPECTED[target]}")
            ok = False
        stored = data.count(struct.pack("<Q", target))
        print(f"{target:#x}: {stored} stored qwords (full-file scan)")
        if stored != 0:
            ok = False
    relocs = subprocess.run(["readelf", "-r", BIN],
                            capture_output=True, text=True).stdout
    for target, expected in EXPECTED_RELOCS.items():
        hits = []
        for ln in relocs.splitlines():
            f = ln.split()
            if len(f) >= 4 and f[2] == "R_X86_64_RELATIVE":
                try:
                    if int(f[-1], 16) == target:
                        hits.append((int(f[0], 16), int(f[-1], 16)))
                except ValueError:
                    pass
        print(f"{target:#x}: {len(hits)} stored references")
        if hits != expected:
            print(f"  MISMATCH vs recorded relocations: {expected}")
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
