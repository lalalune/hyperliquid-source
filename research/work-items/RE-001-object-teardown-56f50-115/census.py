#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Target: the object teardown routine 0x5d56f50.
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
TARGETS = [0x5D56F50]
EXPECTED = {
    0x5D56F50: [(0x5d5d1ca, "call"), (0x5d5d690, "call"),
                (0x5d5fe8d, "call"), (0x5d5ffab, "call"),
                (0x5d68cf5, "call"), (0x5d68ff1, "call"),
                (0x5d6ad47, "call"), (0x5d6b203, "call"),
                (0x5defda6, "call"), (0x5df0073, "call"),
                (0x5df3666, "call"), (0x5df3952, "call"),
                (0x5df650f, "call"), (0x5df67e1, "call"),
                (0x5e45b9b, "call"), (0x5e46e6a, "call"),
                (0x5e56f39, "call"), (0x5e570a7, "call"),
                (0x5e57149, "call"), (0x5e57209, "call"),
                (0x5e84693, "call"), (0x5e84823, "call"),
                (0x5e84a1d, "call"), (0x5e84a6a, "call"),
                (0x5e84cf3, "call"), (0x5e84cfd, "call"),
                (0x5edb89d, "call"), (0x5edc311, "call")],
}
EXPECTED_RELOCS = {
    0x5D56F50: [],
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
            if len(f) >= 4 and f[-1] == f"{target:x}":
                try:
                    hits.append((int(f[0], 16), int(f[-1], 16)))
                except ValueError:
                    pass
        print(f"{target:#x}: {len(hits)} stored references")
        if hits != expected:
            print(f"  MISMATCH vs recorded relocations: {expected}")
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
