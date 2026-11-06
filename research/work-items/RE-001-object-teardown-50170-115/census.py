#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Target: the object teardown routine 0x5d50170.
Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is the routine, then confirms
each candidate by re-disassembling the site with objdump. The scan
walks E8/E9 byte positions with bytes.find (same candidate set as a
byte-by-byte walk, without the byte-by-byte cost). Also scans
relocation addends for stored references to the routine.
Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D50170]
EXPECTED = {
    0x5D50170: [(0x5d802aa, "call"), (0x5e03cf7, "call"),
                (0x5e03d66, "call"), (0x5e04697, "call"),
                (0x5e049a5, "call"), (0x5e04cad, "call"),
                (0x5e0d113, "call"), (0x5e0e6da, "call"),
                (0x5e1b6b9, "call"), (0x5e1d611, "call"),
                (0x5e1e274, "call"), (0x5e1e9eb, "call"),
                (0x5e1efd8, "call"), (0x5e663f4, "call"),
                (0x5e67d83, "call"), (0x5ec4f8a, "call"),
                (0x5ec5ba9, "call"), (0x5ec63dd, "call"),
                (0x5ecdb88, "call"), (0x5ed1cf2, "call"),
                (0x5ed1dbe, "call"), (0x5ee6d2a, "call"),
                (0x5ee7453, "call"), (0x5ee74fc, "call"),
                (0x5f68da1, "call"), (0x5f68dd1, "call"),
                (0x5f769b6, "call"), (0x5f76eec, "call"),
                (0x5f7705c, "call"), (0x5f897c8, "call"),
                (0x60e8312, "call"), (0x60eb09e, "call"),
                (0x60ed8bb, "call"), (0x6105335, "call"),
                (0x615ff45, "call"), (0x618fc59, "call"),
                (0x5dfbcd8, "jmp")],
}
EXPECTED_RELOCS = {
    0x5D50170: [],
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
