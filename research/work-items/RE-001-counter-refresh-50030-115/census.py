#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Target: the counter-refresh routine 0x5d50030.
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
TARGETS = [0x5D50030]
EXPECTED = {
    0x5D50030: [(0x5d535a0, "call"),
                (0x5d54400, "call"),
                (0x5d60e6a, "call"),
                (0x5d61744, "call"),
                (0x5d78a6e, "call"),
                (0x5d79015, "call"),
                (0x5db0cb3, "call"),
                (0x5db12d1, "call"),
                (0x5db14e9, "call"),
                (0x5db161c, "call"),
                (0x5e10951, "call"),
                (0x5e1122b, "call"),
                (0x5e183b1, "call"),
                (0x5e18881, "call"),
                (0x5e1b979, "call"),
                (0x5e1ef4f, "call"),
                (0x5e21ac7, "call"),
                (0x5e21da4, "call"),
                (0x5e22105, "call"),
                (0x5e2215d, "call"),
                (0x5e260ed, "call"),
                (0x5e261ea, "call"),
                (0x5e2658d, "call"),
                (0x5e26719, "call"),
                (0x5e7c9fd, "call"),
                (0x5e7d11e, "call"),
                (0x5e86376, "call"),
                (0x5e86842, "call"),
                (0x5e87128, "call"),
                (0x5e8731a, "call"),
                (0x5e8754d, "call"),
                (0x5e89c60, "call"),
                (0x5e8a3d9, "call"),
                (0x5e8eec2, "call"),
                (0x5e8fae9, "call"),
                (0x5e9090a, "call"),
                (0x5e91244, "call"),
                (0x5e91d35, "call"),
                (0x5e92b4f, "call"),
                (0x5ea2dff, "call"),
                (0x5ea32a2, "call"),
                (0x5ea394d, "call"),
                (0x5ea8577, "call"),
                (0x5ea8c77, "call"),
                (0x5ea8e4e, "call"),
                (0x5f3dd5c, "call"),
                (0x5f3ec4c, "call"),
                (0x6035287, "call"),
                (0x6035468, "call"),
                (0x6035995, "call"),
                (0x6035ba5, "call"),
                (0x6036589, "call"),
                (0x6036927, "call"),
                (0x6036bf2, "call"),
                (0x6036c45, "call"),
                (0x6037021, "call"),
                (0x6037727, "call"),
                (0x603f9da, "call"),
                (0x60439f9, "call"),
                (0x60445e1, "call"),
                (0x6045ad5, "call"),
                (0x6045b9a, "call"),
                (0x6046ec0, "call"),
                (0x6047bd4, "call"),
                (0x60e718d, "call"),
                (0x60e741d, "call"),
                (0x61089a7, "call"),
                (0x6108a36, "call"),
                (0x6108af4, "call"),
                (0x6108d2c, "call"),
                (0x6108f6c, "call"),
                (0x61121f2, "call"),
                (0x611227a, "call"),
                (0x6112338, "call"),
                (0x6112572, "call"),
                (0x61127bc, "call"),
                (0x6113cf9, "call"),
                (0x6113d81, "call"),
                (0x6113e42, "call"),
                (0x6114063, "call"),
                (0x611425f, "call"),
                (0x611588b, "call"),
                (0x611591a, "call"),
                (0x61159d8, "call"),
                (0x6115c2c, "call"),
                (0x6115e74, "call"),
                (0x61174ab, "call"),
                (0x611753a, "call"),
                (0x61175f8, "call"),
                (0x611784c, "call"),
                (0x6117a94, "call")],
}
EXPECTED_RELOCS = {
    0x5D50030: [],
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
