#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Target: the object teardown routine 0x5d516f0.
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
TARGETS = [0x5D516F0]
EXPECTED = {
    0x5D516F0: [(0x5d5f391, "call"), (0x5d5f596, "call"), (0x5d5f7d6, "call"), (0x5d5f9fc, "call"), (0x5d68d23, "call"), (0x5d6976b, "call"), (0x5d69939, "call"), (0x5d6a39f, "call"), (0x5d6a706, "call"), (0x5d6a98b, "call"), (0x5d6ad53, "call"), (0x5d6b20f, "call"), (0x5d6b527, "call"), (0x5d6b778, "call"), (0x5d72eb4, "call"), (0x5d738d6, "call"), (0x5d77653, "call"), (0x5d7772a, "call"), (0x5d77d18, "call"), (0x5d77eef, "call"), (0x5d7f2c6, "call"), (0x5d7f805, "call"), (0x5d816ee, "call"), (0x5d81db0, "call"), (0x5d81fa8, "call"), (0x5da8672, "call"), (0x5ddc16c, "call"), (0x5ddc647, "call"), (0x5de3332, "call"), (0x5de3a92, "call"), (0x5de43c5, "call"), (0x5de5179, "call"), (0x5decaf0, "call"), (0x5deddeb, "call"), (0x5e45ba7, "call"), (0x5e51d6b, "call"), (0x5e51f9b, "call"), (0x5e52942, "call"), (0x5e53549, "call"), (0x5e5df55, "call"), (0x5e5eb1d, "call"), (0x5e68cf3, "call"), (0x5e68d12, "call"), (0x5e68f80, "call"), (0x5e68f9c, "call"), (0x5e68fa8, "call"), (0x5e6963f, "call"), (0x5e69658, "call"), (0x5e69664, "call"), (0x5e69afa, "call"), (0x5e6b663, "call"), (0x5e6ba65, "call"), (0x5e6d9e6, "call"), (0x5e8a857, "call"), (0x5e8bca3, "call"), (0x5e8bfed, "call"), (0x5e8ef2b, "call"), (0x5e8f9e2, "call"), (0x5e91de2, "call"), (0x5e938f7, "call"), (0x5ee9475, "call"), (0x5f10390, "call"), (0x5f14e25, "call"), (0x5f1691f, "call"), (0x5f6eafa, "call"), (0x5f72b59, "call"), (0x5f72d7a, "call"), (0x5f7a4fc, "call"), (0x5f89d8b, "call"), (0x5f89dc2, "call"), (0x5f89dda, "call"), (0x5f89e59, "call"), (0x5f8a40c, "call"), (0x5f8aaa4, "call"), (0x5f8ab7d, "call"), (0x5f8b2ef, "call"), (0x5f8b802, "call"), (0x5f8b84d, "call"), (0x5f957f6, "call"), (0x5f970f7, "call"), (0x5f9da87, "call"), (0x5f9e548, "call"), (0x5f9e730, "call"), (0x5fa0e29, "call"), (0x5fa1679, "call"), (0x5fa3af1, "call"), (0x5fa4550, "call")],
}
EXPECTED_RELOCS = {
    0x5D516F0: [],
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
