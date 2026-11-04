#!/usr/bin/env python3
"""Direct-call / tail-jump census and stored-reference census.

Targets: the adapter 0x5d548a0, the cache routine 0x61bcde0, the
record builder 0x61bc290, and the getter 0x5d54890.

Scans the executable LOAD segment of work/hl-node-115.bin for E8 (call)
and E9 (jmp) rel32 sites whose target is one of the routines, then
confirms each candidate by re-disassembling the site with objdump.
Also scans relocation addends for stored references to the adapter.
Run from the repository root.

Usage: python3 census.py  (prints the census; exits non-zero on surprise)
"""
import struct
import subprocess
import sys

BIN = "work/hl-node-115.bin"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
TARGETS = [0x5D548A0, 0x61BCDE0, 0x61BC290, 0x5D54890]
EXPECTED = {
    # Reached only through pointers: no direct call or tail jump.
    0x5D548A0: [],
    # Only the adapter's call.
    0x61BCDE0: [(0x5D548E5, "call")],
    # Only the cache routine's call.
    0x61BC290: [(0x61BCEA3, "call")],
    # Only the adapter's call.
    0x5D54890: [(0x5D548D1, "call")],
}
EXPECTED_RELOCS = {
    0x5D548A0: [(0x64C9790, 0x5D548A0), (0x64CB508, 0x5D548A0),
                (0x64CB9E8, 0x5D548A0), (0x64CBFE8, 0x5D548A0)],
    0x61BCDE0: [],
    0x61BC290: [],
    0x5D54890: [],
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
        print(f"relocations to {target:#x}: {len(hits)}")
        for addr, addend in hits:
            print(f"  {addr:#x} -> {addend:#x}")
        if hits != expected:
            print(f"  MISMATCH vs recorded relocations: {expected}")
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
