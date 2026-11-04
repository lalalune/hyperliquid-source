"""Reproduce the reference census for the
RE-001-lazy-materialize-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-lazy-materialize-predicate-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is the
    predicate address (no full dump is stored).
  * Scan the raw binary for an 8-byte little-endian qword equal to
    the predicate address.
  * Parse `readelf -r` output for R_X86_64_RELATIVE records whose
    addend equals the predicate address.

Expected result for the digest-verified node #115 work binary:
predicate 0x5f77190: exactly 2 direct calls (0x5f773ae, 0x5f774ed),
0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x5F77190


def main():
    text = subprocess.run(
        ["objdump", "-d", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    calls, jumps = [], []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+5f77190\b",
                         line)
        if not match:
            continue
        if match.group(2) == "call":
            calls.append(int(match.group(1), 16))
        else:
            jumps.append(int(match.group(1), 16))
    data = BINARY.read_bytes()
    needle = struct.pack("<Q", TARGET)
    qwords, index = [], 0
    while True:
        hit = data.find(needle, index)
        if hit < 0:
            break
        qwords.append(hit)
        index = hit + 1
    relocations = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    relative = [line for line in relocations.splitlines()
                if "5f77190" in line and "RELATIVE" in line]
    print("direct calls:", [hex(c) for c in sorted(set(calls))])
    print("tail jumps:", [hex(j) for j in sorted(set(jumps))])
    print("stored qwords:", [hex(q) for q in qwords])
    print("RELATIVE addends:", len(relative))
    return 0


if __name__ == "__main__":
    sys.exit(main())
