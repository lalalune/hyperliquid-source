"""Reproduce the reference census for the
RE-001-composite-teardown-5a350-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-composite-teardown-5a350-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    0x5d5a350. No full dump is stored.
  * Scan the raw binary for an 8-byte little-endian qword equal to
    0x5d5a350.
  * Parse `readelf -r` output for RELATIVE records mentioning
    0x5d5a350.

Expected result for the digest-verified node #115 work binary:
exactly 3 direct calls (0x5d84a13, 0x5d87d02, 0x5d8844a),
exactly 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x5D5A350


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {"call": set(), "jmp": set()}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+5d5a350\b")
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[match.group(2)].add(int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        raise AssertionError("objdump failed")
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
                if ("%x" % TARGET) in line and "RELATIVE" in line]
    print("direct calls: %s" % [hex(c) for c in sorted(found["call"])])
    print("tail jumps: %s" % [hex(c) for c in sorted(found["jmp"])])
    print("stored qwords: %s" % [hex(q) for q in qwords])
    print("RELATIVE addends: %d" % len(relative))
    return 0


if __name__ == "__main__":
    sys.exit(main())
