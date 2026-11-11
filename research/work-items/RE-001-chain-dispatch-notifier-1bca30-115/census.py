"""Reproduce the reference census for the
RE-001-chain-dispatch-notifier-1bca30-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-dispatch-notifier-1bca30-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    0x61bca30. No full dump is stored.
  * Scan the raw binary for an 8-byte little-endian qword equal to
    0x61bca30.
  * Parse `readelf -r` output for RELATIVE records mentioning
    0x61bca30, and separately report the RELATIVE record at
    0x64ecf80 whose addend is the expected-slot walker 0x5d4d490.

Expected result for the digest-verified node #115 work binary:
exactly 1 direct call (0x61bcebd), exactly 0 tail jumps,
0 stored qwords, 0 RELATIVE addends for the routine itself, and
exactly 1 RELATIVE record at 0x64ecf80 with addend 0x5d4d490.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x61BCA30
EXPECTED_GLOBAL = 0x64ECF80
EXPECTED_WALKER = 0x5D4D490


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {"call": set(), "jmp": set()}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+61bca30\b")
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
    global_reloc = [line for line in relocations.splitlines()
                    if ("%x" % EXPECTED_GLOBAL) in line
                    and "RELATIVE" in line]
    print("direct calls: %s" % [hex(c) for c in sorted(found["call"])])
    print("tail jumps: %s" % [hex(c) for c in sorted(found["jmp"])])
    print("stored qwords: %s" % [hex(q) for q in qwords])
    print("RELATIVE addends: %d" % len(relative))
    print("expected-slot global relocations: %s" % global_reloc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
