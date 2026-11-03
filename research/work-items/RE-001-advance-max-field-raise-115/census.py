"""Reproduce the reference census for the
RE-001-advance-max-field-raise-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-advance-max-field-raise-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is one
    of the two leaf addresses (0x5f6f400, 0x5f6f430). No full dump
    is stored.
  * Scan the raw binary for an 8-byte little-endian qword equal to
    either leaf address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    either leaf address.

Expected result for the digest-verified node #115 work binary:
advance leaf 0x5f6f400: exactly 5 direct calls (0x5e6987d,
0x5e6b3ac, 0x5e82edc, 0x5f9dfc1, 0x5f9dfd1), exactly 0 tail
jumps, 0 stored qwords, 0 RELATIVE addends.
max leaf 0x5f6f430: exactly 2 direct calls (0x5f9846d,
0x5f9dfb1), exactly 0 tail jumps, 0 stored qwords,
0 RELATIVE addends.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = {0x5F6F400: "advance", 0x5F6F430: "max"}


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {t: {"call": set(), "jmp": set()} for t in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6f400|5f6f430)\b")
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        raise AssertionError("objdump failed")
    data = BINARY.read_bytes()
    relocations = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target, label in TARGETS.items():
        needle = struct.pack("<Q", target)
        qwords, index = [], 0
        while True:
            hit = data.find(needle, index)
            if hit < 0:
                break
            qwords.append(hit)
            index = hit + 1
        relative = [line for line in relocations.splitlines()
                    if ("%x" % target) in line and "RELATIVE" in line]
        print("%s %#x: direct calls: %s" % (
            label, target,
            [hex(c) for c in sorted(found[target]["call"])]))
        print("%s %#x: tail jumps: %s" % (
            label, target,
            [hex(c) for c in sorted(found[target]["jmp"])]))
        print("%s %#x: stored qwords: %s" % (
            label, target, [hex(q) for q in qwords]))
        print("%s %#x: RELATIVE addends: %d" % (
            label, target, len(relative)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
