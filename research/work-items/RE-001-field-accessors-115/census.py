"""Reproduce the reference census for the
RE-001-field-accessors-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-field-accessors-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    one of the three accessor leaves (0x5d8d0c0, 0x5d8d0d0,
    0x5d8d0e0).
  * Scan the raw binary for an 8-byte little-endian qword equal
    to each leaf address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    any leaf address.

Expected result for the digest-verified node #115 work binary:
filled in by the packet author once the scan completes; the
verify.py checker asserts the exact counts and site lists.
"""

import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D8D0C0, 0x5D8D0D0, 0x5D8D0E0)


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {target: {"call": set(), "jmp": set()} for target in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5d8d0c0|5d8d0d0|5d8d0e0)\b")
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
    for target in TARGETS:
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
        calls = sorted(found[target]["call"])
        print("leaf %#x: direct calls: %s"
              % (target, ["%#x" % site for site in calls]))
        print("leaf %#x: tail jumps: %s"
              % (target, ["%#x" % site for site in sorted(found[target]["jmp"])]))
        print("leaf %#x: stored qwords: %s" % (target, qwords))
        print("leaf %#x: RELATIVE addends: %d" % (target, len(relative)))


if __name__ == "__main__":
    main()
