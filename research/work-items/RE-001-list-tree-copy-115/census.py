"""Reproduce the reference census for the
RE-001-list-tree-copy-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-list-tree-copy-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    the list-tree copy routine (0x5d4caa0).
  * Scan the raw binary for an 8-byte little-endian qword equal to
    the routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    the routine address.

Expected result for the digest-verified node #115 work binary:
routine 0x5d4caa0: exactly 3 direct calls (the self-recursive
calls at 0x5d4caef and 0x5d4cb47, and the external call at
0x5d80ee3), exactly 0 tail jumps, 0 stored qwords, 0 RELATIVE
addends.
"""

import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x5D4CAA0


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {"call": set(), "jmp": set()}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5d4caa0)\b")
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[match.group(2)].add(int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        raise AssertionError("objdump failed")
    data = BINARY.read_bytes()
    relocations = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    needle = struct.pack("<Q", TARGET)
    qwords, index = [], 0
    while True:
        hit = data.find(needle, index)
        if hit < 0:
            break
        qwords.append(hit)
        index = hit + 1
    relative = [line for line in relocations.splitlines()
                if ("%x" % TARGET) in line and "RELATIVE" in line]
    calls = sorted(found["call"])
    print("routine %#x: direct calls: %s"
          % (TARGET, ["%#x" % site for site in calls]))
    print("tail jumps: %s" % ["%#x" % site for site in sorted(found["jmp"])])
    print("stored qwords: %s" % qwords)
    print("RELATIVE addends: %d" % len(relative))


if __name__ == "__main__":
    main()
