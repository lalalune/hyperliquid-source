"""Reproduce the reference census for the RE-001-node-tree-60-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node-tree-60-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    the teardown (0x5d4cfd0), the copy (0x5d4d050), or the string
    builder (0x5d4a6a0).
  * Scan the raw binary for 8-byte little-endian qwords equal to
    any of the three routine addresses.
  * Parse `readelf -r` output for RELATIVE records mentioning
    any of the three addresses.

Expected result for the digest-verified node #115 work binary:
teardown: 23 direct calls, no tail jumps, no stored qwords, no
RELATIVE addends. Copy: 4 direct calls, no tail jumps, no
stored qwords, no RELATIVE addends. Builder: 79 direct calls,
no tail jumps, no stored qwords, no RELATIVE addends.
verify.py asserts exactly this.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D4CFD0, 0x5D4D050, 0x5D4A6A0)


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {target: {"call": set(), "jmp": set()} for target in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+"
        r"(5d4cfd0|5d4d050|5d4a6a0)\b")
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
        print("routine %#x: direct calls: %s"
              % (target, ["%#x" % site for site in calls]))
        print("routine %#x: tail jumps: %s"
              % (target, ["%#x" % site for site in sorted(found[target]["jmp"])]))
        print("routine %#x: stored qwords: %s" % (target, qwords))
        print("routine %#x: RELATIVE addends: %d" % (target, len(relative)))


if __name__ == "__main__":
    main()
