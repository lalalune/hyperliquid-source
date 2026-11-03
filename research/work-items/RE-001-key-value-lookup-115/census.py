"""Reproduce the reference census for the
RE-001-key-value-lookup-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-key-value-lookup-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    the key lookup routine (0x5d8cf70) or the second-stage value
    lookup (0x5d8ce90).
  * Scan the raw binary for 8-byte little-endian qwords equal to
    either routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    either address.

Expected result for the digest-verified node #115 work binary:
key lookup: nine direct calls, no tail jumps; value lookup:
eight direct calls and one tail jump (0x5d8cfea, from inside the
key lookup itself); no stored qwords and no RELATIVE addends for
either routine; verify.py asserts exactly this.
"""

import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D8CF70, 0x5D8CE90)


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {target: {"call": set(), "jmp": set()} for target in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5d8cf70|5d8ce90)\b")
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
