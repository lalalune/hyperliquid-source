"""Reproduce the reference census for the RE-001-resolve-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-resolve-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    the wrapper (0x5d8cf30) or the default leaf (0x5d8ce80).
  * Scan the raw binary for 8-byte little-endian qwords equal to
    either routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    either address.

Expected result for the digest-verified node #115 work binary:
wrapper: no direct calls, no tail jumps; one stored qword, at
file offset 1069888 (0x105340), which is the addend field of
the RELATIVE relocation entry for slot 0x64c9bc8 inside the
.rela.dyn section itself, not a data pointer; one RELATIVE
addend (that same slot). Leaf: ten direct calls, no tail
jumps, no stored qwords, no RELATIVE addends; verify.py
asserts exactly this.
"""

import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D8CF30, 0x5D8CE80)


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {target: {"call": set(), "jmp": set()} for target in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5d8cf30|5d8ce80)\b")
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
