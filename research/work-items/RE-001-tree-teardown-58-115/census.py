"""Reproduce the reference census for the RE-001-tree-teardown-58-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tree-teardown-58-115/census.py

Method:
  * Stream the whole-binary disassembly through objdump and keep
    only direct calls and tail jumps whose displayed target is
    the teardown (0x5d4d250).
  * Scan the raw binary for 8-byte little-endian qwords equal to
    the routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    the routine address.

Expected result for the digest-verified node #115 work binary:
teardown: see the printed lists; verify.py asserts them exactly.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D4D250,)


def main():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    found = {target: {"call": set(), "jmp": set()} for target in TARGETS}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+"
        r"(5d4d250)\b")
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        raise SystemExit("objdump failed")
    data = BINARY.read_bytes()
    for target in TARGETS:
        qwords = []
        for off in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, off)[0] == target:
                qwords.append(off + 0x1000)
        print("routine %#x: direct calls: %s"
              % (target, sorted("%#x" % c for c in found[target]["call"])))
        print("routine %#x: tail jumps: %s"
              % (target, sorted("%#x" % j for j in found[target]["jmp"])))
        print("routine %#x: stored qwords: %s"
              % (target, ["%#x" % q for q in qwords]))
    text = subprocess.run(["readelf", "-r", str(BINARY)],
                          capture_output=True, text=True,
                          check=True).stdout
    for target in TARGETS:
        count = 0
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                count += 1
        print("routine %#x: RELATIVE addends: %d" % (target, count))


if __name__ == "__main__":
    main()
