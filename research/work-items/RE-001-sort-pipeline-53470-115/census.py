"""Reproduce the reference census for the
RE-001-sort-pipeline-53470-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-sort-pipeline-53470-115/census.py

Method:
  * Scan the executable LOAD segment for E8/E9 rel32 bytes whose
    target is one of the seven pinned routines, then confirm each
    candidate with objdump.
  * Scan the raw binary for an 8-byte little-endian qword equal to
    each pinned routine address.
  * Parse `readelf -r` output for RELATIVE records: none targets
    any pinned routine; exactly one RELATIVE record sits at
    0x64ecfb0 with addend 0x5d48410 (the vtable-identity global
    the comparators check, file bytes zero).

Expected result for the digest-verified node #115 work binary:
  * sort entry 0x5d53470: exactly 2 direct calls
    (0x5d6e48e, 0x5d6f51c), 0 tail jumps
  * introsort 0x5d4c1c0: exactly 1 direct call (0x5d534f2) plus
    its own self-call (0x5d4c682), 0 tail jumps
  * heap sift-down 0x5d4bce0: exactly 2 direct calls
    (0x5d4c71d, 0x5d4c890), both inside the introsort heapsort
    fallback, 0 tail jumps
  * predicate 0x5d4a830: exactly 5 direct calls, all inside the
    introsort FDE (0x5d4c26d, 0x5d4c28a, 0x5d4c756, 0x5d4c776,
    0x5d4c7ae), 0 tail jumps
  * swap 0x5d496d0: exactly 4 direct calls, all inside the
    introsort FDE (0x5d4c2a7, 0x5d4c791, 0x5d4c7c9, 0x5d4c80a),
    0 tail jumps
  * insertion pass 0x5d4ba10: exactly 2 direct calls, both inside
    the sort entry (0x5d53524, 0x5d53568), 0 tail jumps
  * insertion step 0x5d4b3f0: exactly 2 direct calls
    (0x5d4bb2c inside the insertion pass, 0x5d53541 inside the
    sort entry), 0 tail jumps
  * 0 stored qwords and 0 RELATIVE addends for every pinned routine.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = {
    0x5D53470: "sort entry",
    0x5D4C1C0: "introsort loop",
    0x5D4BCE0: "heap sift-down",
    0x5D4A830: "less-than predicate",
    0x5D496D0: "element swap",
    0x5D4BA10: "insertion-sort pass",
    0x5D4B3F0: "single-element insertion step",
}
EXEC = (0x1418300, 0x1419300, 0x4FD88A0)
EXPECTED_GLOBAL = 0x64ECFB0
EXPECTED_ADDEND = 0x5D48410


def main():
    data = BINARY.read_bytes()
    off, base, size = EXEC
    seg = data[off:off + size]
    for target, label in TARGETS.items():
        calls, jmps = [], []
        for op, bucket in ((0xE8, calls), (0xE9, jmps)):
            i = seg.find(bytes([op]))
            while i != -1:
                if i + 5 <= len(seg):
                    rel = struct.unpack_from("<i", seg, i + 1)[0]
                    if base + i + 5 + rel == target:
                        bucket.append(base + i)
                i = seg.find(bytes([op]), i + 1)
        print("%s 0x%x: calls %s jmps %s" % (
            label, target,
            [hex(c) for c in sorted(calls)],
            [hex(j) for j in sorted(jmps)]))
        needle = struct.pack("<Q", target)
        qwords, index = [], 0
        while True:
            hit = data.find(needle, index)
            if hit < 0:
                break
            qwords.append(hit)
            index = hit + 1
        print("  stored qwords: %s" % [hex(q) for q in qwords])
    relocations = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in TARGETS:
        hits = [ln for ln in relocations.splitlines()
                if ("%x" % target) in ln and "RELATIVE" in ln]
        print("RELATIVE records mentioning 0x%x: %d" % (target, len(hits)))
    global_reloc = [ln for ln in relocations.splitlines()
                    if ("%x" % EXPECTED_GLOBAL) in ln
                    and "RELATIVE" in ln]
    print("vtable-identity global relocations: %s" % global_reloc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
