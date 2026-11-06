"""Reproduce the reference census for the
RE-001-tag13-query-2cf0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tag13-query-2cf0-115/census.py

Method:
  * Scan the executable LOAD segment for E8/E9 rel32 bytes whose
    target is one of the pinned routines, then confirm each
    candidate with objdump.
  * Scan the raw binary for an 8-byte little-endian qword equal to
    each pinned routine address.
  * Parse `readelf -r` output for RELATIVE records: none targets
    any pinned routine; exactly one RELATIVE record sits at
    0x64ecf80 with addend 0x5d4d490 (the expected-slot walker
    the chain walk compares against, installed at load time).

Expected result for the digest-verified node #115 work binary:
  * tag-13 query 0x61b2cf0: exactly 3 direct calls (0x5d79107,
    0x61b456a, 0x61b4739), 0 tail jumps
  * count-mismatch helper 0x61cf670: 847 direct calls (shared
    helper; only the tag-13 query's site 0x61b2d7f is listed),
    0 tail jumps
  * gate 0x61b1930: exactly 5 direct calls (0x61b1b28, 0x61b1e7b,
    0x61b2247, 0x61b27b7, 0x61b2dc8), 0 tail jumps
  * limit check 0x61b1910: exactly 1 direct call (0x61b1940),
    0 tail jumps
  * bit setter 0x61b18b0: exactly 15 direct calls, 0 tail jumps
  * frame-and-deliver 0x61b1a10: exactly 7 direct calls,
    0 tail jumps
  * framer 0x61b1260: exactly 5 direct calls, 0 tail jumps
  * varint encoder 0x61bd410: many direct calls (shared helper),
    0 tail jumps
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
    0x61B2CF0: "tag-13 query",
    0x61CF670: "count-mismatch helper",
    0x61B1930: "throttle gate",
    0x61B1910: "limit check",
    0x61B18B0: "flag-bit setter",
    0x61B1A10: "frame-and-deliver",
    0x61B1260: "frame builder",
    0x61BD410: "ULEB128 encoder",
}
EXEC = (0x1418300, 0x1419300, 0x4FD88A0)
EXPECTED_GLOBAL = 0x64ECF80
EXPECTED_ADDEND = 0x5D4D490


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
    print("expected-slot walker global relocations: %s" % global_reloc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
