"""Census for the node #115 guard value-exchange chain: the acquire
wrapper 0x607c700, the release wrapper 0x607c720, the exchange core
0x607c3b0, the exchange 0x6078810 and the gated TLS-object getter
0x6078650.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to each window,
for 8-byte little-endian occurrences of each window start in .text,
and scans .rela.dyn/.rela.plt for RELATIVE addends equal to each
window start. Also scans the whole file for 8-byte little-endian
occurrences of each window start (vtable/data references). Uses
bytes.find (C speed) rather than a per-byte Python loop. Prints a
JSON summary to stdout.

Every hit must still be confirmed as a real call by reading its
containing function from its FDE start: the hits to 0x607c700 are
the e8 calls at 0x5e00207 (in 0x5dff230..0x5e019df), 0x5e03e20 (in
0x5e03db0..0x5e053e9), 0x5e08132 (in 0x5e080f0..0x5e095ed), 0x5e0b26d
(in 0x5e0b220..0x5e0c68a), 0x5e10a20 (in 0x5e109e0..0x5e114d4),
0x5ed2487 (in 0x5ed2440..0x5ed5cbb), 0x5ed5e5d (in
0x5ed5df0..0x5ed88be), 0x5f13343 (in 0x5f13310..0x5f133da, the
element-prepare window mapped by RE-001-element-prepare-115),
0x5f148e1 (in 0x5f148a0..0x5f14b48), 0x5f14f28 (in
0x5f14e80..0x5f1683d) and 0x5f16a28 (in 0x5f16980..0x5f17752); the
hits to 0x607c720 are the e8 calls at 0x5dfef6f, 0x5dffd38, 0x5e03d3c,
0x5e04ce2, 0x5e07fe7, 0x5e08aed, 0x5e0b1dc, 0x5e0c1a6, 0x5e1095d,
0x5e10c6b, 0x5ed22a6, 0x5ed3ee2, 0x5ed5d81, 0x5ed68e8, 0x5f132e9 (in
the element-prepare unwind cleanup 0x5f132e6..0x5f1330b), 0x5f133a7
(in 0x5f13310..0x5f133da), 0x5f14877, 0x5f149c2, 0x5f14df5, 0x5f14f72,
0x5f168ce and 0x5f1744f (containing FDEs listed in records.json);
the only hits to 0x607c3b0 are the two in-window e8 calls at
0x607c70a and 0x607c72a; the only hit to 0x6078810 is the e9 tail
jump at 0x607c3d2 inside the core; the hits to 0x6078650 are the e8
call at 0x6078817 inside the exchange plus seven e8 calls in the
neighbouring small wrappers at 0x607868f (in 0x6078680..0x60786ab),
0x60786b8 (in 0x60786b0..0x60786c8), 0x60786d8 (in
0x60786d0..0x6078707), 0x607871f (in 0x6078710..0x607873c), 0x6078748
(in 0x6078740..0x607875e), 0x607876f (in 0x6078760..0x60787a5) and
0x60787b8 (in 0x60787b0..0x60787e2), whose internals are not claimed.
"""

import json
import struct
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = REPO_ROOT / "work" / "hl-node-115.bin"
TEXT_VMA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700
TARGETS = (0x607C700, 0x607C720, 0x607C3B0, 0x6078810, 0x6078650)


def scan_branch(text, opcode, target):
    hits = []
    start = 0
    while True:
        j = text.find(bytes([opcode]), start)
        if j < 0 or j + 5 > len(text):
            break
        rel = struct.unpack_from("<i", text, j + 1)[0]
        if TEXT_VMA + j + 5 + rel == target:
            hits.append(hex(TEXT_VMA + j))
        start = j + 1
    return hits


def main():
    data = BINARY.read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    result = {}
    for target in TARGETS:
        qword = []
        start = 0
        needle = struct.pack("<Q", target)
        while True:
            j = text.find(needle, start)
            if j < 0:
                break
            qword.append(hex(TEXT_VMA + j))
            start = j + 1
        whole_file = []
        start = 0
        while True:
            j = data.find(needle, start)
            if j < 0:
                break
            whole_file.append(hex(j))
            start = j + 1
        rela_hits = []
        for off, size in [(0x6BE8, 0x163CC8), (0x16A8B0, 0x1A10)]:
            for i in range(off, off + size, 24):
                _, _, addend = struct.unpack_from("<QQq", data, i)
                if addend == target:
                    rela_hits.append(hex(i))
        result[hex(target)] = {
            "direct_calls": scan_branch(text, 0xE8, target),
            "tail_jumps": scan_branch(text, 0xE9, target),
            "qword_hits": qword,
            "qword_hits_whole_file": whole_file,
            "relative_addend_hits": rela_hits,
        }
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
