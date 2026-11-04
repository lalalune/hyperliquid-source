"""Census for the node #115 element-prepare function at 0x5f13310, its
per-element callee 0x5f54ee0, and the guard helpers 0x607c700/0x607c720.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to each window,
for 8-byte little-endian occurrences of each window start, and scans
.rela.dyn/.rela.plt for RELATIVE addends equal to each window start.
Uses bytes.find (C speed) rather than a per-byte Python loop. Prints a
JSON summary to stdout.

Every hit must still be confirmed as a real call by reading its
containing function from its FDE start: the hits to 0x5f13310 are the
e8 calls at 0x5de6e58 and 0x5ed6895; the in-window hit to 0x5f54ee0 is
the e8 call at 0x5f1337c. The other direct calls to 0x5f54ee0 and to
the guard helpers sit in functions whose internals were not read, so
only their sites are listed, not their behavior.
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
TARGETS = (0x5F13310, 0x5F54EE0, 0x607C700, 0x607C720)


def scan_branch(text, opcode, target):
    hits = []
    start = 0
    needle = bytes([opcode])
    while True:
        j = text.find(needle, start)
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
        rela_hits = []
        for off, size in [(0x6BE8, 0x163CC8), (0x16A8B0, 0x1A10)]:
            for i in range(off, off + size, 24):
                _, _, addend = struct.unpack_from("<QQq", data, i)
                if addend == target:
                    rela_hits.append(hex(off + (i - off)))
        result[hex(target)] = {
            "direct_calls": scan_branch(text, 0xE8, target),
            "tail_jumps": scan_branch(text, 0xE9, target),
            "qword_hits": qword,
            "relative_addend_hits": rela_hits,
        }
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
