"""Census for the node #115 window at 0x5f6ad70.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to the window,
for 8-byte little-endian occurrences of the window start, and scans
.rela.dyn/.rela.plt for RELATIVE addends equal to the window start.
Uses bytes.find (C speed) rather than a per-byte Python loop. Prints a
JSON summary to stdout.

The single e8 hit must still be confirmed as a real call by reading
its containing function: it is the call at 0x5eeb5b3 inside the
composite getter 0x5eeb570, shown in the verbatim excerpt committed
with PR #2215.
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
TARGET = 0x5F6AD70


def scan_branch(text, opcode):
    hits = []
    start = 0
    needle = bytes([opcode])
    while True:
        j = text.find(needle, start)
        if j < 0 or j + 5 > len(text):
            break
        rel = struct.unpack_from("<i", text, j + 1)[0]
        if TEXT_VMA + j + 5 + rel == TARGET:
            hits.append(hex(TEXT_VMA + j))
        start = j + 1
    return hits


def main():
    data = BINARY.read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    qword = []
    start = 0
    needle = struct.pack("<Q", TARGET)
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
            if addend == TARGET:
                rela_hits.append(hex(off + (i - off)))
    print(json.dumps({
        "direct_calls": scan_branch(text, 0xE8),
        "tail_jumps": scan_branch(text, 0xE9),
        "qword_hits": qword,
        "relative_addend_hits": rela_hits,
    }, indent=1))


if __name__ == "__main__":
    main()
