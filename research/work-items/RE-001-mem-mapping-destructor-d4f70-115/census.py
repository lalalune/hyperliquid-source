"""Census for the node #115 guarded mem-mapping
release 0x60d4f70.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to the window,
for 8-byte little-endian occurrences of the window start in .text,
and scans .rela.dyn/.rela.plt for RELATIVE addends equal to the
window start. Also scans the whole file for 8-byte little-endian
occurrences of the window start (vtable/data references). Uses
bytes.find (C speed) rather than a per-byte Python loop. Prints a
JSON summary to stdout.

Every hit was confirmed as a real call by disassembling its
containing FDE from the FDE start: the eleven call sites sit in
0x605cc30..0x605cf73 (four, the member destroy mapped by merged
RE-001-destructor-pair-115), 0x605cfd6..0x605cffb (one, an unwind
cleanup block), 0x605d000..0x605d3a1 (one, the arena grow window),
0x605db40..0x605dcb2 (four, a destructor-like body) and
0x60d4fa0..0x60d4fdc (one, the move-assignment neighbour). No tail
jumps, stored qwords or RELATIVE addends reference the window.
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
TARGETS = (0x60D4F70,)


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
