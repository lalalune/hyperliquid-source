"""Census for the node #115 rdx-arg getters 0x5eeb6c0/0x5eeb6e0/
0x5eeb700/0x5eeb720 and their callees 0x5e4b550/0x5e4b560/0x5fc9610.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to each window,
for 8-byte little-endian occurrences of each window start in .text,
and scans .rela.dyn/.rela.plt for RELATIVE addends equal to each
window start. Also scans the whole file for 8-byte little-endian
occurrences of each window start (vtable/data references). Uses
bytes.find (C speed) rather than a per-byte Python loop. Prints a
JSON summary to stdout.

Every hit must still be confirmed as a real call by reading its
containing function from its FDE start: the hits to 0x5e4b550 are
the e8 calls at 0x5dd1aff, 0x5e4ef75, 0x5e697f0 and 0x5eeb6cb (the
last inside getter 0x5eeb6c0, mapped in this packet); the hits to
0x5e4b560 are 0x5e4eec1 and 0x5eeb6eb (the last inside getter
0x5eeb6e0); the hits to 0x5fc9610 are 0x5d8bf39, 0x5dd5f7b,
0x5de0057, 0x5de1baf, 0x5dfcec9, 0x5dfdef0, 0x5e872f5, 0x5e8732b,
0x5e87aa1, 0x5e8e84d, 0x5ecc429 and 0x5eeb72f (the last inside getter
0x5eeb720). The four getters themselves have no direct calls, tail
jumps, qword hits or RELATIVE addends anywhere in the file.
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
TARGETS = (0x5EEB6C0, 0x5EEB6E0, 0x5EEB700, 0x5EEB720,
           0x5E4B550, 0x5E4B560, 0x5FC9610)


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
