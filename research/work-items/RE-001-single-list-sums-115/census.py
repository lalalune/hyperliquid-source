"""Census for the RE-001 single-list-sums windows.

Scans the whole node #115 binary for direct e8 calls, e9 tail jumps,
qword hits, and RELATIVE relocation addends targeting the five window
starts. Addresses follow objdump's convention for this binary:
address = file offset + 0x1000.

Run from the repository root:
    python3 research/work-items/RE-001-single-list-sums-115/census.py
"""

import os
import struct
import sys

# Five windows plus the composite's sole G callee, whose only caller is
# also census-checked.
TARGETS = [0x5F13060, 0x5F13100, 0x5EEB510, 0x5EEB540, 0x5EEB570,
           0x5F6AD70]


def main():
    repo = os.path.join(os.path.dirname(__file__), "..", "..", "..")
    data = open(os.path.join(repo, "work", "hl-node-115.bin"), "rb").read()

    def vma(foff):
        return foff + 0x1000

    for target in TARGETS:
        calls = []
        jumps = []
        for i in range(len(data) - 5):
            op = data[i]
            if op not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from("<i", data, i + 1)[0]
            if vma(i) + 5 + rel == target:
                (calls if op == 0xE8 else jumps).append(hex(vma(i)))
        qw = []
        start = 0
        while True:
            j = data.find(struct.pack("<Q", target), start)
            if j < 0:
                break
            qw.append(hex(j))
            start = j + 1
        print(f"{target:#x}: e8={calls} e9={jumps} qword_file_offsets={qw}")

    for base, size, name in [(0x6BE8, 0x163CC8, "rela.dyn"),
                             (0x16A8B0, 0x1A10, "rela.plt")]:
        hits = []
        for off in range(base, base + size, 24):
            _o, info, add = struct.unpack_from("<QQq", data, off)
            if add in TARGETS:
                hits.append((hex(off), hex(_o), info & 0xFFFFFFFF,
                             hex(add)))
        print(f"{name}: addend hits: {hits if hits else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
