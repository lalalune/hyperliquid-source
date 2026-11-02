"""Caller census for RE-001-wal-writer-94: scan .text for direct calls
(e8) and tail jumps (e9) to the AddRecord and EmitFragment windows, and
scan the whole file for qword references to either window address.

.text: file offset 0x1342c80, vaddr 0x1343c80, size 0x431c430.
"""

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

TARGETS = {"AddRecord": 0x5163730, "EmitFragment": 0x5163550}


def main():
    with open(BINARY, "rb") as handle:
        data = handle.read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for name, target in TARGETS.items():
        calls, jumps = [], []
        for i in range(len(text) - 5):
            opcode = text[i]
            if opcode not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VADDR + i + 5 + rel == target:
                (calls if opcode == 0xE8 else jumps).append(TEXT_VADDR + i)
        print(name, hex(target), "calls:", [hex(c) for c in calls],
              "tail jumps:", [hex(j) for j in jumps])
        qword = struct.pack("<Q", target)
        offsets, idx = [], 0
        while True:
            pos = data.find(qword, idx)
            if pos < 0:
                break
            offsets.append(pos)
            idx = pos + 1
        print(name, "qword file offsets:", [hex(o) for o in offsets])


if __name__ == "__main__":
    sys.exit(main())
