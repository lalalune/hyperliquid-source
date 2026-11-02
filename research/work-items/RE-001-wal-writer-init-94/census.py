"""Caller census for RE-001-wal-writer-init-94: scan .text for direct calls
(e8) and tail jumps (e9) to the initializer window, and scan the whole file
for qword references to the window address.

.text: file offset 0x1342c80, vaddr 0x1343c80, size 0x431c430.
"""

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

TARGET = 0x51645D0


def main():
    with open(BINARY, "rb") as handle:
        data = handle.read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls, jumps = [], []
    # Per-byte scan, not a regex scan: a regex match window consumes
    # its 5 bytes, so a call opcode starting inside a previous match
    # is silently skipped.
    for i in range(len(text) - 5):
        opcode = text[i]
        if opcode not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        if TEXT_VADDR + i + 5 + rel == TARGET:
            (calls if opcode == 0xE8 else jumps).append(TEXT_VADDR + i)
    print("initializer", hex(TARGET), "calls:", [hex(c) for c in calls],
          "tail jumps:", [hex(j) for j in jumps])
    qword = struct.pack("<Q", TARGET)
    offsets, idx = [], 0
    while True:
        pos = data.find(qword, idx)
        if pos < 0:
            break
        offsets.append(pos)
        idx = pos + 1
    print("initializer", "qword file offsets:", [hex(o) for o in offsets])


if __name__ == "__main__":
    sys.exit(main())
