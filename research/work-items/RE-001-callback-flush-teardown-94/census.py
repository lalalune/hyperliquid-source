"""Caller census for the 0x5165b80 flush-and-teardown window.

Scans every byte offset of the .text file range (not a regex scan, so a
call opcode starting inside a previous match window is still found) for
E8 direct calls and E9 tail jumps whose target is 0x5165b80, and scans
the whole file for 8-byte little-endian qwords equal to 0x5165b80.

Objdump-displayed addresses map to file offsets as VA - 0x1000 (verified
against the window entry bytes f3 0f 1e fa at file offset 0x5164b80).

Run from the repository root:
  python3 research/work-items/RE-001-callback-flush-teardown-94/census.py
"""

import struct
import sys

BINARY = "work/hl-node-94.bin"
TEXT_OFF, TEXT_SIZE = 0x1342C80, 0x431C430
TARGET = 0x5165B80


def main():
    sys.dont_write_bytecode = True
    data = open(BINARY, "rb").read()
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls, jumps = [], []
    for i in range(len(seg) - 5):
        op = seg[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            va = i + 0x1000
            if va + 5 + rel == TARGET:
                (calls if op == 0xE8 else jumps).append(va)
    qword = struct.pack("<Q", TARGET)
    qw, start = [], 0
    while True:
        j = data.find(qword, start)
        if j < 0:
            break
        qw.append(j)
        start = j + 1
    print("direct_calls:", [hex(c) for c in calls])
    print("tail_jumps:", [hex(j) for j in jumps])
    print("qword_file_offsets:", [hex(o) for o in qw])
    print("counts: calls=%d jumps=%d qwords=%d" % (len(calls), len(jumps), len(qw)))


if __name__ == "__main__":
    main()
