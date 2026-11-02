"""Caller census for node #94 0x516adf0 (the shard array construction).

Method (same as the neighbouring RE-001 packets): per-byte scan of
the .text file bytes for e8/e9 opcodes, decoding the rel32 target in
objdump virtual-address space (.text file offset = VA - 0x1000), plus
a whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target.  Prints the
direct call sites, tail jumps, qword hits and RELATIVE slots.
"""

import struct
import sys

TARGET = 0x516ADF0
TEXT_OFF, TEXT_SIZE = 0x1342C80, 0x431C430
RELA_OFF, RELA_SIZE = 0x6BC0, 0x1D4E10


def main(path="work/hl-node-94.bin"):
    data = open(path, "rb").read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls, tails = [], []
    for i in range(len(text) - 5):
        op = text[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            va = TEXT_OFF + i + 0x1000
            if va + 5 + rel == TARGET:
                (calls if op == 0xE8 else tails).append(hex(va))
    print("direct calls:", " ".join(calls) if calls else "(none)")
    print("tail jumps:", " ".join(tails) if tails else "(none)")
    pat = struct.pack("<Q", TARGET)
    hits, start = [], 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        hits.append(hex(j))
        start = j + 1
    print("qword hits (file offsets):", " ".join(hits) if hits else "(none)")
    slots = []
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add == TARGET:
            slots.append(hex(ro))
    print("RELATIVE slots:", " ".join(slots) if slots else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
