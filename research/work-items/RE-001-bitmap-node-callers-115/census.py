"""Caller census for node #115 bitmap-node ctor callers.

Method (same as the neighbouring RE packets): per-byte scan of
the .text file bytes for e8/e9 opcodes, decoding the rel32 target in
objdump virtual-address space (.text file offset = VA - 0x1000), plus
a whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target. Prints the
direct call sites, tail jumps, qword hits and RELATIVE slots.
Every site reported here was additionally confirmed as a real
call/jump instruction in objdump output disassembled from its
containing FDE start (see gen_records.py). Note: a vtable slot is
zero in the file and is resolved only by its RELATIVE entry, so any
qword hit that is a RELATIVE entry's addend field is not a separate
reference.
"""

import struct
import sys

TARGETS = (
    0x60F4A00,  # bitmap-node ctor: nine direct callers
    0x612A800,  # reset helper A: count from *(arg1)+0xcc
    0x612A8A0,  # reset helper B: count 0
    0x612A940,  # reset helper C: count 0
    0x612A9E0,  # reset helper D: count 0
    0x612AA80,  # reset helper E: count 0
    0x60F4900,  # bitmap-node dtor
    0x60F4D10,  # 0x120-byte consumer factory
    0x60F4840,  # trailing-u32 magnitude helper
    0x60F48A0,  # trailing-u32 kind helper
    0x612CEB0,  # sign/magnitude split helper
    0x612CE30,  # trailing-u16 helper
    0x612CE90,  # tag helper (sibling, one other caller)
    0x60F50C0,  # 0x178-byte consumer materialize
    0x6106790,  # slot release helper
    0x61841A0,  # poll-copy helper
    0x6184300,  # oneshot prep (one caller: host 0x61849e0)
    0x61572D0,  # big prep (one caller in this packet: host 0x6186e30)
)
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8


def main(path="work/hl-node-115.bin"):
    data = open(path, "rb").read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls = {t: [] for t in TARGETS}
    tails = {t: [] for t in TARGETS}
    for i in range(len(text) - 5):
        op = text[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            va = TEXT_OFF + i + 0x1000
            target = va + 5 + rel
            if target in calls:
                (calls if op == 0xE8 else tails)[target].append(hex(va))
    hits = {t: [] for t in TARGETS}
    for t in TARGETS:
        pat = struct.pack("<Q", t)
        start = 0
        while True:
            j = data.find(pat, start)
            if j < 0:
                break
            hits[t].append(hex(j))
            start = j + 1
    slots = {t: [] for t in TARGETS}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add in slots:
            slots[add].append(hex(ro))
    for t in TARGETS:
        print("target", hex(t))
        print("  direct calls:", " ".join(calls[t]) if calls[t] else "(none)")
        print("  tail jumps:", " ".join(tails[t]) if tails[t] else "(none)")
        print("  qword hits (file offsets):",
              " ".join(hits[t]) if hits[t] else "(none)")
        print("  RELATIVE slots:", " ".join(slots[t]) if slots[t] else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
