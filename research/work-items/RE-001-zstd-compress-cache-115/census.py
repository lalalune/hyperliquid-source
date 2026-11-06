"""Caller census for node #115 cached-ZSTD-compress-context windows.

Method (same as the neighbouring RE packets): per-byte scan of
the .text file bytes for e8/e9 opcodes, decoding the rel32 target in
objdump virtual-address space (.text file offset = VA - 0x1000), plus
a whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target. Prints the
direct call sites, tail jumps, qword hits and RELATIVE slots.
Every site reported here was additionally confirmed as a real
call/jump instruction in objdump output disassembled from its
containing FDE start (see records.json).
"""

import struct
import sys

TARGETS = (
    0x61C1C10, 0x6218920, 0x62188A0, 0x62187A0, 0x6212010,
    0x6211A10, 0x62119E0, 0x62117E0, 0x5F041D0, 0x5F03B80, 0x6051A20,
)
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8


def scan(path="work/hl-node-115.bin"):
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
                (calls if op == 0xE8 else tails)[target].append(va)
    hits = {t: [] for t in TARGETS}
    for t in TARGETS:
        pat = struct.pack("<Q", t)
        start = 0
        while True:
            j = data.find(pat, start)
            if j < 0:
                break
            hits[t].append(j)
            start = j + 1
    slots = {t: [] for t in TARGETS}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add in slots:
            slots[add].append(ro)
    return calls, tails, hits, slots


def main(path="work/hl-node-115.bin"):
    calls, tails, hits, slots = scan(path)
    for t in TARGETS:
        print("target", hex(t))
        print("  direct calls:", " ".join(hex(v) for v in calls[t]) if calls[t] else "(none)")
        print("  tail jumps:", " ".join(hex(v) for v in tails[t]) if tails[t] else "(none)")
        print("  qword hits (file offsets):",
              " ".join(hex(v) for v in hits[t]) if hits[t] else "(none)")
        print("  RELATIVE slots:", " ".join(hex(v) for v in slots[t]) if slots[t] else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
