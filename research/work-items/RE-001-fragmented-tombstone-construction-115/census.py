"""Caller census for node #115 FragmentedRangeTombstoneIterator construction.

Method (same as the neighbouring RE packets): scan of the .text
file bytes for e8/e9 opcodes, decoding the rel32 target in objdump
virtual-address space (.text file offset = VA - 0x1000), plus a
whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target. Additionally a
vtable-install scan: every RIP-relative lea resolving to the
FragmentedRangeTombstoneIterator vtable start (0x64ccae0) or slot 0
(0x64ccaf0), and every imm32 of those values, which enumerates every
constructor (including a copy/move constructor, if one exists) of the
class. Every site reported here was additionally confirmed as a real
instruction in objdump output disassembled from its containing FDE
start (see records.json).
"""

import re
import struct
import sys

TARGETS = (
    0x5F31380,  # ctor A (raw list)
    0x5F31470,  # ctor List (shared_ptr<FragmentedRangeTombstoneList>)
    0x5F315A0,  # ctor Cache (shared_ptr<FragmentedRangeTombstoneListCache>)
    0x5F33950,  # SplitBySnapshot
    0x5F31250,  # SplitBySnapshot's list probe
    0x5F33670,  # SplitBySnapshot's map emplace
    0x5F269E0,  # TruncatedRangeDelIterator::SplitBySnapshot
    0x5F2EB90,  # list index once-initializer (address-taken only)
    0x5F32900,  # MaxCoveringTombstoneSeqnum (consumer census cross-check)
    0x5F32A10,  # D1 dtor (vtable-only)
    0x5F32B80,  # D0 dtor (vtable-only)
)
VTABLE_START = 0x64CCAE0
VTABLE_SLOT0 = 0x64CCAF0
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8


def scan(path="work/hl-node-115.bin"):
    data = open(path, "rb").read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls = {t: [] for t in TARGETS}
    tails = {t: [] for t in TARGETS}
    for m in re.finditer(b"[\xe8\xe9]", text):
        i = m.start()
        if i + 5 > len(text):
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        va = TEXT_OFF + i + 0x1000
        target = va + 5 + rel
        if target in calls:
            (calls if text[i] == 0xE8 else tails)[target].append(va)
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
    # Vtable-install scan for both the vtable start and slot 0.
    installs = {VTABLE_START: [], VTABLE_SLOT0: []}
    for vt in installs:
        imm = struct.pack("<i", vt)
        start = 0
        while True:
            j = text.find(imm, start)
            if j < 0:
                break
            installs[vt].append(("imm32", TEXT_OFF + j + 0x1000))
            start = j + 1
    for m in re.finditer(b"\x48\x8d", text):
        i = m.start()
        if i + 7 > len(text):
            continue
        modrm = text[i + 2]
        if (modrm & 0xC7) == 0x05:  # mod=00, rm=101: RIP-relative
            rel = struct.unpack_from("<i", text, i + 3)[0]
            va = TEXT_OFF + i + 0x1000
            if va + 7 + rel in installs:
                installs[va + 7 + rel].append(("lea", va))
    return calls, tails, hits, slots, installs


def main(path="work/hl-node-115.bin"):
    calls, tails, hits, slots, installs = scan(path)
    for t in TARGETS:
        print("target", hex(t))
        print("  direct calls:", " ".join(hex(v) for v in calls[t]) if calls[t] else "(none)")
        print("  tail jumps:", " ".join(hex(v) for v in tails[t]) if tails[t] else "(none)")
        print("  qword hits (file offsets):",
              " ".join(hex(v) for v in hits[t]) if hits[t] else "(none)")
        print("  RELATIVE slots:", " ".join(hex(v) for v in slots[t]) if slots[t] else "(none)")
    for vt in (VTABLE_START, VTABLE_SLOT0):
        print("vtable", hex(vt), "installs:",
              " ".join("%s@%s" % (k, hex(v)) for k, v in installs[vt]) if installs[vt] else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
