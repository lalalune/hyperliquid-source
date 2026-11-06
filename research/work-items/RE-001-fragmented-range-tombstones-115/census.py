"""Caller census for node #115 fragmented-range-tombstone construction.

Method (same as the neighbouring RE packets): scan of the .text
file bytes for e8/e9 opcodes, decoding the rel32 target in objdump
virtual-address space (.text file offset = VA - 0x1000), plus a
whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target. The opcode scan
uses numpy vectorisation; the semantics are identical to the
per-byte loop the neighbouring packets use. Prints the direct call
sites, tail jumps, qword hits and RELATIVE slots. Every site
reported here was additionally confirmed as a real call/jump
instruction in objdump output disassembled from its containing FDE
start (see records.json).
"""

import struct
import sys

TARGETS = (
    0x5F0A3D0,  # host: MemTable::ConstructFragmentedRangeTombstones
    0x60B21F0,  # ReadOptions::ReadOptions()
    0x5F04F80,  # std::__adjust_heap for 16-byte entries
    0x5F053D0,  # std::__introsort_loop for 16-byte entries
    0x5F05120,  # std::__insertion_sort for 16-byte entries
    0x5F37410,  # FragmentedRangeTombstoneListCache ctor
    0x5F059B0,  # node-tree list release
    0x5F36C70,  # FragmentedRangeTombstoneList::FragmentTombstones
)
# NOTE: the two generic helpers below are packet windows, not census
# targets. They are libstdc++/RocksDB-wide helpers with 100+ call
# sites each (Cleanable ctor 0x61bd0c0: 103, Cleanable::DoCleanup
# 0x61bd0e0: 223 + 32 tails); enumerating every caller adds no RE
# value. The packet pins the sites THIS behaviour uses instead, as
# packet_internal_sites in records.json (verified in verify.py).
GENERIC_HELPERS = (0x61BD0C0, 0x61BD0E0)
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8


def scan(path="work/hl-node-115.bin"):
    import numpy as np
    data = open(path, "rb").read()
    text = np.frombuffer(data[TEXT_OFF:TEXT_OFF + TEXT_SIZE],
                         dtype=np.uint8)
    calls = {t: [] for t in TARGETS}
    tails = {t: [] for t in TARGETS}
    for op, dest in ((0xE8, calls), (0xE9, tails)):
        pos = np.flatnonzero(text == op)
        if len(pos) == 0:
            continue
        idx = (pos[:, None] + np.arange(1, 5)).ravel()
        b = text[idx].reshape(-1, 4).astype(np.int64)
        rel = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16) | (b[:, 3] << 24)
        rel = np.where(rel >= 2 ** 31, rel - 2 ** 32, rel)
        va = TEXT_OFF + pos + 0x1000
        tgt = va + 5 + rel
        for t in TARGETS:
            dest[t].extend(int(v) for v in va[tgt == t])
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
