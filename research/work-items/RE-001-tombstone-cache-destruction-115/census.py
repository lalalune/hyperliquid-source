"""Caller census for node #115 tombstone-cache destruction.

Method (same as the neighbouring RE packets): scan of the .text
file bytes for e8/e9 opcodes, decoding the rel32 target in objdump
virtual-address space (.text file offset = VA - 0x1000), plus a
whole-file qword search for the target VA and a .rela.dyn parse for
R_X86_64_RELATIVE slots whose addend is the target.
"""
import struct, sys
import numpy as np

TARGETS = (
    0x5F061B0,  # _Sp_counted_ptr_inplace<Cache>::_M_dispose
    0x5F0B080,  # unique_ptr<List>::~unique_ptr
    0x5F10D40,  # MemTable::~MemTable
    0x605E8A0,  # AllocTracker::FreeMem
    0x605E860,  # AllocTracker::DoneAllocating
    0x606A890,  # WriteBufferManager::FreeMem
    0x5F0A290,  # _Sp_counted_ptr_inplace<const shared_ptr<Cache>>::_M_dispose
    0x5F10180,  # ConcurrentArena::~ConcurrentArena D1
    0x5F10D00,  # ConcurrentArena::~ConcurrentArena D0
    0x5F05B80,  # rb-erase, 0x30-byte nodes
    0x5F06770,  # rb-erase, 0x60-byte nodes
    0x5ECD650,  # unique_ptr<FlushJobInfo>::~unique_ptr
    0x5F103F0,  # MemTable::MemTable C1
)
GENERIC_HELPERS = (0x5F053D0, 0x5F05120, 0x5F04F80, 0x61BD0E0, 0x5F059B0)
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

def scan(path="work/hl-node-115.bin"):
    data = open(path, "rb").read()
    text = np.frombuffer(data[TEXT_OFF:TEXT_OFF + TEXT_SIZE], dtype=np.uint8)
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
        print("  direct calls:", " ".join(hex(v) for v in sorted(set(calls[t]))) if calls[t] else "(none)", f"({len(set(calls[t]))} unique, {len(calls[t])} raw)")
        print("  tail jumps:", " ".join(hex(v) for v in sorted(set(tails[t]))) if tails[t] else "(none)", f"({len(set(tails[t]))} unique, {len(tails[t])} raw)")
        print("  qword hits (file offsets):", " ".join(hex(v) for v in hits[t]) if hits[t] else "(none)")
        print("  RELATIVE slots:", " ".join(hex(v) for v in slots[t]) if slots[t] else "(none)")
    return 0

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
