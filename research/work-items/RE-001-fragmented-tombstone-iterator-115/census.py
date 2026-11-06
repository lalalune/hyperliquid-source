"""Caller census for node #115 FragmentedRangeTombstoneIterator.

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
    0x5F32900,  # MaxCoveringTombstoneSeqnum
    0x5F316D0,  # SeekToCoveringTombstone
    0x5F31980,  # SeekForPrevToCoveringTombstone
    0x5F31C80,  # ScanForwardToVisibleTombstone
    0x5F31EB0,  # SeekToTopFirst
    0x5F320A0,  # Seek
    0x5F320F0,  # ScanBackwardToVisibleTombstone
    0x5F32310,  # SeekToTopLast
    0x5F324F0,  # SeekForPrev
    0x5F32540,  # TopNext
    0x5F32720,  # TopPrev
    0x5F32A10,  # ~FragmentedRangeTombstoneIterator (D1)
    0x5F32B80,  # ~FragmentedRangeTombstoneIterator (D0)
    0x5F2E8F0,  # Valid
    0x5F2E8D0,  # SeekToFirst
    0x5F2EE70,  # SeekToLast
    0x5F2EEA0,  # Next
    0x5F2EEF0,  # Prev
    0x5EBA980,  # key
    0x5EBA910,  # value (fragment end key)
    0x5DF7CE0,  # NextAndGetResult (shared InternalIteratorBase impl)
    0x5DF7650,  # slot-11 accessor: key() minus the 8-byte trailer
    0x5F2E7B0,  # status
    0x5DF7670,  # shared bool getter (ret 1)
    0x5DF7680,  # shared bool getter (ret 1)
    0x5DF7690,  # shared bool getter (ret 0)
    0x5D485B0,  # shared void no-op
    0x5F2E790,  # bool getter (ret 0)
    0x5F2E7A0,  # bool getter (ret 1)
    0x5DF7800,  # shared Status builder
    0x5DF76D0,  # shared void no-op
    0x5DF76E0,  # shared void no-op
    0x5DF7640,  # shared bool getter (ret 0)
    0x61BDC40,  # BytewiseComparatorImpl::Compare (slot 0xd0 impl)
    0x61BDC90,  # ReverseBytewiseComparatorImpl::Compare (slot 0xd0 impl)
    0x5D48400,  # builtin slot-0xc8 impl (returns 0)
    0x5D48410,  # builtin slot-0xc8 thunk (forwards to Q->vtable[0x10])
    0x5D44C70,  # GOT-slot forwarder (slot 0xc8 family, identity open)
    0x5EAA060,  # shared helper called by key() (59 sites; identity open)
)
# NOTE: the destructor's generic helpers are packet windows in other
# packets, not census targets here. Cleanable::DoCleanup (0x61bd0e0)
# is reached by the D1 tail jump, _M_release dispose (0x5d35070) by
# two direct calls, and operator delete via the PLT; the packet pins
# those sites as packet_internal_sites in records.json (verified in
# verify.py). The key() helper 0x5eaa060 is a full census target
# because its 59 sites are all real calls (each verified in its FDE).
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
