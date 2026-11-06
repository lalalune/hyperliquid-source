"""Caller census for node #115 OptionTypeInfo::AsCustomSharedPtr<SliceTransform>.

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
    0x6083A90,  # builder: AsCustomSharedPtr<SliceTransform>
    0x607D190,  # std::function manager for the lambda
    0x60809E0,  # std::function _M_invoke for the lambda
    0x61CA3D0,  # create-by-name host
    0x61C9D70,  # registry find (SliceTransform type node)
    0x61CCFA0,  # pthread_once registry initializer
    0x5E332C0,  # OptionTypeInfo record-copy helper
)
# NOTE: 0x5d350c0 (the counted-base release helper, _M_release) is a
# generic helper called from the invoker's release path (site
# 0x6080a51) and the host's release paths (sites 0x61ca957 via the
# 0x5d35070 dispose helper and 0x61cb0b7). It is recorded as a
# packet_internal_site in records.json, not a census target:
# enumerating its every caller adds no RE value. The same holds for
# the record destructor 0x5d3f950 (builder landing-pad site
# 0x6083c55), the dispose helper 0x5d35070 (host sites 0x61ca957,
# 0x61cb0b7), the translators 0x609e510 (host site 0x61ca53b) and
# 0x609e2d0 (host site 0x61ca9c9), the Status builder 0x61cf670
# (host sites 0x61cabc8, 0x61cae1b, 0x61cafbc, 0x61cb05c) and the
# registry helpers 0x61f8b60 (init site 0x61ccfd0) and 0x61cbd50
# (init site 0x61ccfd8).
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
