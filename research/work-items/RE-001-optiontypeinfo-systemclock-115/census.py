"""Caller census for node #115 OptionTypeInfo::AsCustomSharedPtr<SystemClock>.

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
    0x5FD0180,  # builder: AsCustomSharedPtr<SystemClock>
    0x5FCC660,  # std::function manager for the lambda
    0x5FD4C30,  # std::function _M_invoke for the lambda
    0x5FD46C0,  # create-by-name host
    0x5FE2680,  # current-clock function-local-static accessor
    0x5FD20D0,  # pthread_once default-clock initializer
    0x5FCDF70,  # Status move-assignment helper
    0x5E332C0,  # OptionTypeInfo record-copy helper
    0x5FD4080,  # name-to-clock factory helper (host error path)
)
# NOTE: 0x5d350c0 (the counted-base release helper, _M_release) is a
# generic helper called from the invoker's release path (site
# 0x5fd4ca1) and the host's adopt/error paths (sites 0x5fd49c3,
# 0x5fd4955). It is recorded as a packet_internal_site in
# records.json, not a census target: enumerating its every caller
# adds no RE value. The same holds for the record destructor
# 0x5d3f950 (builder site 0x5fd0285), the translators 0x609e510
# (host site 0x5fd489a) and 0x609e2d0 (host site 0x5fd4b76), the
# Status builder 0x61cf670 (host site 0x5fd4bc9) and the cleanup
# helper 0x5d36110 (host site 0x5fd48dd).
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
