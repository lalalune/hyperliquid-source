"""Caller census for node #115 SystemClockWrapper vtable.

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
    0x609D760,  # slot 2: Customizable::GetOption
    0x609DC40,  # slot 3: Customizable::AreEquivalent
    0x5D32560,  # slot 4: returns empty std::string (C++ name open)
    0x5FCF590,  # slot 5: SystemClockWrapper::PrepareOptions
    0x6096790,  # slot 6: Configurable::ValidateOptions
    0x5D2E090,  # slot 7: Customizable::GetOptionsPtr
    0x60956F0,  # slot 8: returns empty Status (C++ name open)
    0x609D0E0,  # slot 9: Configurable::ConfigureOptions
    0x60986B0,  # slot 10: Configurable::ParseOption
    0x6095710,  # slot 11: Configurable::OptionsAreEqual
    0x5FCDAE0,  # slot 12: SystemClockWrapper::SerializeOptions
    0x609D980,  # slot 13: Customizable::GetOptionName
    0x5D32A30,  # slot 15: Customizable::GetId
    0x5D2E770,  # slot 16: Customizable::IsInstanceOf (by contract from #3715)
    0x5D2CA10,  # slot 18: returns "" (by contract from #3715)
    0x5FCC3F0,  # slot 17: returns *(this+0x20) (the wrapped clock)
    0x5D4D490,  # slot 19: SystemClockWrapper::NowMicros
    0x5FCC340,  # slot 20: forwards to wrapped slot 20 (NowNanos)
    0x5FCC360,  # slot 21: forwards to wrapped slot 21 (CPUMicros)
    0x5FCC380,  # slot 22: forwards to wrapped slot 22 (CPUNanos)
    0x5DD41A0,  # slot 23: SystemClockWrapper::SleepForMicroseconds
    0x5D4B100,  # slot 24: GetCurrentTime (by contract from #3352)
    0x5FCC3A0,  # slot 25: SystemClockWrapper::TimeToString
    0x60257A0,  # EmulatedSystemClock slot 14: Name() -> "TimeEmulatedSystemClock"
    0x60259E0,  # EmulatedSystemClock slot 19: NowMicros
    0x60259A0,  # EmulatedSystemClock slot 20: NowNanos
    0x6025A30,  # EmulatedSystemClock slot 21: CPUMicros
    0x6025A10,  # EmulatedSystemClock slot 22: CPUNanos
    0x6025B40,  # EmulatedSystemClock slot 23: SleepForMicroseconds
    0x6025EB0,  # EmulatedSystemClock slot 24: GetCurrentTime
    0x5FE0FE0,  # PosixClock slot 14: Name() -> "DefaultClock"
    0x5D2CA00,  # PosixClock slot 17: returns null
    0x5FE0FF0,  # PosixClock slot 18: returns "PosixClock"
    0x5FE1480,  # PosixClock slot 21: CPUMicros
    0x5FE1430,  # PosixClock slot 22: CPUNanos
    0x5FD0090,  # SystemClockWrapper ctor C1 (re-shipped from #3352)
    0x6029500,  # SystemClockWrapper dtor D0 (by contract; installs base vtable mid-teardown)
    0x5FE2680,  # PosixClock accessor (the default clock installed by PrepareOptions)
    0x6095E70,  # Configurable::PrepareOptions (the base PrepareOptions)
    0x609DE80,  # Customizable::SerializeOptions (the base SerializeOptions)
)
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
