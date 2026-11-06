"""Unicorn differential for the RE-001-pow10-divisibility-gate
packet: emulate the real routine bytes from the digest-verified
work binary and compare every observable outcome against the
model in tools/pow10_divisibility_gate_da30_115.py.

Usage (from the repository root, with a Python that has the
unicorn package):
    python3 research/work-items/RE-001-pow10-divisibility-gate-da30-115/differential.py

Method: map the routine's own page from the work binary (the
bytes are not patched), the two call slots at 0x64df620 and
0x64df830 with their contents replaced by stub addresses (the
slots are data the routine reads, so pointing them at recording
stubs is what lets the two noreturn exits be observed), a stack
whose top holds a halt address as the return target, a synthetic
context/array/record area, and a sentinel-filled out slot. A
code hook records which stub (or the halt address) is reached
and, for returns, the final out bytes and rax are compared
against the model: tag word, payload written or left untouched,
gap and tail bytes untouched, rax == out.

Cases: every class byte 0..255 against 14 directed values
(0, small, exact multiples and off-by-one neighbours of the
divisors, the 2^32 boundary, 2^64 - 1); 6,000 seeded random
cases over random class bytes, values, elements and indices;
and the exit edges (index == count and above, element == bound
and above, element == bound - 1). 9,597 cases in total. Prints
the per-suite counts and a TOTAL line; exits non-zero on the
first sign of any divergence (all mismatches are printed).
"""

import random
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

sys.path.insert(0, str(ROOT / "tools"))

from pow10_divisibility_gate_da30_115 import (  # noqa: E402
    BoundPanic, GateContext, IndexPanic, pow10_divisibility_gate)

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RSP)

BIN = (ROOT / "work" / "hl-node-115.bin").read_bytes()
START, STOP = 0x593DA30, 0x593DB22
CODE_BASE = 0x593D000
SLOT_PAGE = 0x64DF000
SLOT_A = 0x64DF830   # bound-check exit slot
SLOT_B = 0x64DF620   # index-check exit slot
STUB_A = 0x7F0000
STUB_B = 0x7F1000
HALT = 0x7F2000
STACK = 0x700000
RSP0 = 0x70F000
CTX = 0x1000000
ARR = 0x1100000
REC = 0x1200000
OUT = 0x1500000


def model_outcome(value, index, n, element, bound, tbyte):
    """Run the model on a sentinel out slot; return a comparable
    outcome tuple. On the two exit paths the model raises before
    the record byte is read, so an empty record area suffices
    there (and avoids materialising an area for huge elements)."""
    if index >= n or element >= bound:
        area = b""
    else:
        area = bytearray((element + 1) * 0x158)
        area[element * 0x158 + 0x48] = tbyte
        area = bytes(area)
    elements = [0] * (index + 1)
    elements[index] = element
    ctx = GateContext(n, elements, bound, area)
    out = bytearray(b"\xaa" * 32)
    try:
        outcome = pow10_divisibility_gate(out, value, index, ctx)
    except IndexPanic:
        return ("exitA",)
    except BoundPanic:
        return ("exitB",)
    return ("ret", outcome.tag, outcome.quotient, bytes(out))


def run_case(uc, value, index, n, element, bound, tbyte):
    uc.mem_write(CTX + 0x08, struct.pack("<Q", ARR))
    uc.mem_write(CTX + 0x10, struct.pack("<Q", n))
    uc.mem_write(CTX + 0x20, struct.pack("<Q", REC))
    uc.mem_write(CTX + 0x28, struct.pack("<Q", bound))
    if index < 0x8000:
        uc.mem_write(ARR + index * 32, struct.pack("<Q", element))
    if element < 0x1000:
        uc.mem_write(REC + element * 0x158 + 0x48, bytes([tbyte]))
    uc.mem_write(OUT, b"\xaa" * 32)
    uc.mem_write(RSP0, struct.pack("<Q", HALT))
    uc.reg_write(UC_X86_REG_RSP, RSP0)
    uc.reg_write(UC_X86_REG_RDI, OUT)
    uc.reg_write(UC_X86_REG_RSI, value)
    uc.reg_write(UC_X86_REG_RDX, index)
    uc.reg_write(UC_X86_REG_RCX, CTX)
    state = {}

    def hook(uc_, address, size, _):
        if address == STUB_A:
            state["hit"] = ("exitB", uc_.reg_read(UC_X86_REG_RDI))
            uc_.emu_stop()
        elif address == STUB_B:
            state["hit"] = ("exitA", uc_.reg_read(UC_X86_REG_RDI),
                            uc_.reg_read(UC_X86_REG_RSI),
                            uc_.reg_read(UC_X86_REG_RDX))
            uc_.emu_stop()
        elif address == HALT:
            state["hit"] = ("ret",)
            uc_.emu_stop()

    h = uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(START, HALT + 0x1000, count=10000)
    uc.hook_del(h)
    return state.get("hit")


def check(uc, value, index, n, element, bound, tbyte):
    want = model_outcome(value, index, n, element, bound, tbyte)
    hit = run_case(uc, value, index, n, element, bound, tbyte)
    label = ("value=%d index=%d n=%d E=%d B=%d T=%d"
             % (value, index, n, element, bound, tbyte))
    if want[0] == "exitA":
        ok = (hit is not None and hit[0] == "exitA" and hit[1] == index
              and hit[2] == n and hit[3] == 0x6476678)
    elif want[0] == "exitB":
        ok = (hit is not None and hit[0] == "exitB" and hit[1] == 0x64768D8)
    else:
        if hit is None or hit[0] != "ret":
            ok = False
        else:
            out = bytes(uc.mem_read(OUT, 32))
            rax = uc.reg_read(UC_X86_REG_RAX)
            ok = (out == want[3] and rax == OUT)
    if not ok:
        print("MISMATCH %s want=%r hit=%r" % (label, want[0], hit))
        return False
    return True


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_write(START, BIN[START - 0x1000:STOP - 0x1000])
    uc.mem_map(SLOT_PAGE, 0x1000)
    uc.mem_write(SLOT_A, struct.pack("<Q", STUB_A))
    uc.mem_write(SLOT_B, struct.pack("<Q", STUB_B))
    uc.mem_map(STUB_A, 0x3000)
    uc.mem_write(STUB_A, b"\xcc" * 16)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(CTX, 0x1000)
    uc.mem_map(ARR, 0x100000)
    uc.mem_map(REC, 0x200000)
    uc.mem_map(OUT, 0x1000)

    total = 0
    fails = 0
    values = [0, 1, 7, 10**12, 10**12 + 1, 2 * 10**13, 10**14 - 1,
              10**15, 3 * 10**15 + 5, 2**32 - 1, 2**32, 2**32 + 1,
              2**64 - 1, 1234567890123456789]
    for t in range(256):
        for v in values:
            total += 1
            if not check(uc, v, 1, 4, 3, 100, t):
                fails += 1
    print("directed T-sweep: %d cases, %d failures" % (total, fails))

    rng = random.Random(0xDA30)
    n2 = 0
    for _ in range(6000):
        t = rng.randrange(256)
        v = rng.getrandbits(64)
        e = rng.choice([0, 1, 2, 5, 17, 99])
        i = rng.choice([0, 1, 3])
        n2 += 1
        if not check(uc, v, i, 4, e, 100, t):
            fails += 1
    print("random: %d cases" % n2)
    total += n2

    n3 = 0
    for i in (4, 5, 1000):
        for v in (0, 10**15, 2**64 - 1):
            n3 += 1
            if not check(uc, v, i, 4, 3, 100, 9):
                fails += 1
    for e in (100, 101, 2**40):
        n3 += 1
        if not check(uc, 7, 1, 4, e, 100, 9):
            fails += 1
    n3 += 1
    if not check(uc, 10**15, 3, 4, 99, 100, 9):
        fails += 1
    print("exit edges: %d cases" % n3)
    total += n3

    print("TOTAL: %d cases, %d failures" % (total, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
