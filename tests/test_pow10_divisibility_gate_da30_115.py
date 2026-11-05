"""Tests for the node #115 power-of-ten divisibility gate model
(tools/pow10_divisibility_gate_da30_115.py, RE-001 work item
RE-001-pow10-divisibility-gate-da30-115). Each check counts; the
run prints "<n> checks pass" on success.

Expectations are target-grounded: the class byte T at record
offset E * 0x158 + 0x48 selects the divisor 10^(8 - T) for T in
0..8 and no divisor for T >= 9; a divisible value returns tag
0x1a2 with the quotient written at out +8, anything else
returns tag 0x6a with out +8 untouched; the index and bound
checks leave through the two modelled panic exits before any
write -- all read from the whole-function excerpt in the packet
and cross-checked against the binary by the packet's Unicorn
differential (9,597 cases, no divergence).
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from pow10_divisibility_gate_da30_115 import (
    BoundPanic, GateContext, IndexPanic, divisor_for,
    pow10_divisibility_gate)

CHECKS = [0]
SENTINEL = 0xAAAAAAAAAAAAAAAA


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def expect_raises(fn, kinds, label):
    try:
        fn()
    except kinds:
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def make_context(tbyte, element=3, count=4, bound=100, index_fill=None,
                 index=1):
    elements = [0, 0, 0, 0]
    if index_fill is not None:
        elements = list(index_fill)
    else:
        elements[index] = element
    area = bytearray((element + 1) * 0x158)
    area[element * 0x158 + 0x48] = tbyte
    return GateContext(count, elements, bound, bytes(area))


def fresh_out():
    out = bytearray([0xBB] * 32)
    struct.pack_into("<Q", out, 8, SENTINEL)
    return out


def run(value, tbyte, index=1, **kw):
    out = fresh_out()
    outcome = pow10_divisibility_gate(
        out, value, index, make_context(tbyte, index=index, **kw))
    return out, outcome


def main():
    # Divisor table: T in 0..8 -> 10^(8-T); T >= 9 -> none.
    for t in range(9):
        check(divisor_for(t) == 10 ** (8 - t), "divisor for T=%d" % t)
    for t in (9, 16, 100, 255):
        check(divisor_for(t) is None, "no divisor for T=%d" % t)

    # Every T in 0..8: exact multiples are divisible, off-by-one
    # values are not.
    for t in range(9):
        d = 10 ** (8 - t)
        out, outcome = run(3 * d, t)
        check(outcome.tag == 0x1A2 and outcome.quotient == 3,
              "T=%d exact multiple is divisible" % t)
        check(struct.unpack_from("<H", out, 0)[0] == 0x1A2,
              "T=%d tag word written" % t)
        check(struct.unpack_from("<Q", out, 8)[0] == 3,
              "T=%d quotient written at out+8" % t)
        if d > 1:
            out, outcome = run(3 * d + 1, t)
            check(outcome.tag == 0x6A and outcome.quotient is None,
                  "T=%d off-by-one is not divisible" % t)
            check(struct.unpack_from("<Q", out, 8)[0] == SENTINEL,
                  "T=%d payload untouched on the 0x6a path" % t)
        else:
            # T=8 selects divisor 1, which divides every value.
            out, outcome = run(3 * d + 1, t)
            check(outcome.tag == 0x1A2 and outcome.quotient == 4,
                  "T=8 divisor 1 divides every value")

    # T >= 9: immediate 0x6a even for value 0 (which every real
    # divisor would divide).
    for t in (9, 10, 16, 255):
        out, outcome = run(0, t)
        check(outcome.tag == 0x6A and outcome.quotient is None,
              "T=%d takes the immediate 0x6a path" % t)
        check(struct.unpack_from("<Q", out, 8)[0] == SENTINEL,
              "T=%d writes no payload" % t)

    # Value 0 is divisible by every real divisor, quotient 0.
    for t in range(9):
        out, outcome = run(0, t)
        check(outcome.tag == 0x1A2 and outcome.quotient == 0,
              "value 0 divisible for T=%d" % t)
        check(struct.unpack_from("<Q", out, 8)[0] == 0,
              "value 0 quotient 0 written for T=%d" % t)

    # The 32/64-bit div boundary does not change results: values
    # just below, at, and above 2^32 behave exactly.
    for t in (0, 4, 8):
        d = 10 ** (8 - t)
        for v in (2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 64 - 1):
            out, outcome = run(v, t)
            if v % d == 0:
                check(outcome.tag == 0x1A2 and outcome.quotient == v // d,
                      "boundary value %d divisible for T=%d" % (v, t))
            else:
                check(outcome.tag == 0x6A and outcome.quotient is None,
                      "boundary value %d not divisible for T=%d" % (v, t))

    # Out-slot hygiene: bytes +0x02..+0x08 and past +0x10 are
    # never written on either path.
    for t, v in ((8, 5), (8, 4), (0, 10 ** 8), (0, 10 ** 8 + 1)):
        out, _outcome = run(v, t)
        check(all(out[i] == 0xBB for i in range(2, 8)),
              "gap bytes untouched for T=%d v=%d" % (t, v))
        check(all(out[i] == 0xBB for i in range(16, 32)),
              "tail bytes untouched for T=%d v=%d" % (t, v))

    # Index check: index >= count raises IndexPanic before any
    # write; index == count - 1 passes the check.
    out = fresh_out()
    expect_raises(lambda: pow10_divisibility_gate(
        out, 1, 4, make_context(8)), (IndexPanic,),
        "index == count raises IndexPanic")
    check(struct.unpack_from("<H", out, 0)[0] == 0xBBBB,
          "nothing written on the index exit")
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), 1, 2 ** 64 - 1, make_context(8)), (IndexPanic,),
        "huge index raises IndexPanic")
    out, outcome = run(10, 8, index=3)
    check(outcome.tag == 0x1A2, "index == count - 1 passes")

    # Bound check: element >= bound raises BoundPanic before any
    # write; element == bound - 1 passes.
    out = fresh_out()
    expect_raises(lambda: pow10_divisibility_gate(
        out, 1, 1, make_context(8, element=100, bound=100)), (BoundPanic,),
        "element == bound raises BoundPanic")
    check(struct.unpack_from("<H", out, 0)[0] == 0xBBBB,
          "nothing written on the bound exit")
    # A huge element needs no record area: the bound check
    # fires before the record byte is ever read.
    huge_ctx = GateContext(4, [0, 2 ** 40, 0, 0], 100, b"")
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), 1, 1, huge_ctx),
        (BoundPanic,), "element above bound raises BoundPanic")
    out, outcome = run(10, 8, element=99, bound=100)
    check(outcome.tag == 0x1A2, "element == bound - 1 passes")

    # The class byte comes from the strided record offset: two
    # elements whose records carry different bytes decide
    # differently for the same value.
    out, outcome = run(10, 8, index=1, index_fill=[0, 5, 0, 0], element=5)
    check(outcome.tag == 0x1A2, "element 5 record byte drives the gate")
    # Same value, element whose record byte is 0 (divisor 10^8).
    area = bytearray(6 * 0x158)
    area[5 * 0x158 + 0x48] = 0
    ctx = GateContext(4, [0, 5, 0, 0], 100, bytes(area))
    out = fresh_out()
    outcome = pow10_divisibility_gate(out, 10, 1, ctx)
    check(outcome.tag == 0x6A, "record byte 0 makes 10 not divisible")

    # Input guards (model safety, not binary claims).
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), -1, 1, make_context(8)), (ValueError,),
        "negative value raises")
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), 2 ** 64, 1, make_context(8)), (ValueError,),
        "value above u64 raises")
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), True, 1, make_context(8)), (ValueError,),
        "bool value raises")
    expect_raises(lambda: pow10_divisibility_gate(
        fresh_out(), 1, -1, make_context(8)), (ValueError,),
        "negative index raises")
    expect_raises(lambda: pow10_divisibility_gate(
        bytearray(8), 1, 1, make_context(8)), (ValueError,),
        "short out raises")
    expect_raises(lambda: divisor_for(256), (ValueError,),
                  "class byte above 255 raises")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
