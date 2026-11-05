"""Tests for the node #115 power-of-ten scale select model
(0x5a01110).

Target-grounded expectations: the scale cascade equals
10 ** max(0, digits - 5) on every band boundary; the magic
division by 10000 (multiplier 0x346dc5d63886594b, shift 75)
equals floor division on boundaries and seeded randoms; the
checked decomposition panics with the unwrap message at
l1/src/perp_meta.rs:163:38 when the quotient differs from the
object's +0x50 field or the remainder is not below the +0x10
bound, without consulting the table; a table byte of 7 or more
panics with the subtract-overflow message at
l1/src/perp_meta.rs:287:28; bytes 0..6 contribute 10 ** (6 - b);
and the result is the smaller of the cascade and table powers.
Run from the repository root:

    python3 tests/test_pow10_scale_01110_115.py
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from pow10_scale_01110_115 import (BOUND_OFFSET, BYTE_OFFSET,
                                   DIVISOR, DIV_MAGIC, DIV_SHIFT,
                                   ENTRY_STRIDE, FILE_STRING_ADDRESS,
                                   QUOTIENT_OFFSET, ROUTINE,
                                   ROUTINE_FDE, ROUTINE_SIZE,
                                   SUB_LOCATION_RECORD, SUB_MESSAGE,
                                   SUB_MESSAGE_ADDRESS, SUB_SHIM,
                                   SUB_SLOT, TABLE_POINTER_OFFSET,
                                   UNWIND_BUILDER, UNWIND_SLOT,
                                   UNWRAP_ENCODE, UNWRAP_ENCODE_SLOT,
                                   UNWRAP_LOCATION_RECORD,
                                   UNWRAP_MESSAGE,
                                   UNWRAP_MESSAGE_ADDRESS, UNWRAP_SHIM,
                                   UNWRAP_SLOT, Panic, ScaleObject,
                                   divmod_10000, pow10_scale,
                                   pow10_scale_closed, pow10_scale_select)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def expect_panic(name, fn, message, line, col):
    try:
        fn()
    except Panic as panic:
        check(name + " message", panic.message == message)
        check(name + " file", panic.file == "l1/src/perp_meta.rs")
        check(name + " line", panic.line == line)
        check(name + " col", panic.col == col)
        return
    raise AssertionError("failed: %s did not panic" % name)


def main():
    check("routine address", ROUTINE == 0x5A01110)
    check("routine fde", ROUTINE_FDE == (0x5A01110, 0x5A0130B))
    check("routine size", ROUTINE_SIZE == 507)
    check("table pointer offset", TABLE_POINTER_OFFSET == 0x8)
    check("bound offset", BOUND_OFFSET == 0x10)
    check("quotient offset", QUOTIENT_OFFSET == 0x50)
    check("entry stride", ENTRY_STRIDE == 32)
    check("byte offset", BYTE_OFFSET == 0x1D)
    check("divisor", DIVISOR == 10000)
    check("div magic", DIV_MAGIC == 0x346DC5D63886594B)
    check("div shift", DIV_SHIFT == 75)
    check("unwrap slot", UNWRAP_SLOT == 0x64DF830)
    check("unwrap shim", UNWRAP_SHIM == 0x1680C10)
    check("unwrap encode slot", UNWRAP_ENCODE_SLOT == 0x64DF730)
    check("unwrap encode", UNWRAP_ENCODE == 0x1680E60)
    check("unwind slot", UNWIND_SLOT == 0x64DF6B8)
    check("unwind builder", UNWIND_BUILDER == 0x1680E80)
    check("unwrap location record", UNWRAP_LOCATION_RECORD == 0x64768A8)
    check("unwrap message address", UNWRAP_MESSAGE_ADDRESS == 0x46E992)
    check("unwrap message length", len(UNWRAP_MESSAGE) == 43)
    check("sub slot", SUB_SLOT == 0x64DF848)
    check("sub shim", SUB_SHIM == 0x1681E40)
    check("sub location record", SUB_LOCATION_RECORD == 0x6478258)
    check("sub message address", SUB_MESSAGE_ADDRESS == 0x46EB80)
    check("sub message length", len(SUB_MESSAGE) == 33)
    check("sub encoded length", 2 * len(SUB_MESSAGE) + 1 == 0x43)
    check("file string address", FILE_STRING_ADDRESS == 0x437DF7)

    # The cascade transcription equals the closed form on every
    # power-of-ten boundary, on both sides.
    for k in range(0, 20):
        for x in (10 ** k - 1, 10 ** k, 10 ** k + 1):
            if 0 <= x < 2 ** 64:
                check("cascade boundary 10^%d" % k,
                      pow10_scale(x) == pow10_scale_closed(x))
    rng = random.Random(1106)
    for _ in range(2000):
        x = rng.randrange(2 ** 64)
        check("cascade random", pow10_scale(x) == pow10_scale_closed(x))
    check("cascade zero", pow10_scale(0) == 1)
    check("cascade below first band", pow10_scale(99999) == 1)
    check("cascade first band", pow10_scale(100000) == 10)
    check("cascade top band", pow10_scale(10 ** 19) == 10 ** 15)
    check("cascade u64 max", pow10_scale(2 ** 64 - 1) == 10 ** 15)

    # The magic division equals floor division by 10000.
    samples = [0, 1, 9999, 10000, 10001, 19999, 20000,
               2 ** 63, 2 ** 64 - 1, 10 ** 19, 10 ** 19 + 9999]
    for k in range(0, 20):
        samples += [10 ** k - 1, 10 ** k, 10 ** k + 1]
    samples += [rng.randrange(2 ** 64) for _ in range(20000)]
    for x in samples:
        if 0 <= x < 2 ** 64:
            q, r = divmod_10000(x)
            check("divmod %d" % x, (q, r) == (x // 10000, x % 10000))

    def obj(quotient, bound, byte):
        return ScaleObject(quotient, bound, lambda _r: byte)

    # Happy path: the cascade is the smaller power.
    result = pow10_scale_select(obj(7, 10000, 0), 71234, 12345)
    check("select cascade wins", result == 1)
    # Happy path: the table power is the smaller one.
    result = pow10_scale_select(obj(7, 10000, 6), 71234, 10 ** 19)
    check("select table 10^0 wins", result == 1)
    result = pow10_scale_select(obj(7, 10000, 5), 71234, 10 ** 19)
    check("select table 10^1 wins", result == 10)
    # Every byte 0..6 contributes exactly 10 ** (6 - b).
    for b in range(7):
        result = pow10_scale_select(obj(0, 10000, b), 9999, 2 ** 64 - 1)
        check("byte %d power" % b, result == 10 ** (6 - b))
    # The table is indexed by the remainder, not the value.
    seen = []

    def recording(remainder):
        seen.append(remainder)
        return 6

    pow10_scale_select(ScaleObject(3, 10000, recording), 39876, 0)
    check("table indexed by remainder", seen == [9876])

    # Quotient mismatch: unwrap panic, table never consulted.
    def forbidden(_r):
        raise AssertionError("table consulted on the panic path")

    expect_panic("quotient mismatch",
                 lambda: pow10_scale_select(
                     ScaleObject(8, 10000, forbidden), 71234, 0),
                 UNWRAP_MESSAGE, 163, 38)
    # Remainder at the bound: unwrap panic, table never consulted.
    expect_panic("remainder at bound",
                 lambda: pow10_scale_select(
                     ScaleObject(7, 1234, forbidden), 71234, 0),
                 UNWRAP_MESSAGE, 163, 38)
    # Remainder one below the bound passes the check.
    result = pow10_scale_select(obj(7, 1235, 6), 71234, 0)
    check("remainder below bound passes", result == 1)
    # Byte 7 and byte 255: subtract-overflow panic.
    expect_panic("byte 7",
                 lambda: pow10_scale_select(obj(7, 10000, 7), 71234, 0),
                 SUB_MESSAGE, 287, 28)
    expect_panic("byte 255",
                 lambda: pow10_scale_select(obj(7, 10000, 255), 71234, 0),
                 SUB_MESSAGE, 287, 28)
    # Value below the divisor: quotient 0, remainder is the value.
    result = pow10_scale_select(obj(0, 10000, 6), 4321, 10 ** 12)
    check("small value", result == 1)
    expect_panic("small value wrong quotient",
                 lambda: pow10_scale_select(
                     ScaleObject(1, 10000, forbidden), 4321, 0),
                 UNWRAP_MESSAGE, 163, 38)

    print("pow10_scale_01110_115: %d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
