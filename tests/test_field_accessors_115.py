"""Tests for tools/field_accessors_115.py (node #115 accessors at
0x5d8d0c0, 0x5d8d0d0 and 0x5d8d0e0).

Run with: python3 tests/test_field_accessors_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from field_accessors_115 import get_field18, get_field70, raise_field70

CHECKS = []


def check(name, fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - test harness reports
        print("FAIL %s: %r" % (name, exc))
        return False
    print("ok %s" % name)
    return True


def expect_equal(got, want):
    if got != want:
        raise AssertionError("got %r, want %r" % (got, want))


def test_get70_zero():
    expect_equal(get_field70({0x70: 0}), 0)


def test_get70_value():
    expect_equal(get_field70({0x70: 0x12345678}), 0x12345678)


def test_get70_masks_to_32_bits():
    expect_equal(get_field70({0x70: (1 << 32) | 5}), 5)


def test_get70_missing_raises():
    try:
        get_field70({})
    except ValueError:
        return
    raise AssertionError("missing +0x70 did not raise")


def test_raise70_below_raises():
    obj = {0x70: 10}
    raise_field70(obj, 20)
    expect_equal(obj[0x70], 20)


def test_raise70_equal_stores_nothing_new():
    obj = {0x70: 20}
    raise_field70(obj, 20)
    expect_equal(obj[0x70], 20)


def test_raise70_above_keeps_current():
    obj = {0x70: 30}
    raise_field70(obj, 20)
    expect_equal(obj[0x70], 30)


def test_raise70_unsigned_edge():
    # 0xFFFFFFFF is the largest unsigned 32-bit value, so a raise
    # against 0 never moves it; and 0xFFFFFFFF beats 0x80000000
    # even though the latter is negative as signed.
    obj = {0x70: 0xFFFFFFFF}
    raise_field70(obj, 0)
    expect_equal(obj[0x70], 0xFFFFFFFF)
    obj = {0x70: 0x80000000}
    raise_field70(obj, 0xFFFFFFFF)
    expect_equal(obj[0x70], 0xFFFFFFFF)


def test_raise70_masks_incoming_to_32_bits():
    obj = {0x70: 0}
    raise_field70(obj, (1 << 32) | 7)
    expect_equal(obj[0x70], 7)


def test_raise70_missing_raises():
    try:
        raise_field70({}, 1)
    except ValueError:
        return
    raise AssertionError("missing +0x70 did not raise")


def test_get18_zero():
    expect_equal(get_field18({0x18: 0}), 0)


def test_get18_value():
    expect_equal(get_field18({0x18: 0xDEADBEEFCAFEBABE}), 0xDEADBEEFCAFEBABE)


def test_get18_masks_to_64_bits():
    expect_equal(get_field18({0x18: (1 << 64) | 3}), 3)


def test_get18_missing_raises():
    try:
        get_field18({})
    except ValueError:
        return
    raise AssertionError("missing +0x18 did not raise")


def test_record_fill_use():
    # Open PR #2378's taken arm: the record-fill routine calls the
    # +0x70 getter on src+0x40 and stores the 32-bit result at
    # dst+0x60. The getter half of that arm, modelled end to end.
    src_sub = {0x70: 0xABCDEF01}
    dst = {}
    dst[0x60] = get_field70(src_sub)
    expect_equal(dst[0x60], 0xABCDEF01)


def test_shared_caller_first_step():
    # The shared caller at 0x5f9dfa1 raises the +0x70 field of the
    # [rbp+0x60]+0x40 subobject with the [rbp+0x170] value before
    # raising the other fields through open PR #2374's leaves.
    sub = {0x70: 100}
    raise_field70(sub, 250)
    expect_equal(sub[0x70], 250)
    raise_field70(sub, 200)
    expect_equal(sub[0x70], 250)


def test_getter_and_raiser_agree():
    # The getter observes exactly what the raiser stores: raise,
    # then read back.
    obj = {0x70: 5}
    raise_field70(obj, 9)
    expect_equal(get_field70(obj), 9)


def main():
    tests = [
        ("get70 zero", test_get70_zero),
        ("get70 value", test_get70_value),
        ("get70 masks to 32 bits", test_get70_masks_to_32_bits),
        ("get70 missing raises", test_get70_missing_raises),
        ("raise70 below raises", test_raise70_below_raises),
        ("raise70 equal stores nothing new", test_raise70_equal_stores_nothing_new),
        ("raise70 above keeps current", test_raise70_above_keeps_current),
        ("raise70 unsigned edge", test_raise70_unsigned_edge),
        ("raise70 masks incoming", test_raise70_masks_incoming_to_32_bits),
        ("raise70 missing raises", test_raise70_missing_raises),
        ("get18 zero", test_get18_zero),
        ("get18 value", test_get18_value),
        ("get18 masks to 64 bits", test_get18_masks_to_64_bits),
        ("get18 missing raises", test_get18_missing_raises),
        ("record-fill use", test_record_fill_use),
        ("shared caller first step", test_shared_caller_first_step),
        ("getter and raiser agree", test_getter_and_raiser_agree),
    ]
    passed = sum(check(name, fn) for name, fn in tests)
    print("%d/%d checks pass" % (passed, len(tests)))
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
