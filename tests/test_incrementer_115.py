"""Tests for tools/incrementer_115.py (node #115 incrementer leaf
at 0x5d8d0b0 and its sole call site's branch).

Run with: python3 tests/test_incrementer_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from incrementer_115 import increment_field70, site_disposition

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


def test_increment_zero():
    obj = {0x70: 0}
    expect_equal(increment_field70(obj), 1)
    expect_equal(obj[0x70], 1)


def test_increment_value():
    obj = {0x70: 41}
    expect_equal(increment_field70(obj), 42)
    expect_equal(obj[0x70], 42)


def test_increment_wraps():
    obj = {0x70: 0xFFFFFFFF}
    expect_equal(increment_field70(obj), 0)
    expect_equal(obj[0x70], 0)


def test_increment_masks_to_32_bits():
    obj = {0x70: (1 << 32) | 7}
    expect_equal(increment_field70(obj), 8)


def test_increment_twice():
    obj = {0x70: 5}
    increment_field70(obj)
    expect_equal(increment_field70(obj), 7)
    expect_equal(obj[0x70], 7)


def test_increment_missing_raises():
    try:
        increment_field70({})
    except ValueError:
        return
    raise AssertionError("missing +0x70 did not raise")


def test_increment_leaves_other_fields():
    obj = {0x70: 3, 0x18: 99, 0x40: 7}
    increment_field70(obj)
    expect_equal(obj[0x18], 99)
    expect_equal(obj[0x40], 7)


def test_site_null_arm_increments_and_stores():
    obj = {0x70: 10}
    expect_equal(site_disposition(obj, 0), 11)
    expect_equal(obj[0x70], 11)


def test_site_null_arm_wraps():
    obj = {0x70: 0xFFFFFFFF}
    expect_equal(site_disposition(obj, 0), 0)
    expect_equal(obj[0x70], 0)


def test_site_taken_arm_no_increment():
    obj = {0x70: 10}
    expect_equal(site_disposition(obj, 12345), None)
    expect_equal(obj[0x70], 10)


def test_site_taken_arm_nonzero_pointer():
    obj = {0x70: 0}
    expect_equal(site_disposition(obj, 0x5D8CF70), None)
    expect_equal(obj[0x70], 0)


def test_site_null_arm_missing_raises():
    try:
        site_disposition({}, 0)
    except ValueError:
        return
    raise AssertionError("missing +0x70 on null arm did not raise")


def main():
    tests = [
        ("increment_zero", test_increment_zero),
        ("increment_value", test_increment_value),
        ("increment_wraps", test_increment_wraps),
        ("increment_masks_to_32_bits", test_increment_masks_to_32_bits),
        ("increment_twice", test_increment_twice),
        ("increment_missing_raises", test_increment_missing_raises),
        ("increment_leaves_other_fields", test_increment_leaves_other_fields),
        ("site_null_arm_increments_and_stores",
         test_site_null_arm_increments_and_stores),
        ("site_null_arm_wraps", test_site_null_arm_wraps),
        ("site_taken_arm_no_increment", test_site_taken_arm_no_increment),
        ("site_taken_arm_nonzero_pointer", test_site_taken_arm_nonzero_pointer),
        ("site_null_arm_missing_raises", test_site_null_arm_missing_raises),
    ]
    passed = sum(check(name, fn) for name, fn in tests)
    print("%d/%d checks pass" % (passed, len(tests)))
    if passed != len(tests):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
