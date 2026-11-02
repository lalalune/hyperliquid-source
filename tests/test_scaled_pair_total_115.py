"""Tests for the node #115 scaled pair total 0x5f09a50 model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_scaled_pair_total_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))

from scaled_pair_total_115 import (
    SENTINEL,
    Subobject,
    pair_total,
    scaled_total,
)

OTHER = 0x5F05000


def test_both_default_returns_zero():
    first = Subobject(None)
    second = Subobject(SENTINEL)
    assert pair_total(first, second, 1, 2) == 0
    assert scaled_total(first, second, 100, 30, 1, 2) == (0, 0)


def test_first_call_only():
    first = Subobject(OTHER, 20)
    second = Subobject(SENTINEL)
    assert pair_total(first, second, 1, 2) == 20
    # cap 30 does not clamp 20; scale 100 // 30 == 3.
    assert scaled_total(first, second, 100, 30, 1, 2) == (60, 20)


def test_second_call_adds_to_first():
    first = Subobject(OTHER, 20)
    second = Subobject(OTHER + 8, 15)
    assert pair_total(first, second, 1, 2) == 35
    # clamped to cap 30; scale 100 // 30 == 3.
    assert scaled_total(first, second, 100, 30, 1, 2) == (90, 30)


def test_zero_returning_call_counts_as_zero_total():
    first = Subobject(OTHER, 0)
    second = Subobject(SENTINEL)
    assert scaled_total(first, second, 100, 30, 1, 2) == (0, 0)


def test_zero_cap_returns_zero():
    first = Subobject(OTHER, 20)
    second = Subobject(SENTINEL)
    assert scaled_total(first, second, 100, 0, 1, 2) == (0, 0)


def test_exact_cap_boundary():
    first = Subobject(OTHER, 30)
    second = Subobject(SENTINEL)
    # total == cap: min is the total itself; scale 100 // 30 == 3.
    assert scaled_total(first, second, 100, 30, 1, 2) == (90, 30)


def test_scale_uses_quotient_not_field():
    first = Subobject(OTHER, 10)
    second = Subobject(SENTINEL)
    # field_a68 95, cap 30: quotient 3, not 95.
    assert scaled_total(first, second, 95, 30, 1, 2) == (30, 10)
    # field_a68 below cap: quotient 0, scaled value 0, clamped kept.
    assert scaled_total(first, second, 20, 30, 1, 2) == (0, 10)


def test_wrapping_addition():
    big = (1 << 64) - 5
    first = Subobject(OTHER, big)
    second = Subobject(OTHER + 8, 10)
    assert pair_total(first, second, 1, 2) == 5


def test_second_default_after_nonzero_first():
    first = Subobject(OTHER, 7)
    second = Subobject(None)
    assert pair_total(first, second, 1, 2) == 7
    assert scaled_total(first, second, 70, 7, 1, 2) == (70, 7)


def test_packet_records_present():
    import json

    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-scaled-pair-total-115")
    with open(os.path.join(packet, "records.json")) as fh:
        records = json.load(fh)
    assert records["window"] == "0x5f09a50"
    assert records["sentinel"] == "0x5f04d70"
    with open(os.path.join(packet, "main-5f09a50.objdump.txt")) as fh:
        excerpt = fh.read()
    assert "5f09a50" in excerpt and "5f09b05" in excerpt


def _run():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
        print("ok", test.__name__)
    print("all", len(tests), "tests passed")


if __name__ == "__main__":
    _run()
