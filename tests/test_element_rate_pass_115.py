"""Tests for tools/element_rate_pass_115.py (RE-001, node #115).

Runs under plain python3 via the __main__ runner below (pytest is not
installed on this VM); every test is an assertion on the model, and
the packet check at the end pins the work-item records to the model.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from element_rate_pass_115 import (
    ElementRatePassError,
    apply_element_rate_pass,
    compute_rate,
    make_element,
    make_obj,
)

MASK64 = (1 << 64) - 1
HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(
    HERE, "..", "research", "work-items", "RE-001-element-rate-pass-115")


def check(name, fn):
    fn()
    print("ok:", name)


def test_rate_zero_divisor():
    assert compute_rate(999, 888, 777, 0) == 0


def test_rate_dividend_is_f98_alone():
    # Correct: (90 // 7) * 100 // (90 + 10) = 1200 // 100 = 12.
    # Misreading the first dividend as (f98 + f90) would give 14.
    assert compute_rate(100, 10, 90, 7) == 12


def test_rate_truncating_divisions():
    assert compute_rate(7, 50, 100, 30) == 0  # (3 * 7) // 150


def test_rate_wrapping_add():
    # f98 + f90 wraps: total = 4; (2**64 - 4) // 4 = 2**62 - 1,
    # times 2, then // 4.
    rate = compute_rate(2, 8, MASK64 - 3, 4)
    assert rate == (((MASK64 - 3) // 4 * 2) & MASK64) // 4


def test_rate_zero_total_traps_even_with_nonpositive_count():
    # Native order: the rate block runs before the count check, so the
    # divide-by-zero trap fires even when no group would be walked.
    obj = make_obj(f88=5, f90=0, f98=0, fa0=3, count=0, groups=[])
    try:
        apply_element_rate_pass(obj)
    except ElementRatePassError:
        return
    raise AssertionError("expected ElementRatePassError")


def test_nonpositive_count_is_noop():
    el = make_element(e10=10, e80=1, e88=50, ea0=0, ea8=3, e78=0)
    obj = make_obj(f88=2, f90=0, f98=10, fa0=1, count=0, groups=[[el]])
    assert apply_element_rate_pass(obj) == 2  # rate still computed
    assert el["e78"] == 0


def test_negative_signed_count_is_noop():
    el = make_element(e10=10, e80=1, e88=50, ea0=0, ea8=3, e78=0)
    obj = make_obj(f88=2, f90=0, f98=10, fa0=1, count=0xFFFFFFFF,
                   groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 0


def test_empty_groups_and_group_order():
    first = make_element(e10=100, e80=10, e88=20, ea0=0, ea8=1, e78=0)
    second = make_element(e10=7, e80=0, e88=5, ea0=5, ea8=2, e78=0)
    obj = make_obj(f88=1, f90=0, f98=4, fa0=2, count=3,
                   groups=[[], [first], [second]])
    # rate = (4 // 2) * 1 // 4 = 0, so both take the e10 + ea8 result
    # (first via the scaling arm with a zero rate, second via delta2=0).
    apply_element_rate_pass(obj)
    assert first["e78"] == 101
    assert second["e78"] == 9


def test_already_stamped_element_skipped():
    el = make_element(e10=10, e80=1, e88=50, ea0=0, ea8=3, e78=42)
    obj = make_obj(f88=2, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 42


def test_below_threshold_arm():
    # delta2 = 2 * (30 - 10) = 40 < e80 = 50: result = e10 + ea8.
    el = make_element(e10=11, e80=50, e88=30, ea0=10, ea8=4, e78=0)
    obj = make_obj(f88=9, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 15


def test_scaling_arm():
    # rate = (10 // 1) * 3 // 10 = 3; delta2 = 2 * (30 - 10) = 40;
    # scaled = (40 - 25) * 3 = 45; e78 = 11 + 2 * 45 + 4 = 105.
    el = make_element(e10=11, e80=25, e88=30, ea0=10, ea8=4, e78=0)
    obj = make_obj(f88=3, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 105


def test_scaling_arm_at_exact_threshold():
    # delta2 == e80: scaled = 0, so e78 = e10 + ea8 through the arm.
    el = make_element(e10=11, e80=40, e88=30, ea0=10, ea8=4, e78=0)
    obj = make_obj(f88=3, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 15


def test_wrapping_delta_and_result():
    # e88 - ea0 wraps to 2**64 - 1; delta2 wraps to 2**64 - 2;
    # scaled = (2**64 - 2) * 1; result and sum wrap at 64 bits.
    el = make_element(e10=5, e80=0, e88=0, ea0=1, ea8=3, e78=0)
    obj = make_obj(f88=1, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == (5 + 2 * (MASK64 - 1) + 3) & MASK64


def test_pass_is_idempotent():
    el = make_element(e10=11, e80=25, e88=30, ea0=10, ea8=4, e78=0)
    obj = make_obj(f88=3, f90=0, f98=10, fa0=1, count=1, groups=[[el]])
    apply_element_rate_pass(obj)
    assert el["e78"] == 105
    apply_element_rate_pass(obj)
    assert el["e78"] == 105


def test_missing_group_is_guard_error():
    obj = make_obj(f88=1, f90=0, f98=4, fa0=2, count=2, groups=[[make_element()]])
    try:
        apply_element_rate_pass(obj)
    except ElementRatePassError:
        return
    raise AssertionError("expected ElementRatePassError")


def test_packet_records():
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["task"] == "RE-001"
    window = records["windows"]["pass"]
    assert window["start"] == "0x5f6b660"
    assert window["end"] == "0x5f6b715"
    assert window["size"] == 181
    assert records["census"]["pass"]["direct_calls"] == ["0x5f884c1"]
    assert records["model"] == "tools/element_rate_pass_115.py"


TESTS = [
    ("rate_zero_divisor", test_rate_zero_divisor),
    ("rate_dividend_is_f98_alone", test_rate_dividend_is_f98_alone),
    ("rate_truncating_divisions", test_rate_truncating_divisions),
    ("rate_wrapping_add", test_rate_wrapping_add),
    ("rate_zero_total_traps_even_with_nonpositive_count",
     test_rate_zero_total_traps_even_with_nonpositive_count),
    ("nonpositive_count_is_noop", test_nonpositive_count_is_noop),
    ("negative_signed_count_is_noop", test_negative_signed_count_is_noop),
    ("empty_groups_and_group_order", test_empty_groups_and_group_order),
    ("already_stamped_element_skipped", test_already_stamped_element_skipped),
    ("below_threshold_arm", test_below_threshold_arm),
    ("scaling_arm", test_scaling_arm),
    ("scaling_arm_at_exact_threshold", test_scaling_arm_at_exact_threshold),
    ("wrapping_delta_and_result", test_wrapping_delta_and_result),
    ("pass_is_idempotent", test_pass_is_idempotent),
    ("missing_group_is_guard_error", test_missing_group_is_guard_error),
    ("packet_records", test_packet_records),
]


def main():
    for name, fn in TESTS:
        check(name, fn)
    print("%d tests passed" % len(TESTS))


if __name__ == "__main__":
    main()
