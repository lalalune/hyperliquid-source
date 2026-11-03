"""Tests for tools/downward_group_scan_115.py (node #115, RE-001).

Run with pytest when available, or directly: python3 this file.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from downward_group_scan_115 import (
    downward_scan,
    group_sum,
    index_leaf,
    leaf_sum,
)


def group(*sizes):
    return {"pointers": [{"size_field": s} for s in sizes]}


def test_small_counts_return_n():
    groups = [group(1), group(2)]
    for n in (1, 0, -3):
        assert downward_scan(n, groups, [0, 0]) == n


def test_first_nonempty_from_top_returns_i_plus_one():
    # The scan returns at the first non-empty group met from the top:
    # a positive count falls through to the epilogue returning i + 1.
    groups = [group(1), group(2), group(3)]
    assert downward_scan(3, groups, [0, 0, 0, 0]) == 3
    groups4 = [group(1), group(2), group(3), group(4)]
    assert downward_scan(4, groups4, [0, 0, 0, 0, 0]) == 4

def test_empty_top_group_below_index_returns_i_plus_one():
    # n = 3: group 2 empty, index_array[2] = 4, group 3's leading sum 5.
    # cmp %rax,%r15; jb: 4 < 5 unsigned, so return i + 1 = 3.
    groups = [group(1), group(2), {"pointers": []}, group(5)]
    assert downward_scan(3, groups, [0, 0, 4, 0]) == 3

def test_empty_top_group_at_or_above_index_continues_down():
    # group 2 empty, index_array[2] = 10, group 3's sum 5: 10 < 5 is
    # false, so the scan steps to group 1 (non-empty) and returns 2.
    groups = [group(1), group(2), {"pointers": []}, group(5)]
    assert downward_scan(3, groups, [0, 0, 10, 0]) == 2

def test_nonempty_group_above_empty_group_wins_first():
    # n = 4: group 3 is non-empty, so the scan returns 4 at once; the
    # empty group 2 below it is never reached.
    groups = [group(1), group(2), {"pointers": []}, group(9), group(3)]
    assert downward_scan(4, groups, [0, 0, 7, 0, 0]) == 4

def test_comparison_uses_group_n_not_group_i():
    # n = 4, group 3 empty, a = index_array[3] = 2, group 4's sum = 3:
    # 2 < 3, so return i + 1 = 4. A model that wrongly used group i's
    # own (empty) sum of 0 would give 2 < 0 false and continue to 3.
    groups = [group(1), group(2), group(3), {"pointers": []}, group(3)]
    assert downward_scan(4, groups, [0, 0, 0, 2, 0]) == 4
    # a = 5, group 4's sum = 3: 5 < 3 is false, so step to group 2
    # (non-empty) and return 3.
    assert downward_scan(4, groups, [0, 0, 0, 5, 0]) == 3

def test_single_null_pointer_counts_as_nonempty():
    # Range length is 1, so the count test passes and the scan returns
    # i + 1 at once, even though the leaf sum over that group would
    # be 0; the callee branch is never taken for this group.
    groups = [group(1), group(2), {"pointers": [None]}]
    assert downward_scan(3, groups, [0, 0, 0]) == 3

def test_leaf_sum_stops_at_first_null():
    assert leaf_sum({"pointers": [{"size_field": 4}, None,
                                    {"size_field": 100}]}) == 4
    assert leaf_sum({"pointers": [None, {"size_field": 100}]}) == 0
    assert leaf_sum({"pointers": []}) == 0


def test_unsigned_comparison():
    # Wrapped sum 2**64 - 1 is huge unsigned, so 5 < huge holds.
    big = {"pointers": [{"size_field": -1}]}
    groups = [group(1), {"pointers": []}, big]
    assert group_sum(groups, 2) == -1
    # n = 2: group 1 empty, a = index_array[1] = 5, b = 2**64 - 1:
    # 5 < b, so return i + 1 = 2.
    assert downward_scan(2, groups, [0, 5, 0]) == 2

def test_wrapped_leaf_sum():
    total = leaf_sum({"pointers": [{"size_field": (1 << 63)},
                                    {"size_field": (1 << 63)}]})
    assert total == 0  # 2**64 wraps to 0 in the signed 64-bit view


def test_index_leaf_sign_extends():
    assert index_leaf([10, 20, 30], 1) == 20
    assert index_leaf([10, 20, 30], -1) == 30  # Python mirrors the index


def test_missing_group_raises():
    try:
        downward_scan(3, [group(1)], [0, 0, 0, 0])
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError for a missing group")


def test_missing_field_guards():
    try:
        leaf_sum({})
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing pointers field")


def test_packet_checks():
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-downward-group-scan-115"
    assert (packet / "records.json").exists()
    assert (packet / "MANIFEST.sha256").exists()
    for name in ("scanner_0x5d52bb0.objdump", "stub_0x60d5390.objdump",
                 "index_leaf_0x5f6c740.objdump", "group_sum_0x5f6c300.objdump",
                 "leaf_0x5da4de0.objdump"):
        assert (packet / name).exists()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} tests passed")
