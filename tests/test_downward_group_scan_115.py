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


def test_all_nonempty_scans_down_to_one():
    groups = [group(1), group(2), group(3)]
    assert downward_scan(3, groups, [0, 0, 0, 0]) == 1


def test_empty_top_group_below_threshold_returns_i_plus_one():
    # n = 3: group 2 empty, index_array[2] = 10, group 3's leading sum 5.
    groups = [group(1), group(2), {"pointers": []}, group(5)]
    assert downward_scan(3, groups, [0, 0, 10, 0]) == 3


def test_empty_top_group_at_or_above_threshold_continues_down():
    # group 2 empty, index_array[2] = 4, group 3's sum 5: not below, so
    # the scan continues to group 1 (non-empty) and then returns 1.
    groups = [group(1), group(2), {"pointers": []}, group(5)]
    assert downward_scan(3, groups, [0, 0, 4, 0]) == 1


def test_empty_middle_group_returns_its_i_plus_one():
    # n = 4: group 3 non-empty, group 2 empty with index 7, group 4 sum 3.
    groups = [group(1), group(2), {"pointers": []}, group(9), group(3)]
    assert downward_scan(4, groups, [0, 0, 7, 0, 0]) == 3


def test_comparison_uses_group_n_not_group_i():
    # Same empty group 2, but group 4's sum differs from group 2's own
    # (empty) sum: the native code compares group n's sum, so the
    # result follows group 4, not group 2.
    # a = 2, group n's sum = 3: 3 < 2 is false, so the scan continues
    # and returns 1. A model that wrongly used group i's own (empty)
    # sum of 0 would return 3 here instead.
    groups = [group(1), group(2), {"pointers": []}, group(9), group(3)]
    assert downward_scan(4, groups, [0, 0, 2, 0, 0]) == 1
    groups2 = [group(1), group(2), {"pointers": []}, group(9), group(8)]
    assert downward_scan(4, groups2, [0, 0, 2, 0, 0]) == 1


def test_single_null_pointer_counts_as_nonempty():
    # Range length is 1, so the count test passes even though the leaf
    # sum over that group would be 0; the scan skips the callee branch.
    groups = [group(1), {"pointers": [None]}, group(3)]
    assert downward_scan(3, groups, [0, 0, 0, 0]) == 1


def test_leaf_sum_stops_at_first_null():
    assert leaf_sum({"pointers": [{"size_field": 4}, None,
                                    {"size_field": 100}]}) == 4
    assert leaf_sum({"pointers": [None, {"size_field": 100}]}) == 0
    assert leaf_sum({"pointers": []}) == 0


def test_unsigned_comparison():
    # Wrapped sum 2**64 - 1 is huge unsigned, so it is not below 5.
    big = {"pointers": [{"size_field": -1}]}
    groups = [group(1), {"pointers": []}, big]
    assert group_sum(groups, 2) == -1
    assert downward_scan(2, groups, [0, 5, 0]) == 1


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
