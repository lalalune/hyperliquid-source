"""Tests for tools/double_accumulation_115.py (node #115, 0x5f6c750).

Run from the clone root with plain python3 (pytest is not installed on this
VM): python3 tests/test_double_accumulation_115.py
"""

import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from double_accumulation_115 import (  # noqa: E402
    double_to_unsigned_bits,
    helper,
    index_leaf,
    run,
)

PACKET = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-double-accumulation-115",
)
TWO63 = 1 << 63


def _obj(groups, index, count, level0, cache=0, flag=0):
    return {
        "flag": flag, "groups": groups, "count": count, "level0": level0,
        "index": index, "cache": cache,
    }


def _arg2(count70=0, threshold=0):
    return {"count70": count70, "threshold": threshold}


def test_flag_set_resets_cache():
    obj = _obj([[5]], [0], 3, 0, cache=123, flag=1)
    assert run(obj, _arg2()) is None
    assert obj["cache"] == 0


def test_helper_gate_returns_with_baseline_cache():
    # helper = count - 2 = 0; level0 = 1 > 0, so the loop returns at once.
    obj = _obj([[10, 20]], [0], 2, 1)
    run(obj, _arg2())
    assert obj["cache"] == 30


def test_full_loop_trace():
    # groups: g0=30, g1=5, g2=10; count=4 -> helper=2; level0=0.
    # iter1: acc=60, cache=30+30=60, idx[0]=100 >= 60 -> reset.
    # iter2: acc=5, idx[1]=3 < 5 -> rem=2, count>2 -> g2=10,
    #   cache += (10/5 + 1.0) * 2 = 6 -> 66.
    # iter3: acc=12, idx[2]=20 >= 12 -> reset; iter4: level 3 > 2 -> return.
    obj = _obj([[10, 20], [5], [7, 3]], [100, 3, 20], 4, 0)
    run(obj, _arg2())
    assert obj["cache"] == 66


def test_arg2_threshold_clears_flag_but_double_math_still_adds():
    # arg2 count 5 > N=1 and total 4 < threshold 10: flag dead, total 0.
    # iter1: acc=4, no first-iteration add (flag dead), idx[0]=2 < 4 ->
    #   rem=2, count 3 > 1 -> g2=6, cache += (6/4 + 1.0) * 2 = 5.
    # iter2: acc=8, idx[1]=100 >= 8 -> reset; iter3: level 2 > 1 -> return.
    obj = _obj([[4], [6]], [2, 100], 3, 0)
    run(obj, _arg2(count70=5, threshold=10))
    assert obj["cache"] == 5


def test_arg2_threshold_met_keeps_flag_live():
    # arg2 count 5 > N=1 but total 4 >= threshold 4: flag stays live.
    # iter1: acc=8 (total 4 + group0 sum 4), cache=4+4=8, idx[0]=9 >= 8 -> reset.
    # iter2: level 1 <= 1: acc=0, g=group1=6, acc=6, idx[1]=100 -> reset.
    # iter3: level 2 > 1 -> return.
    obj = _obj([[4], [6]], [9, 100], 3, 0)
    run(obj, _arg2(count70=5, threshold=4))
    assert obj["cache"] == 8


def test_double_math_at_two_to_63_arm():
    # Iter1: total 2**61, acc 2**62, cache 2**62, idx[0]=0 < acc ->
    # rem 2**62, next group sum 2**62 == acc, so the double value is
    # (2**62 / 2**62 + 1.0) * 2**62 = 2**63 exactly, and the >= 2**63
    # conversion arm yields 2**63. Final cache = 2**62 + 2**63.
    obj = _obj([[1 << 61], [1 << 62]], [0, (1 << 64) - 1], 3, 0)
    run(obj, _arg2())
    assert obj["cache"] == (1 << 62) + (1 << 63)


def test_wrapping_group_sum_and_unsigned_index_compare():
    # Group sums wrap mod 2**64; index compare is unsigned, so the huge
    # index resets instead of taking the remainder branch.
    obj = _obj([[(1 << 64) - 1, 2], [3]], [(1 << 64) - 1, 0], 3, 0)
    # iter1: total=1, cache=1+1=2, idx huge >= 2 -> reset.
    # iter2: acc=3, idx[1]=0 < 3 -> rem=3, count 3 > 2 -> group2 missing.
    try:
        run(obj, _arg2())
        raise AssertionError("expected group-range guard")
    except ValueError:
        pass


def test_empty_group0_and_zero_threshold():
    obj = _obj([[]], [7], 2, 0)
    run(obj, _arg2(count70=1, threshold=0))
    assert obj["cache"] == 0


def test_helper_and_leaf():
    assert helper(_obj([], [], 5, 0)) == 3
    assert helper(_obj([], [], 5, 0, flag=1)) == 0
    assert helper(_obj([], [], 1, 0)) == -1
    assert index_leaf(_obj([], [11, 22], 0, 0), 1) == 22
    try:
        index_leaf(_obj([], [11], 0, 0), 1)
        raise AssertionError("expected index-range guard")
    except ValueError:
        pass


def test_double_conversion_arms():
    assert double_to_unsigned_bits(6.0) == 6
    assert double_to_unsigned_bits(float(TWO63)) == TWO63
    assert double_to_unsigned_bits(float(TWO63) + 4096.0) == TWO63 + 4096
    assert double_to_unsigned_bits(math.inf) == 0
    assert double_to_unsigned_bits(math.nan) == TWO63
    assert double_to_unsigned_bits(0.9) == 0  # truncate toward zero


def test_missing_field_guards():
    try:
        run({"groups": []}, _arg2())
        raise AssertionError("expected missing-field guard")
    except ValueError:
        pass


def test_packet_records_are_semantic_only():
    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    assert records["windows"]["main"]["address"] == "0x5f6c750"
    assert records["windows"]["helper"]["address"] == "0x5f6b720"
    assert records["windows"]["leaf"]["address"] == "0x5f6c740"
    assert "instructions" not in records
    assert records["census"]["main"]["direct_calls"] == []
    assert records["census"]["main"]["tail_jumps"] == ["0x5f7e6de"]
    assert records["census"]["leaf"]["direct_calls"] == [
        "0x5d52c06", "0x5dc1201", "0x5dc1ef0", "0x5dc2114", "0x5f6c88e",
        "0x5f7e739", "0x5f7e764", "0x5f7e78c", "0x5f7e7a0", "0x5f7e9ad",
        "0x5f7eb12",
    ]


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for t in tests:
        t()
        print("ok:", t.__name__)
    print("%d tests passed" % len(tests))


if __name__ == "__main__":
    main()
