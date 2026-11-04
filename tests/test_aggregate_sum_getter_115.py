"""Tests for the node #115 aggregate-sum getter model.

Covers the aggregate sum, the forwarding stub, and the getter end
to end, plus packet checks on
research/work-items/RE-001-aggregate-sum-getter-115.
Runs under plain python3 (pytest is not installed on this VM):

  python3 tests/test_aggregate_sum_getter_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from aggregate_sum_getter_115 import (  # noqa: E402
    aggregate_sum,
    aggregate_sum_getter,
    forwarding_stub,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / \
    "research" / "work-items" / "RE-001-aggregate-sum-getter-115"


def test_zero_count_returns_zero():
    assert aggregate_sum({"count": 0, "groups": [[5, 7]]}) == 0


def test_negative_count_returns_zero():
    assert aggregate_sum({"count": -3, "groups": [[5, 7]]}) == 0


def test_single_element_group():
    assert aggregate_sum({"count": 1, "groups": [[42]]}) == 42


def test_pair_of_elements():
    assert aggregate_sum({"count": 1, "groups": [[10, 20]]}) == 30


def test_odd_group_of_three():
    # The binary sums pairs with SIMD and handles the lone final
    # element separately; the observable total is the plain sum.
    assert aggregate_sum({"count": 1, "groups": [[1, 2, 3]]}) == 6


def test_empty_group_contributes_nothing():
    assert aggregate_sum({"count": 2, "groups": [[], [8]]}) == 8


def test_multiple_groups_sum():
    obj = {"count": 3, "groups": [[1, 2], [], [10, 20, 30]]}
    assert aggregate_sum(obj) == 63


def test_only_first_count_groups_counted():
    obj = {"count": 1, "groups": [[7], [100]]}
    assert aggregate_sum(obj) == 7


def test_64_bit_wrap():
    obj = {"count": 1, "groups": [[(1 << 64) - 1, 2]]}
    assert aggregate_sum(obj) == 1


def test_stub_forwards_aggregate():
    member = {"field30": {"count": 2, "groups": [[3], [4, 5]]}}
    assert forwarding_stub(member) == 12


def test_getter_end_to_end_stores_and_returns_one():
    outer = {"field788": {"field30": {"count": 1, "groups": [[9, 1]]}}}
    out = [None]
    assert aggregate_sum_getter(outer, out) == 1
    assert out[0] == 10


def test_getter_reads_field788_then_field30():
    outer = {"field788": {"field30": {"count": 0, "groups": [[99]]}}}
    out = [None]
    assert aggregate_sum_getter(outer, out) == 1
    assert out[0] == 0


def test_missing_field_raises():
    try:
        aggregate_sum_getter({"field788": {}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing field")


def test_packet_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5eeb650", "0x5d8c9d0", "0x5f6acb0"]
    # Semantic records only: no per-instruction mnemonic list.
    assert "instructions" not in records
    assert "mnemonics" not in records
    for name in ("function_0x5eeb650.txt", "function_0x5d8c9d0.txt",
                 "function_0x5f6acb0.txt"):
        assert (PACKET_DIR / name).exists()


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
