"""Tests for the node #115 distinct-sum getter model.

Covers the distinct sum, the forwarding stub, and the getter end
to end, plus packet checks on
research/work-items/RE-001-distinct-sum-getter-115.
Runs under plain python3 (pytest is not installed on this VM):

  python3 tests/test_distinct_sum_getter_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from distinct_sum_getter_115 import (  # noqa: E402
    distinct_sum,
    distinct_sum_getter,
    forwarding_stub,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / \
    "research" / "work-items" / "RE-001-distinct-sum-getter-115"


def node(count, groups):
    return {"count": count, "groups": groups}


def test_empty_chain_returns_zero():
    assert distinct_sum({"chain": []}) == 0


def test_single_group_distinct_keys_sum():
    head = {"chain": [node(1, [[(7, 10), (9, 20)]])]}
    assert distinct_sum(head) == 30


def test_duplicate_key_within_group_skipped():
    head = {"chain": [node(1, [[(7, 10), (7, 99), (9, 1)]])]}
    assert distinct_sum(head) == 11


def test_duplicate_key_across_groups_and_nodes_skipped():
    head = {"chain": [
        node(2, [[(7, 10)], [(7, 99), (8, 5)]]),
        node(1, [[(8, 50), (9, 3)]]),
    ]}
    assert distinct_sum(head) == 18


def test_zero_and_negative_count_nodes_skipped():
    head = {"chain": [
        node(0, [[(1, 100)]]),
        node(-2, [[(2, 200)]]),
        node(1, [[(3, 4)]]),
    ]}
    assert distinct_sum(head) == 4


def test_empty_group_contributes_nothing():
    head = {"chain": [node(2, [[], [(5, 8)]])]}
    assert distinct_sum(head) == 8


def test_only_first_count_groups_counted():
    head = {"chain": [node(1, [[(1, 7)], [(2, 100)]])]}
    assert distinct_sum(head) == 7


def test_64_bit_wrap():
    head = {"chain": [node(1, [[(1, (1 << 64) - 1), (2, 2)]])]}
    assert distinct_sum(head) == 1


def test_stub_forwards_distinct_sum():
    member = {"field28": {"chain": [node(1, [[(4, 3), (4, 9)]])]}}
    assert forwarding_stub(member) == 3


def test_getter_end_to_end_stores_and_returns_one():
    outer = {"field788": {"field28": {"chain": [
        node(1, [[(1, 9), (2, 1)]])]}}}
    out = [None]
    assert distinct_sum_getter(outer, out) == 1
    assert out[0] == 10


def test_getter_reads_field788_then_field28():
    outer = {"field788": {"field28": {"chain": []}}}
    out = [None]
    assert distinct_sum_getter(outer, out) == 1
    assert out[0] == 0


def test_missing_field_raises():
    try:
        distinct_sum_getter({"field788": {}}, [None])
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing field")


def test_packet_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5eeb630", "0x5d8c9b0", "0x5f91010"]
    # Semantic records only: no per-instruction mnemonic list.
    assert "instructions" not in records
    assert "mnemonics" not in records
    for name in ("function_0x5eeb630.txt", "function_0x5d8c9b0.txt",
                 "function_0x5f91010.txt"):
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
