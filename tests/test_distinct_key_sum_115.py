"""Tests for the node #115 distinct-key sum 0x5f90da0 model.

Run with pytest, or directly with plain python3 (no pytest installed
on this VM): ``python3 tests/test_distinct_key_sum_115.py`` prints
``N tests passed`` on success.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from distinct_key_sum_115 import distinct_key_sum, value_of  # noqa: E402

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-distinct-key-sum-115"


def _nodes(spec):
    """Build nodes/objects from a compact spec.

    spec: {node_id: (next_id, [(key, field10, ignored), ...])}.
    """
    nodes = {}
    objects = {}
    for node_id, (next_id, entries) in spec.items():
        objs = []
        for i, (key, field10, ignored) in enumerate(entries):
            obj_id = "%s/%d" % (node_id, i)
            objects[obj_id] = {"key": key, "field10": field10}
            objs.append({"obj": obj_id, "ignored": ignored})
        nodes[node_id] = {"next": next_id, "entries": objs}
    return nodes, objects


def test_self_loop_head_returns_zero():
    nodes, objects = _nodes({"h": ("h", [])})
    assert distinct_key_sum("h", nodes, objects) == 0


def test_single_entry_adds_field_plus_62():
    nodes, objects = _nodes({"h": ("a", []), "a": ("h", [(7, 100, 999)])})
    assert distinct_key_sum("h", nodes, objects) == 162


def test_duplicate_key_within_node_skipped():
    nodes, objects = _nodes({"h": ("a", []), "a": ("h", [(7, 100, 0), (7, 500, 0)])})
    assert distinct_key_sum("h", nodes, objects) == 162


def test_duplicate_key_across_nodes_skipped():
    nodes, objects = _nodes({
        "h": ("a", []),
        "a": ("b", [(7, 100, 0)]),
        "b": ("h", [(7, 500, 0), (8, 10, 0)]),
    })
    assert distinct_key_sum("h", nodes, objects) == 162 + 72


def test_empty_range_contributes_nothing():
    nodes, objects = _nodes({"h": ("a", []), "a": ("h", [])})
    assert distinct_key_sum("h", nodes, objects) == 0


def test_multiple_new_keys_sum():
    nodes, objects = _nodes({"h": ("a", []), "a": ("h", [(1, 0, 0), (2, 1, 0), (3, 2, 0)])})
    assert distinct_key_sum("h", nodes, objects) == 62 + 63 + 64


def test_entry_second_qword_never_read():
    nodes1, objects1 = _nodes({"h": ("a", []), "a": ("h", [(7, 100, 0)])})
    nodes2, objects2 = _nodes({"h": ("a", []), "a": ("h", [(7, 100, 2 ** 63)])})
    assert distinct_key_sum("h", nodes1, objects1) == distinct_key_sum("h", nodes2, objects2) == 162


def test_64_bit_wrap():
    big = (1 << 64) - 10
    nodes, objects = _nodes({"h": ("a", []), "a": ("h", [(7, big, 0), (8, 100, 0)])})
    assert distinct_key_sum("h", nodes, objects) == (big + 62 + 100 + 62) % (1 << 64)


def test_value_leaf_directly():
    assert value_of({"key": 0, "field10": 0}) == 62
    assert value_of({"key": 0, "field10": (1 << 64) - 1}) == 61


def test_missing_node_raises():
    nodes, objects = _nodes({"h": ("a", [])})
    try:
        distinct_key_sum("h", nodes, objects)
    except KeyError:
        return
    raise AssertionError("expected KeyError for a missing node")


def test_missing_object_raises():
    nodes = {"h": {"next": "a", "entries": []}, "a": {"next": "h", "entries": [{"obj": "ghost"}]}}
    try:
        distinct_key_sum("h", nodes, {})
    except KeyError:
        return
    raise AssertionError("expected KeyError for a missing object")


def test_non_returning_chain_raises():
    nodes, objects = _nodes({"h": ("a", []), "a": ("b", []), "b": ("a", [])})
    try:
        distinct_key_sum("h", nodes, objects)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a non-returning chain")


def test_packet_records_match_model():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact_sha256"] == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    starts = [w["start"] for w in records["windows"]]
    assert "0x5f90da0" in starts and "0x5dd3570" in starts
    assert records["census"]["0x5f90da0"]["tail_jumps"] == ["0x5d8c9c8"]


def test_packet_excerpts_present():
    excerpt = (PACKET_DIR / "function_0x5f90da0.txt").read_text()
    assert "5f90da0:" in excerpt and "5f90f9c" in excerpt
    leaf = (PACKET_DIR / "function_0x5dd3570.txt").read_text()
    assert "5dd3570" in leaf


TESTS = [
    test_self_loop_head_returns_zero,
    test_single_entry_adds_field_plus_62,
    test_duplicate_key_within_node_skipped,
    test_duplicate_key_across_nodes_skipped,
    test_empty_range_contributes_nothing,
    test_multiple_new_keys_sum,
    test_entry_second_qword_never_read,
    test_64_bit_wrap,
    test_value_leaf_directly,
    test_missing_node_raises,
    test_missing_object_raises,
    test_non_returning_chain_raises,
    test_packet_records_match_model,
    test_packet_excerpts_present,
]


def main():
    for test in TESTS:
        test()
    print("%d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
