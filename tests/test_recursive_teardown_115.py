"""Tests for tools/recursive_teardown_115.py (node #115 tree teardown).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from recursive_teardown_115 import teardown  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-recursive-teardown-115"


def test_null_head_deletes_nothing():
    assert teardown(None, {}) == []


def test_single_node_no_child_no_next():
    nodes = {"a": {"next": None, "child": None}}
    assert teardown("a", nodes) == ["a"]


def test_sibling_chain_in_order():
    nodes = {
        "a": {"next": "b", "child": None},
        "b": {"next": "c", "child": None},
        "c": {"next": None, "child": None},
    }
    assert teardown("a", nodes) == ["a", "b", "c"]


def test_child_before_parent():
    nodes = {
        "a": {"next": None, "child": "c"},
        "c": {"next": None, "child": None},
    }
    assert teardown("a", nodes) == ["c", "a"]


def test_worked_order_from_readme():
    # A -> B siblings; A child chain C -> D; C child E.
    nodes = {
        "A": {"next": "B", "child": "C"},
        "B": {"next": None, "child": None},
        "C": {"next": "D", "child": "E"},
        "D": {"next": None, "child": None},
        "E": {"next": None, "child": None},
    }
    assert teardown("A", nodes) == ["E", "C", "D", "A", "B"]


def test_deep_first_child_chain_beyond_unrolling():
    # Ten first-child levels: deeper than the binary's eight-level
    # unrolling, so the binary recurses here; the order must still be
    # deepest-first, then back up the chain.
    nodes = {}
    depth = 10
    for i in range(depth):
        nodes["n%d" % i] = {
            "next": None,
            "child": ("n%d" % (i + 1)) if i + 1 < depth else None,
        }
    assert teardown("n0", nodes) == ["n%d" % i for i in range(depth - 1, -1, -1)]


def test_child_chain_with_siblings_at_every_level():
    nodes = {
        "a": {"next": "b", "child": "c"},
        "b": {"next": None, "child": "e"},
        "c": {"next": "d", "child": None},
        "d": {"next": None, "child": None},
        "e": {"next": "f", "child": None},
        "f": {"next": None, "child": None},
    }
    assert teardown("a", nodes) == ["c", "d", "a", "e", "f", "b"]


def test_cycle_raises():
    nodes = {
        "a": {"next": "b", "child": None},
        "b": {"next": "a", "child": None},
    }
    try:
        teardown("a", nodes)
    except ValueError:
        return
    raise AssertionError("cyclic chain did not raise")


def test_unknown_node_raises():
    nodes = {"a": {"next": "missing", "child": None}}
    try:
        teardown("a", nodes)
    except ValueError:
        return
    raise AssertionError("unknown node did not raise")


def test_packet_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["window"]["start"] == "0x5f53f50"
    assert records["window"]["end_exclusive"] == "0x5f54119"
    assert records["window"]["size_bytes"] == 457
    assert records["census"]["direct_calls"] == ["0x5f53fe1", "0x5f54f8e"]
    assert len(records["delete_sites"]) == 9
    excerpt = (PACKET / "function_0x5f53f50.txt").read_text()
    assert "5f53fe1" in excerpt and "5f54118" in excerpt


TESTS = [
    test_null_head_deletes_nothing,
    test_single_node_no_child_no_next,
    test_sibling_chain_in_order,
    test_child_before_parent,
    test_worked_order_from_readme,
    test_deep_first_child_chain_beyond_unrolling,
    test_child_chain_with_siblings_at_every_level,
    test_cycle_raises,
    test_unknown_node_raises,
    test_packet_records,
]


if __name__ == "__main__":
    for test in TESTS:
        test()
        print("ok - %s" % test.__name__)
    print("%d tests passed" % len(TESTS))
