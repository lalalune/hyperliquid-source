"""Tests for the node #115 routine 0x5d52e60 model (RE-001 drain-and-flush).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from drain_and_flush_52e60_115 import (  # noqa: E402
    HEAD, drain, flush, unlink)

MOD = 10


def _rec(next_, key, str_a=("a", None), str_b=("b", None),
          f50=1, f58=2, f60=3):
    return {"next": next_, "key": key, "str_a": str_a, "str_b": str_b,
            "f50": f50, "f58": f58, "f60": f60}


def test_drain_a_order_null_skip_and_chunk_reset():
    ops = drain([["e1", None, "e2"], ["e3"]], "A", 0x58)
    assert ops == [
        ("guard_open", 0x606CA40),
        ("guard_close", 0x60D52F0), ("destroy", "A", 0x58, "e1"),
        ("guard_open", 0x606CA40),
        ("guard_close", 0x60D52F0), ("skip_null", "A"),
        ("guard_open", 0x606CA40),
        ("chunk_reset", 0x200),
        ("guard_close", 0x60D52F0), ("destroy", "A", 0x58, "e2"),
        ("guard_open", 0x606CA40),
        ("chunk_reset", 0x200),
        ("guard_close", 0x60D52F0), ("destroy", "A", 0x58, "e3"),
        ("guard_open", 0x606CA40),
    ]


def test_drain_b_uses_290_destroy_no_entry_guard():
    ops = drain([["b1"]], "B", 0x290, entry_guard=False)
    assert ops == [
        ("chunk_reset", 0x200),
        ("guard_close", 0x60D52F0), ("destroy", "B", 0x290, "b1"),
        ("guard_open", 0x606CA40),
    ]


def test_unlink_head_same_bucket_links_head_only():
    records = {"r1": _rec("r2", 12), "r2": _rec(None, 22)}
    table = {2: HEAD}
    head, ops = unlink(table, "r1", "r1", records, MOD)
    assert head == "r2"
    assert ops == [("store", ("next", HEAD), "r2")]
    assert table == {2: HEAD}


def test_unlink_second_element_cross_bucket():
    records = {"r1": _rec("r2", 2), "r2": _rec("r3", 12),
               "r3": _rec(None, 25)}
    table = {2: "r1"}
    head, ops = unlink(table, "r1", "r2", records, MOD)
    assert head == "r1"
    assert ops == [
        ("store", ("bucket", 5), "r1"),
        ("store", ("bucket", 2), None),
        ("store", ("next", "r1"), "r3"),
    ]
    assert table == {2: None, 5: "r1"}
    assert records["r1"]["next"] == "r3"


def test_unlink_deep_chain_same_bucket_links_only():
    records = {"r1": _rec("r2", 2), "r2": _rec("r3", 12),
               "r3": _rec(None, 22)}
    table = {2: "r1"}
    head, ops = unlink(table, "r1", "r3", records, MOD)
    assert head == "r1"
    assert ops == [("store", ("next", "r2"), None)]
    assert table == {2: "r1"}


def test_unlink_head_null_successor_clears():
    records = {"r1": _rec(None, 12)}
    table = {2: HEAD}
    head, ops = unlink(table, "r1", "r1", records, MOD)
    assert head is None
    assert ops == [
        ("store", ("head",), None),
        ("store", ("bucket", 2), None),
        ("store", ("next", HEAD), None),
    ]
    assert table == {2: None}


def test_unlink_missing_record_raises():
    records = {"r1": _rec(None, 2), "r2": _rec(None, 12)}
    table = {2: "r1"}
    try:
        unlink(table, "r1", "r2", records, MOD)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a missing record")


def test_full_flush_two_records_tail_and_disposal_order():
    records = {
        "r1": _rec("r2", 12, str_a=("a1", None), str_b=("b1", 7),
                    f50=11, f58=12, f60=13),
        "r2": _rec(None, 22, str_a=("a2", None), str_b=("b2", None),
                    f50=21, f58=22, f60=23),
    }
    ops, state = flush([["e1"]], [], records, {2: HEAD}, MOD, "r1", 2, 5)
    assert state["head"] is None
    assert state["count"] == 0
    assert state["tail_counter"] == 4
    assert state["table"] == {2: None}
    emits = [op for op in ops if op[0] == "emit"]
    assert emits == [
        ("emit", 0x5E4B7C0, 13, "a1", "b1", 11, 12),
        ("emit", 0x5E4B7C0, 23, "a2", "b2", 21, 22),
    ]
    # Record r1: string B disposed (sized, capacity 7 + 1) before string A.
    first = ops.index(("dispose_string", "B", "sized", 8))
    assert ops[first + 1] == ("dispose_string", "A", "short")
    assert ops[first + 2] == ("free", 0x68, "r1")
    assert ops[first + 3] == ("count", 1)
    assert ops[-3:] == [("tail_count", 4), ("tail_call", 0x60D57C0),
                        ("tail_jump", 0x60D52F0)]


def test_flush_zero_count_drains_then_tail_only():
    ops, state = flush([], [], {}, {}, MOD, None, 0, 9)
    assert state == {"head": None, "count": 0, "tail_counter": 8,
                     "table": {}}
    assert not [op for op in ops if op[0] == "emit"]
    assert ops[-3:] == [("tail_count", 8), ("tail_call", 0x60D57C0),
                        ("tail_jump", 0x60D52F0)]


def test_flush_heap_build_outputs_dispose_sized():
    records = {"r1": _rec(None, 12)}
    ops, _state = flush([], [], records, {2: HEAD}, MOD, "r1", 1, 1,
                        build=lambda text: (text, 3))
    assert ("dispose_string", "outB", "sized", 4) in ops
    assert ("dispose_string", "outA", "sized", 4) in ops
