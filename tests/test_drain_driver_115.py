"""Tests for tools/drain_driver_115.py (node #115 drain driver).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from drain_driver_115 import drive, prepare, refresh  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-drain-driver-115"


def make_outer(flag=0, refcount=1, items=None):
    inner = {"refcount": refcount, "list": list(items or [])}
    return {"inner": inner, "flag": flag, "agg": None, "nonempty": None}


def test_sequence_prepare_then_drain_then_refresh_then_flag():
    order = []
    outer = make_outer(flag=1, refcount=1, items=["a"])

    def prep(o):
        order.append("prepare")
        return prepare(o, lambda o, i: None, lambda n: None)

    def drain(inner, coll, arg):
        order.append("drain")
        assert inner is outer["inner"]
        assert coll == "coll" and arg == "pred"
        return 1

    def refr(o):
        order.append("refresh")
        refresh(o, lambda inner: 42)

    assert drive(outer, "coll", "pred", prep, drain, refr) == 1
    assert order == ["prepare", "drain", "refresh"]
    assert outer["agg"] == 42 and outer["nonempty"] == 1
    assert outer["flag"] == 0


def test_prepare_swap_changes_drain_object():
    outer = make_outer(flag=0, refcount=2, items=["x"])
    old = outer["inner"]
    seen = {}

    def move(o, inner):
        assert inner is old
        return {"refcount": 1, "list": ["y"]}

    def drain(inner, coll, arg):
        seen["inner"] = inner
        return 0

    result = drive(outer, "coll", "pred",
                   lambda o: prepare(o, move, lambda n: None),
                   drain,
                   lambda o: refresh(o, lambda inner: 7))
    assert result == 0
    assert seen["inner"] is outer["inner"] and seen["inner"] is not old
    assert old["refcount"] == 1 and "released" not in old
    assert outer["agg"] == 7 and outer["nonempty"] == 1


def test_prepare_swap_decrements_without_releasing():
    # From prepare alone the destroy-on-zero branch cannot trigger:
    # count 1 takes the fast path, count 2 decrements to 1, count 0
    # decrements to -1. Both arms below pin the decrement with no
    # release flag, matching the binary's branches.
    for start, expected in ((2, 1), (0, -1)):
        outer = make_outer(flag=0, refcount=start, items=[])
        old = outer["inner"]
        drive(outer, "coll", "pred",
              lambda o: prepare(o, lambda o, i: {"refcount": 5, "list": []},
                                lambda n: None),
              lambda inner, coll, arg: 0,
              lambda o: refresh(o, lambda inner: 0))
        assert old["refcount"] == expected and "released" not in old


def test_prepare_fast_path_calls_neither_move_nor_init():
    outer = make_outer(flag=0, refcount=1, items=["a"])
    calls = []
    result = prepare(outer,
                     lambda o, i: calls.append("move") or {},
                     lambda n: calls.append("init"))
    assert result is outer["inner"] and calls == []


def test_flag_one_clears_zero_and_other_unchanged():
    for flag, expected in ((1, 0), (0, 0), (2, 2), (255, 255)):
        outer = make_outer(flag=flag, refcount=1, items=[])
        drive(outer, "coll", "pred",
              lambda o: prepare(o, lambda o, i: {}, lambda n: None),
              lambda inner, coll, arg: 1,
              lambda o: refresh(o, lambda inner: 0))
        assert outer["flag"] == expected, flag


def test_drain_result_passes_through_and_refresh_empty_list():
    outer = make_outer(flag=0, refcount=1, items=[])
    result = drive(outer, "coll", "pred",
                   lambda o: prepare(o, lambda o, i: {}, lambda n: None),
                   lambda inner, coll, arg: 0,
                   lambda o: refresh(o, lambda inner: 99))
    assert result == 0
    assert outer["nonempty"] == 0 and outer["agg"] == 99


def test_flag_guard_raises():
    outer = make_outer(flag=256, refcount=1, items=[])
    try:
        drive(outer, "coll", "pred", lambda o: None,
              lambda inner, coll, arg: 0, lambda o: None)
    except ValueError:
        return
    raise AssertionError("expected ValueError for flag 256")


def test_packet_records_are_semantic_only():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert [w["start"] for w in records["windows"]] == [
        "0x5f14180", "0x5f13f90", "0x5f13450", "0x5f13f72"]
    blob = (PACKET / "records.json").read_text()
    assert "mnemonic" not in blob
    for name in ("function_0x5f14180.txt", "function_0x5f13f90.txt",
                 "function_0x5f13450.txt", "function_0x5f13f72.txt",
                 "frames.txt", "relocations.txt", "verify.py",
                 "export_excerpts.py", "census.py"):
        assert (PACKET / name).exists(), name


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
    print("ALL TESTS PASSED (%d tests)" % len(tests))
