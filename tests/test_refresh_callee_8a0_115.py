"""Tests for the node #115 stats-snapshot refresh model (0x5eef8a0).

Target-grounded expectations: the slow/fast budget regimes and
their caps, the progress boundary (delta < allowed), the
first-differing-link chain walks, the snapshot fill fields and
name format, the string move, the publish-copy independence,
the null-subobject early return, and the full refresh step on
both paths. Run from the repository root:

    python3 tests/test_refresh_callee_8a0_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from refresh_callee_8a0_115 import (
    CONST_MINUS1, CONST_ZERO, PRODUCE_IDENTITY, WALKER, WALKER70,
    WALKER78, budget, caller_flag, fill_snapshot, format_name,
    is_progress, move_string, publish_copy, refresh_step,
    walk_slots)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def fresh_state(lo=100, hi=120, snapshot=None):
    return {"subobject_present": True, "counter_lo": lo,
            "counter_hi": hi, "snapshot": snapshot,
            "published": None, "no_progress": 0,
            "last_value": 0, "head": 0x5EED000}


def produce():
    return {"produce70": 11, "produce78": 22,
            "produce88": None, "produce80": None}


def test_budget_slow():
    per_unit, cap, allowed = budget(0, 100)
    check("slow per-unit 500", per_unit == 500)
    check("slow cap 180000000", cap == 180000000)
    check("slow allowed 50000", allowed == 50000)
    _p, _c, capped = budget(0, 10 ** 9)
    check("slow allowed capped", capped == 180000000)
    _p, _c, nocap = budget(0, None)
    check("slow gapless allowed is cap", nocap == 180000000)


def test_budget_fast():
    per_unit, cap, allowed = budget(1, 100)
    check("fast per-unit 10", per_unit == 10)
    check("fast cap 10000000", cap == 10000000)
    check("fast allowed 1000", allowed == 1000)
    per_unit2, _c2, _a2 = budget(2, 0)
    check("nonzero flag is fast", per_unit2 == 10)


def test_progress_boundary():
    check("delta below allowed progresses", is_progress(199, 200))
    check("delta zero progresses", is_progress(0, 200))
    check("delta equal to allowed does not progress",
          not is_progress(200, 200))
    check("delta above allowed does not progress",
          not is_progress(201, 200))


def test_walk_slots():
    idx, val = walk_slots([WALKER, WALKER, 0x5D4D500, WALKER], WALKER)
    check("walk stops at first differing link", (idx, val) == (2, 0x5D4D500))
    idx, val = walk_slots([0x5D4D500, WALKER, WALKER], WALKER)
    check("walk dispatches the head when it differs",
          (idx, val) == (0, 0x5D4D500))
    idx, val = walk_slots([WALKER, WALKER, WALKER, WALKER], WALKER)
    check("walk falls through to the last link when all match",
          (idx, val) == (3, WALKER))
    idx, val = walk_slots([PRODUCE_IDENTITY] * 9 + [0x5D427F0],
                          PRODUCE_IDENTITY)
    check("produce walk reaches the tenth link",
          (idx, val) == (9, 0x5D427F0))


def test_fill_chains():
    idx, _v = walk_slots([WALKER70, WALKER70, 0x5D2F000], WALKER70)
    check("slot70 walk picks the third link", idx == 2)
    idx, _v = walk_slots([WALKER78] * 5, WALKER78)
    check("slot78 walk falls through to the fifth link", idx == 4)


def test_format_name():
    check("name format", format_name("db", 0x1234, 42) == "db@0x1234#42")
    check("name format zero ptr", format_name("x", 0, 1) == "x@0x0#1")


def test_fill_snapshot():
    snap = fill_snapshot(41, 0x5EED000, "db", 0x1234, 42, 11, 22)
    check("fill seq increments", snap["seq"] == 42)
    check("fill head stored", snap["head"] == 0x5EED000)
    check("fill name built", snap["name"] == "db@0x1234#42")
    check("fill produce70", snap["produce70"] == 11)
    check("fill produce78", snap["produce78"] == 22)
    check("fill produce88 defaults to 0", snap["produce88"] == 0)
    check("fill produce80 defaults to -1", snap["produce80"] == -1)
    check("fill body zeroed", snap["body_zero"])
    check("fill last value zeroed", snap["last_value"] == 0)
    snap2 = fill_snapshot(0, 0, "n", 1, 2, 3, 4, produce88=7,
                          produce80=8)
    check("fill explicit produce88", snap2["produce88"] == 7)
    check("fill explicit produce80", snap2["produce80"] == 8)


def test_move_string():
    dst, src = move_string("hello")
    check("move short string", dst == "hello" and src == "")
    dst, src = move_string("a" * 40)
    check("move long string", dst == "a" * 40 and src == "")


def test_publish_copy():
    snap = fill_snapshot(0, 0x5EED000, "db", 0x1234, 42, 11, 22)
    pub = publish_copy(snap)
    check("publish copies fields", pub["seq"] == snap["seq"]
          and pub["name"] == snap["name"])
    pub["seq"] = 999
    check("publish copy is independent", snap["seq"] == 1)


def test_refresh_noop():
    state = fresh_state()
    state["subobject_present"] = False
    result = refresh_step(state, 0, iter([150, 160]), produce(),
                          "db", 0x1234, 42)
    check("null subobject returns at once", result["path"] == "noop")
    check("null subobject leaves state alone",
          state["counter_lo"] == 100 and state["published"] is None)


def test_refresh_progress():
    state = fresh_state(lo=100, hi=120)
    result = refresh_step(state, 0, iter([150, 160]), produce(),
                          "db", 0x1234, 42)
    check("progress path taken", result["path"] == "progress")
    check("progress stores value at counter_lo",
          state["counter_lo"] == 150)
    check("progress stores observed at counter_hi",
          state["counter_hi"] == 160)
    check("progress fills the snapshot",
          state["snapshot"]["name"] == "db@0x1234#42")
    check("progress snapshot seq starts at 1",
          state["snapshot"]["seq"] == 1)
    check("progress snapshot last value",
          state["snapshot"]["last_value"] == 160)
    check("progress publishes a copy",
          state["published"] is not None
          and state["published"]["name"] == "db@0x1234#42")


def test_refresh_no_progress():
    snap = fill_snapshot(5, 0x5EED000, "db", 0x1234, 42, 11, 22)
    state = fresh_state(lo=100, hi=120, snapshot=snap)
    result = refresh_step(state, 1, iter([200000]), produce(),
                          "db", 0x1234, 42)
    check("no-progress path taken", result["path"] == "no-progress")
    check("no-progress counter bumped", state["no_progress"] == 1)
    check("no-progress keeps the old snapshot",
          state["snapshot"]["seq"] == 6)
    check("no-progress publishes the old snapshot",
          state["published"]["seq"] == 6)
    check("no-progress counters unchanged",
          state["counter_lo"] == 100 and state["counter_hi"] == 120)


def test_refresh_boundary():
    # flag 1: allowed = min(10M, 20*10) = 200; delta exactly 200
    # must take the no-progress path.
    state = fresh_state(lo=100, hi=120)
    result = refresh_step(state, 1, iter([320]), produce(),
                          "db", 0x1234, 42)
    check("delta equal to allowed takes no-progress",
          result["path"] == "no-progress")
    state = fresh_state(lo=100, hi=120)
    result = refresh_step(state, 1, iter([319, 320]), produce(),
                          "db", 0x1234, 42)
    check("delta one below allowed progresses",
          result["path"] == "progress")


def test_refresh_gapless():
    state = fresh_state(lo=120, hi=120)
    result = refresh_step(state, 1, iter([150, 160]), produce(),
                          "db", 0x1234, 42)
    check("gapless refresh uses the cap",
          result["allowed"] == 10000000)
    check("gapless refresh progresses", result["path"] == "progress")


def test_caller_flag():
    check("caller flag 1 selects fast", caller_flag(1) == 0)
    check("caller flag 0 selects slow", caller_flag(0) == 1)
    check("identity constants",
          CONST_MINUS1 == 0x5D3EF70 and CONST_ZERO == 0x5D3EF80)


def main():
    for name, fn in sorted(dict(globals()).items()):
        if name.startswith("test_"):
            fn()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
