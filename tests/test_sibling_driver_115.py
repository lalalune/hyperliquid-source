"""Tests for tools/sibling_driver_115.py (node #115 sibling drain
driver 0x5f140c0 with its wrapper, pre-call and lazy-init callee).

Run with pytest, or directly: ``python3 tests/test_sibling_driver_115.py``
prints ALL TESTS PASSED when every check passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from sibling_driver_115 import (DEFAULT_SLOT, drive, lazy_init,
                                pre_call, wrapper)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "RE-001-sibling-driver-115"


def make_world(counter=0, first_flag=0, flag=0, slot=DEFAULT_SLOT,
               lazy_inner=None, lazy_flag=0):
    calls = []
    outer = {"inner": {"position": "pos", "counter": 5, "sum": 100},
             "counter": counter, "first_flag": first_flag, "flag": flag}
    collection = {
        "dispatch_object": {"slot": slot},
        "lazy": {"inner": lazy_inner, "cb_arg": "cb-arg",
                 "flag": lazy_flag},
    }

    def prepare(o, c, p):
        calls.append(("prepare", o is outer, c is collection, p))

    def refresh(o):
        calls.append(("refresh", o is outer))

    def dispatch(obj):
        calls.append(("dispatch", obj is collection["dispatch_object"]))

    def callback(inner, arg):
        calls.append(("callback", inner, arg))

    def drain(inner, coll, pred):
        calls.append(("drain", pred))
        return 7  # driver ignores it; its return is always 1

    def pre_call_fn(inner, coll):
        node = pre_call(inner, coll, lambda c: 3,
                        lambda n, pos: calls.append(("hook", n, pos)))
        calls.append(("pre_call_node", node))
        return node

    def wrapper_fn(inner, coll, pred):
        calls.append(("wrapper", pred))
        return wrapper(inner, coll, pred, pre_call_fn, drain)

    return outer, collection, calls, prepare, refresh, dispatch, \
        callback, wrapper_fn


def test_full_sequence_first_run():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world(lazy_inner={"first": "f", "field20": 0})
    result = drive(outer, coll, 9, prepare, wrap, dispatch, refresh, cb)
    assert result == 1
    kinds = [c[0] for c in calls]
    assert kinds == ["prepare", "wrapper", "hook", "pre_call_node",
                     "drain", "callback", "refresh"], kinds
    assert outer["counter"] == 1
    assert outer["first_flag"] == 1
    # The drain received 0, not the driver's predicate argument 9.
    assert calls[4] == ("drain", 0)
    assert coll["lazy"]["flag"] == 1


def test_dispatch_skipped_for_default_fires_for_override():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world(slot="override-slot")
    drive(outer, coll, 0, prepare, wrap, dispatch, refresh, cb)
    assert ("dispatch", True) in calls
    outer2, coll2, calls2, p2, r2, d2, cb2, w2 = make_world()
    drive(outer2, coll2, 0, p2, w2, d2, r2, cb2)
    assert not any(c[0] == "dispatch" for c in calls2)


def test_counter_second_run_leaves_first_flag():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world(counter=1, first_flag=0)
    drive(outer, coll, 0, prepare, wrap, dispatch, refresh, cb)
    assert outer["counter"] == 2
    assert outer["first_flag"] == 0


def test_counter_wraps_32_bit():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world(counter=0xFFFFFFFF)
    drive(outer, coll, 0, prepare, wrap, dispatch, refresh, cb)
    assert outer["counter"] == 0
    assert outer["first_flag"] == 0


def test_flag_conditional_clear():
    for start, expected in ((1, 0), (0, 0), (2, 2), (255, 255)):
        outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
            make_world(flag=start)
        drive(outer, coll, 0, prepare, wrap, dispatch, refresh, cb)
        assert outer["flag"] == expected, (start, outer["flag"])


def test_prepare_swap_changes_wrapped_inner():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world()
    new_inner = {"position": "new-pos", "counter": 0, "sum": 0}
    seen = {}

    def swapping_prepare(o, c, p):
        o["inner"] = new_inner

    def recording_wrapper(inner, c, p):
        seen["inner"] = inner
        return wrap(inner, c, p)

    drive(outer, coll, 0, swapping_prepare, recording_wrapper,
          dispatch, refresh, cb)
    assert seen["inner"] is new_inner
    assert new_inner["counter"] == 1
    assert new_inner["sum"] == 3


def test_pre_call_effects():
    inner = {"position": "pos", "counter": 10, "sum": 2**64 - 5}
    hooks = []
    node = pre_call(inner, "coll", lambda c: 7,
                    lambda n, pos: hooks.append((n, pos)))
    assert node == {"collection": "coll"}
    assert hooks == [(node, "pos")]
    assert inner["counter"] == 11
    assert inner["sum"] == 2  # 64-bit wrapping addition


def test_lazy_init_arms():
    # Null inner: flag untouched, no callback.
    arg = {"inner": None, "cb_arg": "x", "flag": 0}
    seen = []
    lazy_init(arg, lambda i, a: seen.append((i, a)))
    assert arg["flag"] == 0 and seen == []
    # Flag already set: flag untouched, no callback.
    arg = {"inner": {"first": "f", "field20": 0}, "cb_arg": "x",
           "flag": 1}
    lazy_init(arg, lambda i, a: seen.append((i, a)))
    assert arg["flag"] == 1 and seen == []
    # First qword null but +0x20 nonzero: callback runs, flag set.
    inner = {"first": None, "field20": 4}
    arg = {"inner": inner, "cb_arg": "x", "flag": 0}
    lazy_init(arg, lambda i, a: seen.append((i, a)))
    assert seen == [(inner, "x")] and arg["flag"] == 1
    # Both null/zero: no callback, but the flag is still set.
    seen.clear()
    arg = {"inner": {"first": None, "field20": 0}, "cb_arg": "x",
           "flag": 0}
    lazy_init(arg, lambda i, a: seen.append((i, a)))
    assert seen == [] and arg["flag"] == 1


def test_flag_range_guard():
    outer, coll, calls, prepare, refresh, dispatch, cb, wrap = \
        make_world(flag=256)
    try:
        drive(outer, coll, 0, prepare, wrap, dispatch, refresh, cb)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for flag 256")


def test_packet_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5f140c0", "0x5f14090", "0x5f127b0",
                      "0x5f127f6", "0x605e860"], starts
    assert records["census"]["0x5f140c0"]["direct_calls"] == \
        ["0x5e83a33", "0x5e8aba9", "0x5ed1c20"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    for test in TESTS:
        test()
    print("ALL TESTS PASSED (%d tests)" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
