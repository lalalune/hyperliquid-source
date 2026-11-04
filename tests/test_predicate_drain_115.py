"""Tests for tools/predicate_drain_115.py (node #115 predicate drain).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from predicate_drain_115 import drain, transfer  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-predicate-drain-115"


def make_payload(refcount=1):
    return {"refcount": refcount}


def make_collection(count=0):
    return {"count": count, "inline": [], "vector": []}


def test_predicate_false_at_once_pops_nothing():
    obj = {"list2": [make_payload()], "size": 1}
    coll = make_collection()
    target = [100]
    assert drain(obj, coll, target, 0, lambda o, a: False, lambda p: 9) == 0
    assert len(obj["list2"]) == 1 and obj["size"] == 1
    assert coll["inline"] == [] and target == [100]


def test_predicate_true_but_empty_list_returns_zero():
    obj = {"list2": [], "size": 0}
    coll = make_collection()
    assert drain(obj, coll, [50], 0, lambda o, a: True, lambda p: 9) == 0


def test_single_pop_transfers_and_returns_one():
    payload = make_payload(1)
    obj = {"list2": [payload], "size": 1}
    coll = make_collection()
    target = [100]
    assert drain(obj, coll, target, 0, lambda o, a: True, lambda p: 30) == 1
    assert obj["list2"] == [] and obj["size"] == 0
    assert coll["inline"] == [payload] and coll["count"] == 1
    assert target == [70]


def test_pop_order_is_last_first():
    first, middle, last = make_payload(1), make_payload(1), make_payload(1)
    obj = {"list2": [first, middle, last], "size": 3}
    coll = make_collection()
    seen = []

    def aggregate(payload):
        seen.append(payload)
        return 0

    assert drain(obj, coll, [0], 0, lambda o, a: True, aggregate) == 1
    assert seen == [last, middle, first]
    assert coll["inline"] == [last, middle, first]


def test_drain_stops_when_predicate_turns_false():
    obj = {"list2": [make_payload(1), make_payload(1), make_payload(1)],
           "size": 3}
    coll = make_collection()
    calls = {"n": 0}

    def predicate(o, a):
        calls["n"] += 1
        return calls["n"] <= 2

    assert drain(obj, coll, [0], 0, predicate, lambda p: 0) == 1
    assert len(obj["list2"]) == 1 and obj["size"] == 1


def test_size_field_decrements_per_pop():
    obj = {"list2": [make_payload(1), make_payload(1)], "size": 2}
    drain(obj, make_collection(), [0], 0, lambda o, a: True, lambda p: 0)
    assert obj["size"] == 0


def test_size_mismatch_guard_raises():
    obj = {"list2": [make_payload(1)], "size": 5}
    try:
        drain(obj, make_collection(), [0], 0, lambda o, a: True, lambda p: 0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_transfer_positive_refcount_is_noop():
    payload = make_payload(2)
    coll = make_collection()
    target = [100]
    assert transfer(target, coll, payload, lambda p: 40) is False
    assert payload["refcount"] == 1
    assert coll["inline"] == [] and coll["count"] == 0 and target == [100]


def test_transfer_zero_refcount_still_transfers():
    # The binary proceeds when the decremented count is <= 0, so a
    # count of 0 (decremented to -1) transfers, not just a count of 1.
    payload = make_payload(0)
    coll = make_collection()
    target = [100]
    assert transfer(target, coll, payload, lambda p: 25) is True
    assert coll["inline"] == [payload] and target == [75]


def test_transfer_inline_boundary_and_vector_overflow():
    coll = make_collection(count=7)
    target = [1000]
    first = make_payload(1)
    assert transfer(target, coll, first, lambda p: 10) is True
    assert coll["inline"] == [first] and coll["count"] == 8
    second = make_payload(1)
    assert transfer(target, coll, second, lambda p: 10) is True
    assert coll["vector"] == [second] and coll["count"] == 8
    assert target == [980]


def test_transfer_subtracts_aggregate_return():
    coll = make_collection()
    target = [55]
    transfer(target, coll, make_payload(1), lambda p: 55)
    assert target == [0]


def test_packet_records_match_windows():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    starts = [w["start"] for w in records["windows"]]
    assert starts == ["0x5f14000", "0x5f13e00"]
    for name in ("function_0x5f14000.txt", "function_0x5f13e00.txt",
                 "frames.txt", "records.json"):
        assert (PACKET / name).exists()
    census = records["census"]
    assert census["drain_0x5f14000"]["direct_calls"] == ["0x5f141b4"]
    assert census["transfer_0x5f13e00"]["tail_jumps"] == ["0x5f1435f"]


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok %s" % name)
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
