"""Tests for tools/guard_exchange_c700_115.py (node #115 guard
value-exchange chain 0x607c700/0x607c720 with core 0x607c3b0,
exchange 0x6078810 and gated getter 0x6078650).

Run with pytest, or directly: ``python3 tests/test_guard_exchange_c700_115.py``
prints ALL TESTS PASSED when every check passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from guard_exchange_c700_115 import (acquire, exchange, gated_object,
                                     guard_exchange, release)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "RE-001-guard-exchange-c700-115"

GATE = 0x500000000  # any nonzero qword: only its zero-ness is tested


def make_state(gate=GATE, flag=1, field30=0xAAAA, with_object=True):
    obj = {"flag": flag, "field30": field30} if with_object else None
    return {"gate": gate, "object": obj}


def make_slot(value=0xFFFFFFFF):
    return {"value": value}


def test_round_trip_open_gates():
    state = make_state()
    slot = make_slot()
    acquire(state, slot, 9)
    assert state["object"]["field30"] == 9
    assert slot["value"] == 0xAAAA
    returned = release(state, slot)
    assert returned == 9
    assert state["object"]["field30"] == 0xAAAA
    # the release does not write the slot
    assert slot["value"] == 0xAAAA


def test_gate_qword_closed():
    state = make_state(gate=0)
    slot = make_slot()
    acquire(state, slot, 9)
    assert slot["value"] == 0
    assert state["object"]["field30"] == 0xAAAA
    assert release(state, slot) == 0
    assert state["object"]["field30"] == 0xAAAA
    assert guard_exchange(state, 7) == 0


def test_object_slot_closed():
    state = make_state(with_object=False)
    slot = make_slot()
    acquire(state, slot, 9)
    assert slot["value"] == 0
    assert gated_object(state) is None
    assert exchange(state, 3) == 0
    assert release(state, slot) == 0


def test_flag_byte_closed():
    state = make_state(flag=0)
    slot = make_slot()
    assert gated_object(state) is None
    acquire(state, slot, 9)
    assert slot["value"] == 0
    assert state["object"]["field30"] == 0xAAAA
    assert release(state, slot) == 0
    assert state["object"]["field30"] == 0xAAAA


def test_nested_lifo():
    state = make_state(field30=100)
    slot1, slot2 = make_slot(), make_slot()
    acquire(state, slot1, 9)
    assert (slot1["value"], state["object"]["field30"]) == (100, 9)
    acquire(state, slot2, 5)
    assert (slot2["value"], state["object"]["field30"]) == (9, 5)
    assert release(state, slot2) == 5
    assert state["object"]["field30"] == 9
    assert release(state, slot1) == 9
    assert state["object"]["field30"] == 100


def test_sequential_exchanges():
    state = make_state(field30=7)
    assert guard_exchange(state, 1) == 7
    assert state["object"]["field30"] == 1
    assert guard_exchange(state, 2) == 1
    assert state["object"]["field30"] == 2
    assert exchange(state, 0xFFFFFFFF) == 2
    assert state["object"]["field30"] == 0xFFFFFFFF


def test_getter_open_returns_object():
    state = make_state()
    assert gated_object(state) is state["object"]


def test_model_guards():
    state = make_state()
    for bad in (-1, 1 << 32):
        try:
            guard_exchange(state, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("no ValueError for value %r" % bad)
    bad_flag = make_state(flag=256)
    try:
        gated_object(bad_flag)
    except ValueError:
        pass
    else:
        raise AssertionError("no ValueError for flag 256")


def test_records():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    assert [w["name"] for w in records["windows"]] == \
        ["acquire", "release", "core", "exchange", "getter"]
    assert len(records["caller_records"]) == 40
    census = records["census"]
    assert len(census["0x607c700"]["direct_calls"]) == 11
    assert len(census["0x607c720"]["direct_calls"]) == 22
    assert census["0x607c3b0"]["direct_calls"] == \
        ["0x607c70a", "0x607c72a"]
    assert census["0x6078810"]["direct_calls"] == []
    assert census["0x6078810"]["tail_jumps"] == ["0x607c3d2"]
    assert len(census["0x6078650"]["direct_calls"]) == 8
    for entry in census.values():
        assert entry["qword_hits"] == []
        assert entry["relative_addend_hits"] == []


TESTS = [
    test_round_trip_open_gates,
    test_gate_qword_closed,
    test_object_slot_closed,
    test_flag_byte_closed,
    test_nested_lifo,
    test_sequential_exchanges,
    test_getter_open_returns_object,
    test_model_guards,
    test_records,
]


def main():
    for fn in TESTS:
        fn()
    print("ALL TESTS PASSED (%d tests)" % len(TESTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
