"""Tests for tools/seq_time_entry_insert_55670_115.py.

Each test drives the model end to end (chain walk through producer,
resolver, locked consumer, and the conditional log) and checks the
observable event sequence, not only constants. Run directly: every
test_* function is invoked by the packet checker (pytest is not
installed on this VM).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from seq_time_entry_insert_55670_115 import (  # noqa: E402
    EXPECTED_SLOT, LOG_FILE, LOG_FORMAT, Holder, Node, insert, wrapper,
)


def _chain(slots):
    nodes = [Node(s) for s in slots]
    for left, right in zip(nodes, nodes[1:]):
        left.next_node = right
    return nodes[0]


def _holder(slots, inner=0x5D48710, fallback=77):
    return Holder(_chain(slots), inner, fallback)


def _producer(heap="heap-token", length=42):
    def produce(node):
        return heap, length
    return produce


def _consumer(byte):
    def consume(target, r13, length):
        assert target == "H+0x18c8"
        return byte
    return consume


def test_chain_picks_first_differing_node():
    events = []
    insert(_holder([0x111, 0x222, 0x333, 0x444]),
           _producer(), lambda h: 9, _consumer(1), events)
    assert events[0] == ("producer", 0)


def test_chain_picks_second_node():
    events = []
    insert(_holder([EXPECTED_SLOT, 0x222, 0x333, 0x444]),
           _producer(), lambda h: 9, _consumer(1), events)
    assert events[0] == ("producer", 1)


def test_chain_picks_third_node():
    events = []
    insert(_holder([EXPECTED_SLOT, EXPECTED_SLOT, 0x333, 0x444]),
           _producer(), lambda h: 9, _consumer(1), events)
    assert events[0] == ("producer", 2)


def test_chain_falls_through_to_fourth_node():
    events = []
    insert(_holder([EXPECTED_SLOT, EXPECTED_SLOT, EXPECTED_SLOT, 0x444]),
           _producer(), lambda h: 9, _consumer(1), events)
    assert events[0] == ("producer", 3)


def test_resolver_uses_slot_call_when_inner_differs():
    seen = []
    events = []
    insert(_holder([0x111, 0, 0, 0], inner=0x999),
           _producer(), lambda h: seen.append("called") or 55,
           _consumer(1), events)
    assert seen == ["called"]
    assert ("resolver_call", 0x999) in events


def test_resolver_uses_fallback_field_when_inner_matches():
    got = []
    events = []
    insert(_holder([0x111, 0, 0, 0], inner=0x5D48710, fallback=77),
           _producer(), lambda h: 55,
           lambda t, r13, length: got.append(r13) or 1, events)
    assert got == [77]
    assert not any(e[0] == "resolver_call" for e in events)


def test_success_path_no_log_and_lock_order():
    events = []
    result = insert(_holder([0x111, 0, 0, 0]),
                    _producer(), lambda h: 9, _consumer(1), events)
    assert result == 1
    assert events == [("producer", 0), ("free", "heap-token"),
                      ("acquire",), ("release",)]


def test_failure_path_logs_with_exact_strings_and_args():
    events = []
    result = insert(_holder([0x111, 0, 0, 0], fallback=123),
                    _producer(length=7), lambda h: 9, _consumer(0),
                    events)
    assert result == 0
    assert events[-1] == ("log", LOG_FILE, LOG_FORMAT,
                          "component", 123, 7)
    assert LOG_FILE == "db/db_impl/db_impl.cc"
    assert LOG_FORMAT == ("[%s:5963] Failed to insert sequence number "
                          "to time entry: %lu -> %lu")


def test_producer_heap_freed_before_consumer():
    order = []
    events = []

    def produce(node):
        order.append("produce")
        return "tok", 3

    def consume(target, r13, length):
        order.append("consume")
        assert ("free", "tok") in events
        return 1

    insert(_holder([0x111, 0, 0, 0]), produce, lambda h: 9,
           consume, events)
    assert order == ["produce", "consume"]


def test_wrapper_double_deref():
    events = []
    holder = _holder([0x111, 0, 0, 0])
    result = wrapper([[holder]], _producer(), lambda h: 9,
                     _consumer(1), events)
    assert result == 1
    assert events[0] == ("producer", 0)


def test_exception_in_consumer_unlocks_and_resumes():
    events = []

    def consume(target, r13, length):
        raise RuntimeError("boom")

    try:
        insert(_holder([0x111, 0, 0, 0]), _producer(), lambda h: 9,
               consume, events)
    except RuntimeError:
        pass
    else:
        raise AssertionError("exception did not propagate")
    assert events[-2:] == [("release_landing",), ("resume",)]
    assert ("release",) not in events
