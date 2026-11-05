"""Tests for tools/drain_append_527a0_115.py.

Every expectation is target-grounded: slot arithmetic, growth
thresholds and throw conditions come from the disassembly pinned in
research/work-items/RE-001-drain-append-527a0-115/.  Run directly
(no pytest on this VM): python3 -c with each test_* function, or
through the packet's verify.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.drain_append_527a0_115 import (
    GUARD, MAX_SIZE, BadAlloc, BadArrayNewLength, Deque, LengthError_,
    Source, drain, map_growth_slots,
)


def _deque(map_size, start, finish):
    slots = [[None] * 64 for _ in range(map_size)]
    return Deque(slots, start, finish)


def _guard_calls(trace):
    return [t for t in trace if t[0] == "guard"]


def test_empty_drain_returns_after_entry_guard():
    dq = _deque(4, (1, 0), (1, 0))
    src = Source([1] * 8, [], 0)
    trace = drain(GUARD, dq, src)
    assert trace == [("guard", GUARD)]
    assert dq.finish == (1, 0)
    assert src.base == 0 and src.heap == []


def test_inline_only_drain_in_order():
    dq = _deque(4, (1, 0), (1, 0))
    src = Source([10, 20, 30, 0, 0, 0, 0, 0], [], 3)
    trace = drain(GUARD, dq, src)
    assert len(_guard_calls(trace)) == 4
    assert [t for t in trace if t[0] == "store"] == [
        ("store", 1, 0, 10), ("store", 1, 1, 20), ("store", 1, 2, 30)]
    assert dq.slots[1][0:3] == [10, 20, 30]
    assert dq.finish == (1, 3)
    assert ("zero_base",) in trace
    assert src.base == 0


def test_heap_drain_reads_inline_then_heap_and_resets_source():
    dq = _deque(4, (1, 0), (1, 0))
    src = Source(list(range(8)), [40, 50], 8)
    trace = drain(GUARD, dq, src)
    assert len(_guard_calls(trace)) == 11
    assert [t[3] for t in trace if t[0] == "store"] == list(range(8)) + [40, 50]
    assert dq.finish == (1, 10)
    assert ("zero_base",) in trace and ("drain_heap",) in trace
    assert src.base == 0 and src.heap == []


def test_size_formula_matches_routine_arithmetic():
    dq = _deque(8, (2, 10), (5, 20))
    # (5 - 2 - 1) * 64 + 20 + (64 - 10) = 202
    assert dq.size() == 202
    assert _deque(4, (1, 0), (1, 0)).size() == 0
    assert _deque(4, (1, 5), (1, 5)).size() == 0


def test_chunk_alloc_growth_fills_last_slot_then_moves_finish():
    dq = _deque(4, (1, 0), (1, 62))
    src = Source([7, 8, 9, 0, 0, 0, 0, 0], [], 3)
    trace = drain(GUARD, dq, src)
    assert [t for t in trace if t[0] == "store"] == [
        ("store", 1, 62, 7), ("store", 1, 63, 8), ("store", 2, 0, 9)]
    assert ("alloc_chunk", 0x63F0DD0, 0x200) in trace
    assert dq.slots[1][62] == 7 and dq.slots[1][63] == 8
    assert dq.slots[2][0] == 9
    assert dq.finish == (2, 1)


def test_map_grow_doubles_map_and_centres_pointers():
    dq = _deque(2, (0, 0), (1, 63))
    src = Source([5, 0, 0, 0, 0, 0, 0, 0], [], 1)
    trace = drain(GUARD, dq, src)
    assert ("alloc_map", 0x63F0DD0, 6 * 8) in trace
    assert ("free_map", 0x63F0D80, 2, 16) in trace
    assert len(dq.slots) == 6
    assert dq.slots[1] is not None and dq.slots[2] is not None
    assert dq.slots[2][63] == 5
    assert dq.finish == (3, 0)
    assert dq.start == (1, 0)


def test_map_recenter_moves_pointers_inside_the_map():
    dq = _deque(8, (6, 0), (7, 63))
    src = Source([5, 0, 0, 0, 0, 0, 0, 0], [], 1)
    trace = drain(GUARD, dq, src)
    assert not any(t[0] == "alloc_map" for t in trace)
    assert ("memmove_map", 0x63F0A70, 2, 6, 2) in trace
    assert dq.slots[6] is None and dq.slots[7] is None
    assert dq.slots[2] is not None and dq.slots[3] is not None
    assert dq.slots[3][63] == 5
    assert dq.start == (2, 0) and dq.finish == (4, 0)


def test_length_error_at_max_size():
    span = MAX_SIZE // 64
    dq = Deque([], (0, 0), (span, 63))
    assert dq.size() == MAX_SIZE
    src = Source([1, 0, 0, 0, 0, 0, 0, 0], [], 1)
    try:
        drain(GUARD, dq, src)
    except LengthError_:
        return
    raise AssertionError("expected LengthError_")


def test_map_growth_slot_counts_and_overflow_throws():
    assert map_growth_slots(0) == 3
    assert map_growth_slots(2) == 6
    assert map_growth_slots(7) == 16
    huge = MAX_SIZE
    # 2 * (MAX_SIZE + 1) = 2**61: over the limit with a nonzero high
    # part, so the bad-array-new-length arm fires.
    try:
        map_growth_slots(huge)
    except BadArrayNewLength:
        pass
    else:
        raise AssertionError("expected BadArrayNewLength")
    # 2 * (2**59 + 1) = 2**60 + 2: over the limit but with a zero
    # high part, so the bad-alloc arm fires instead.
    edge = 1 << 59
    try:
        map_growth_slots(edge)
    except BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
