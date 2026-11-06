"""Tests for the node #115 routine 0x5d520d0 model (RE-001 map-at lookup).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from map_at_lookup_520d0_115 import (  # noqa: E402
    SENTINEL, Node, OutOfRangeError, Temp, map_at_lookup)


class Harness:
    def __init__(self, temps):
        self.temps = temps  # tag -> Temp
        self.calls = []
        self.deletes = []
        self.assigns = []

    def builder(self, tag, field):
        self.calls.append((tag, field))
        return self.temps[tag]

    def assign(self, out, temp):
        self.assigns.append((out, temp))

    def delete(self, pointer):
        self.deletes.append(pointer)


def _full_graph():
    # Phase A chain (+0x10): h -> a -> b (tail kind 0).
    # Phase 1 walk from h: h (kind 0) steps via alt to x (kind 1).
    # Phase 2 walk from h: h (kind 0) -> x (kind 1) via alt -> y (kind 2).
    y = Node(kind=2, field=0x2002)
    x = Node(kind=1, alt=y, field=0x1001)
    b = Node(kind=0, field=0x000B)
    a = Node(kind=9, nxt=b, field=0x000A)
    h = Node(kind=0, nxt=a, alt=x, field=0x0000)
    return h


def test_full_path_tags_and_copy():
    h = _full_graph()
    hs = Harness({0: Temp(0, 0xAAAA, 0xBB, 0xC0),
                  1: Temp(0, 0xDDDD, 0xEE, 0xC1),
                  2: Temp(0, 0x12345678, 0x9ABC, 0xC2)})
    out, events = map_at_lookup(1, 1, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(0, 0x000B), (1, 0x1001), (2, 0x2002)], hs.calls
    assert hs.deletes == [0xC0, 0xC1], hs.deletes
    assert hs.assigns == [], hs.assigns
    assert (out.dword, out.word, out.qword) == (0x12345678, 0x9ABC, 0xC2)
    assert out.gap is None
    assert events == [("build", 0, 0x000B), ("delete", 0xC0),
                      ("build", 1, 0x1001), ("delete", 0xC1),
                      ("build", 2, 0x2002)], events


def test_phase_a_flag_zero_path():
    h = _full_graph()
    hs = Harness({0: Temp(1, 0, 0, 0xD0), 1: Temp(0), 2: Temp(0)})
    out, events = map_at_lookup(1, 1, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(0, 0x000B)], hs.calls
    assert len(hs.assigns) == 1
    assert (out.dword, out.word, out.qword) == (0, 0, 0)
    assert hs.deletes == [0xD0], hs.deletes
    assert events[0] == ("build", 0, 0x000B)
    assert ("assign",) in events


def test_phase_1_flag_zero_path():
    h = _full_graph()
    hs = Harness({0: Temp(0, 0, 0, 0xC0),
                  1: Temp(1, 0, 0, 0xD1), 2: Temp(0)})
    out, events = map_at_lookup(1, 1, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(0, 0x000B), (1, 0x1001)], hs.calls
    assert len(hs.assigns) == 1
    assert (out.dword, out.word, out.qword) == (0, 0, 0)
    assert hs.deletes == [0xC0, 0xD1], hs.deletes


def test_flag0_zero_skips_phase_a():
    h = _full_graph()
    hs = Harness({1: Temp(0, 0, 0, 0xC1),
                  2: Temp(0, 7, 8, 0xC2)})
    out, _ = map_at_lookup(0, 1, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(1, 0x1001), (2, 0x2002)], hs.calls
    assert (out.dword, out.word, out.qword) == (7, 8, 0xC2)


def test_both_flags_zero_goes_straight_to_phase_2():
    h = _full_graph()
    hs = Harness({2: Temp(0, 7, 8, 0xC2)})
    out, _ = map_at_lookup(0, 0, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(2, 0x2002)], hs.calls
    assert (out.dword, out.word, out.qword) == (7, 8, 0xC2)


def test_null_head_throws():
    hs = Harness({2: Temp(0)})
    try:
        map_at_lookup(0, 0, None, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("null head must throw")


def test_phase_a_chain_ending_at_sentinel_throws():
    h = Node(kind=0, nxt=SENTINEL)
    hs = Harness({0: Temp(0)})
    try:
        map_at_lookup(1, 0, h, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("sentinel tail must throw")
    assert hs.calls == [], hs.calls


def test_phase_a_tail_kind_nonzero_throws():
    h = Node(kind=0, nxt=Node(kind=3))
    hs = Harness({0: Temp(0)})
    try:
        map_at_lookup(1, 0, h, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("nonzero tail kind must throw")


def test_phase_1_candidate_kind_above_gate_throws():
    h = Node(kind=2)
    hs = Harness({1: Temp(0)})
    try:
        map_at_lookup(0, 1, h, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("kind-2 phase-1 candidate must throw")


def test_phase_1_no_candidate_throws():
    h = Node(kind=0, alt=Node(kind=0))
    hs = Harness({1: Temp(0)})
    try:
        map_at_lookup(0, 1, h, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("no candidate must throw")


def test_phase_2_candidate_kind_above_gate_throws():
    h = Node(kind=3)
    hs = Harness({2: Temp(0)})
    try:
        map_at_lookup(0, 0, h, hs.builder, hs.assign, hs.delete)
    except OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("kind-3 phase-2 candidate must throw")


def test_phase_2_copy_leaves_gap_unwritten():
    h = Node(kind=2, field=0x55)
    hs = Harness({2: Temp(0, 0x11111111, 0x2222, 0x33333333)})
    out, _ = map_at_lookup(0, 0, h, hs.builder, hs.assign, hs.delete)
    assert hs.calls == [(2, 0x55)], hs.calls
    assert hs.deletes == [], hs.deletes
    assert (out.dword, out.word, out.qword) == (0x11111111, 0x2222, 0x33333333)
    assert out.gap is None
