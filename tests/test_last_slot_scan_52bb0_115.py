"""Tests for the node #115 last-slot scan model (0x5d52bb0)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from last_slot_scan_52bb0_115 import last_slot_scan


def _never(_idx):
    raise AssertionError("fallback must not be called")


def _never_count(_count):
    raise AssertionError("fallback must not be called")


def test_count_one_returns_one_without_table():
    result, events = last_slot_scan(1, [], _never, _never_count)
    assert result == 1
    assert events == [("entry_call", 0x60D5390)]


def test_count_zero_returns_zero_without_table():
    result, _events = last_slot_scan(0, [], _never, _never_count)
    assert result == 0


def test_top_entry_positive_span_returns_count():
    entries = [(0, 0), (0, 0), (10, 10 + 8)]
    result, _events = last_slot_scan(3, entries, _never, _never_count)
    assert result == 3


def test_lower_entry_positive_span_after_empty_top():
    # Top index 2 has span 0 and a losing fallback pair; index 1 wins
    # on span, so the fallback pair is consulted exactly once.
    calls = []

    def first(idx):
        calls.append(("first", idx))
        return 7

    def second(count):
        calls.append(("second", count))
        return 7

    entries = [(0, 0), (5, 5 + 16), (9, 9)]
    result, _events = last_slot_scan(3, entries, first, second)
    assert result == 2
    assert calls == [("first", 2), ("second", 3)]


def test_fallback_ordering_wins():
    def first(idx):
        return 3

    def second(count):
        return 4

    entries = [(0, 0), (0, 0), (0, 0)]
    result, _events = last_slot_scan(3, entries, first, second)
    assert result == 3


def test_fallback_receives_index_and_original_count():
    seen = []

    def first(idx):
        seen.append(("first", idx))
        return 9

    def second(count):
        seen.append(("second", count))
        return 9

    entries = [(0, 0), (0, 0), (0, 0), (0, 0)]
    result, _events = last_slot_scan(4, entries, first, second)
    assert result == 1
    assert seen == [("first", 3), ("second", 4),
                    ("first", 2), ("second", 4),
                    ("first", 1), ("second", 4)]


def test_exhaustion_returns_one_and_never_reads_index_zero():
    def first(idx):
        return 5

    def second(count):
        return 5

    # Index 0 entry is a sentinel that would win on span if read.
    entries = [(0, 10 ** 6), (0, 0), (0, 0)]
    result, _events = last_slot_scan(3, entries, first, second)
    assert result == 1


def test_negative_span_does_not_win():
    def first(idx):
        return 1

    def second(count):
        return 2

    # high < low gives a negative span; the fallback pair wins instead.
    entries = [(0, 0), (100, 90)]
    result, _events = last_slot_scan(2, entries, first, second)
    assert result == 2


def test_zero_span_does_not_win():
    def first(idx):
        return 8

    def second(count):
        return 8

    entries = [(0, 0), (42, 42)]
    result, _events = last_slot_scan(2, entries, first, second)
    assert result == 1
