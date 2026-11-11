#!/usr/bin/env python3
"""Tests for the node #115 record-loop teardown model 0x5d59510."""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from record_loop_teardown_59510_115 import (  # noqa: E402
    FIELDS, record_loop_teardown)

SHORT = ("short",)


def _record(capacities):
    return [("heap", cap) if cap is not None else SHORT
            for cap in capacities]


def test_empty_range_null_buffer():
    assert record_loop_teardown({"records": [], "buffer_size": None}) == []


def test_empty_range_heap_buffer():
    assert record_loop_teardown(
        {"records": [], "buffer_size": 0x100}) == [("free_buffer", 0x100)]


def test_single_record_all_short():
    ops = record_loop_teardown(
        {"records": [[SHORT] * 11], "buffer_size": 0x1D8})
    assert len(ops) == 12
    assert all(op[2] == "skip_string" for op in ops[:11])
    assert ops[-1] == ("free_buffer", 0x1D8)


def test_single_record_all_heap_in_field_order():
    caps = [0x10 * i for i in range(11)]
    ops = record_loop_teardown(
        {"records": [_record(caps)], "buffer_size": 0x1D8})
    assert [op[3] for op in ops[:11]] == [cap + 1 for cap in caps]
    assert [op[1] for op in ops[:11]] == list(range(11))


def test_field_offsets_match_binary_order():
    assert FIELDS[0] == (0x1B0, 0x1C0)
    assert FIELDS[-1] == (0x000, 0x010)
    assert len(FIELDS) == 11


def test_two_records_second_starts_after_first_last_field():
    first = _record([None] * 11)
    second = _record([0x20] + [None] * 10)
    ops = record_loop_teardown(
        {"records": [first, second], "buffer_size": 0x3B0})
    assert ops[11] == (1, 0, "free_string", 0x21)
    assert ops[-1] == ("free_buffer", 0x3B0)
    assert len(ops) == 23


def test_mixed_short_and_heap():
    record = [("heap", 0x07)] + [SHORT] * 9 + [("heap", 0x03)]
    ops = record_loop_teardown({"records": [record], "buffer_size": 0x1D8})
    assert ops[0] == (0, 0, "free_string", 0x08)
    assert ops[10] == (0, 10, "free_string", 0x04)
    assert ops[-1] == ("free_buffer", 0x1D8)


def test_buffer_free_size_passes_through():
    ops = record_loop_teardown({"records": [], "buffer_size": 0x5A0})
    assert ops == [("free_buffer", 0x5A0)]
