#!/usr/bin/env python3
"""Tests for tools/record_teardown_593f0_115.py.

Run directly (pytest is not installed on this VM):
    python3 -c "import tests.test_record_teardown_593f0_115 as t; ..."
or via the packet checker research/work-items/RE-001-record-teardown-593f0-115/verify.py,
which invokes every test_ function here.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from record_teardown_593f0_115 import record_teardown


def _holder(elements, buffer):
    return {"elements": elements, "buffer": buffer}


SHORT = ("short",)


def _heap(cap):
    return ("heap", cap)


def test_empty_null_buffer():
    ops = record_teardown(_holder([], None))
    assert ops == ["return_null_buffer"], ops


def test_empty_nonnull_buffer():
    ops = record_teardown(_holder([], 0x130))
    assert ops == [("free_buffer", 0x130)], ops


def test_all_short_fields():
    ops = record_teardown(_holder([[SHORT] * 4], 0x130))
    assert ops == [(0, 0, "skip_short_field"), (0, 1, "skip_short_field"),
                   (0, 2, "skip_short_field"), (0, 3, "skip_short_field"),
                   ("free_buffer", 0x130)], ops


def test_field_order_and_sizes():
    # Field order in the binary is +0x100, +0xe0, +0x50, +0x30,
    # each freed as (pointer, capacity + 1).
    ops = record_teardown(_holder(
        [[_heap(0x0F), _heap(0x1F), _heap(0x2F), _heap(0x3F)]], 0x130))
    assert ops == [(0, 0, "free_field", 0x10), (0, 1, "free_field", 0x20),
                   (0, 2, "free_field", 0x30), (0, 3, "free_field", 0x40),
                   ("free_buffer", 0x130)], ops


def test_zero_capacity_heap_field():
    ops = record_teardown(_holder([[SHORT, SHORT, SHORT, _heap(0)]], 0x130))
    assert (0, 3, "free_field", 1) in ops, ops


def test_two_records_order():
    ops = record_teardown(_holder(
        [[SHORT, _heap(0x07), SHORT, SHORT],
         [_heap(0x00), SHORT, SHORT, _heap(0x03)]], 0x260))
    assert ops == [(0, 0, "skip_short_field"), (0, 1, "free_field", 0x08),
                   (0, 2, "skip_short_field"), (0, 3, "skip_short_field"),
                   (1, 0, "free_field", 1), (1, 1, "skip_short_field"),
                   (1, 2, "skip_short_field"), (1, 3, "free_field", 0x04),
                   ("free_buffer", 0x260)], ops


def test_null_buffer_with_records_raises():
    try:
        record_teardown(_holder([[SHORT] * 4], None))
    except ValueError:
        return
    raise AssertionError("expected ValueError for null buffer with records")


def test_wrong_field_count_raises():
    try:
        record_teardown(_holder([[SHORT] * 3], 0x130))
    except ValueError:
        return
    raise AssertionError("expected ValueError for a 3-field record")
