#!/usr/bin/env python3
"""Tests for the node #115 chunked array teardown model 0x5d58fb0."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from chunked_array_teardown_58fb0_115 import chunked_array_teardown  # noqa: E402


def test_null_inner_frees_nothing():
    assert chunked_array_teardown(None) == []


def test_empty_slot_range_still_frees_inner():
    ops = chunked_array_teardown({"inner_count": 3, "slots": []})
    assert ops == [("free_inner", 24)]


def test_one_slot_chunk_then_inner():
    ops = chunked_array_teardown({"inner_count": 1, "slots": ["a"]})
    assert ops == [("free_chunk", 0x200), ("free_inner", 8)]


def test_three_slots_in_order_inner_last():
    ops = chunked_array_teardown(
        {"inner_count": 2, "slots": ["a", "b", "c"]})
    assert ops == [("free_chunk", 0x200), ("free_chunk", 0x200),
                   ("free_chunk", 0x200), ("free_inner", 16)]


def test_chunk_size_fixed_regardless_of_slot():
    ops = chunked_array_teardown(
        {"inner_count": 0, "slots": ["x", "y"]})
    assert ops[0] == ("free_chunk", 0x200)
    assert ops[1] == ("free_chunk", 0x200)


def test_zero_inner_count_still_calls_inner_free():
    ops = chunked_array_teardown({"inner_count": 0, "slots": []})
    assert ops == [("free_inner", 0)]


def test_inner_size_is_count_times_eight():
    ops = chunked_array_teardown({"inner_count": 5, "slots": []})
    assert ops == [("free_inner", 40)]


def test_holder_itself_never_freed():
    ops = chunked_array_teardown({"inner_count": 1, "slots": ["a"]})
    assert all(op[0] in ("free_chunk", "free_inner") for op in ops)
    assert not any(op[0] == "free_holder" for op in ops)
