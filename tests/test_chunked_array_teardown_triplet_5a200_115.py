#!/usr/bin/env python3
"""Tests for the node #115 chunked array teardown triplet model."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from chunked_array_teardown_triplet_5a200_115 import (  # noqa: E402
    ROUTINES, OWNER_SEQUENCE, chunked_array_teardown,
    owner_sequence_teardown, visited_slot_count)


def test_null_inner_frees_nothing():
    assert chunked_array_teardown(None, 0x200) == []


def test_empty_slot_range_still_frees_inner():
    ops = chunked_array_teardown({"inner_count": 3, "slots": []}, 0x200)
    assert ops == [("free_inner", 24)]


def test_one_slot_chunk_then_inner():
    ops = chunked_array_teardown({"inner_count": 1, "slots": ["a"]},
                                 0x200)
    assert ops == [("free_chunk", 0x200), ("free_inner", 8)]


def test_middle_routine_uses_0x1f8_chunks():
    ops = chunked_array_teardown({"inner_count": 1, "slots": ["a", "b"]},
                                 ROUTINES[0x5D5A270])
    assert ops == [("free_chunk", 0x1F8), ("free_chunk", 0x1F8),
                   ("free_inner", 8)]


def test_bound_slot_included_in_visit_count():
    assert visited_slot_count(0, 0) == 1
    assert visited_slot_count(2, 5) == 4
    assert visited_slot_count(5, 2) == 0


def test_inner_size_is_count_times_eight():
    ops = chunked_array_teardown({"inner_count": 5, "slots": []}, 0x1F8)
    assert ops == [("free_inner", 40)]


def test_holder_itself_never_freed():
    ops = chunked_array_teardown({"inner_count": 1, "slots": ["a"]},
                                 0x200)
    assert all(op[0] in ("free_chunk", "free_inner") for op in ops)
    assert not any(op[0] == "free_holder" for op in ops)


def test_owner_sequence_order_and_sizes():
    holders = {
        0x5D5A2E0: {"inner_count": 1, "slots": ["x"]},
        0x5D5A270: {"inner_count": 2, "slots": ["y"]},
        0x5D5A200: {"inner_count": 0, "slots": []},
    }
    assert OWNER_SEQUENCE == [0x5D5A2E0, 0x5D5A270, 0x5D5A200]
    assert owner_sequence_teardown(holders) == [
        ("free_chunk", 0x200), ("free_inner", 8),
        ("free_chunk", 0x1F8), ("free_inner", 16),
        ("free_inner", 0),
    ]
