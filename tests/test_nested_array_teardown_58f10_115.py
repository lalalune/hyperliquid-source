#!/usr/bin/env python3
"""Tests for the node #115 nested array teardown model 0x5d58f10."""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from nested_array_teardown_58f10_115 import nested_array_teardown  # noqa: E402


def test_null_inner_frees_nothing():
    assert nested_array_teardown(None) == []


def test_empty_array_heap_buffer():
    ops = nested_array_teardown(
        {"elements": [], "begin_nonnull": True, "buffer_bytes": 24})
    assert ops == [("free_buffer", 24), ("free_inner", 0x18)]


def test_empty_array_null_begin_skips_buffer_free():
    ops = nested_array_teardown(
        {"elements": [], "begin_nonnull": False, "buffer_bytes": 0})
    assert ops == [("free_inner", 0x18)]
    assert not any(op[0] == "free_buffer" for op in ops)


def test_null_element_skipped():
    ops = nested_array_teardown(
        {"elements": [None], "begin_nonnull": True, "buffer_bytes": 8})
    assert ops == [("free_buffer", 8), ("free_inner", 0x18)]


def test_inline_string_skips_string_free():
    ops = nested_array_teardown(
        {"elements": [{"string_alloc": False, "capacity": 7}],
         "begin_nonnull": False, "buffer_bytes": 0})
    assert ops == [("free_element", 0x20), ("free_inner", 0x18)]
    assert not any(op[0] == "free_string" for op in ops)


def test_allocated_string_freed_with_capacity_plus_one():
    ops = nested_array_teardown(
        {"elements": [{"string_alloc": True, "capacity": 15}],
         "begin_nonnull": False, "buffer_bytes": 0})
    assert ops[0] == ("free_string", 16)
    assert ops[1] == ("free_element", 0x20)


def test_two_elements_order_and_buffer_last():
    ops = nested_array_teardown(
        {"elements": [{"string_alloc": True, "capacity": 3},
                      {"string_alloc": False, "capacity": 0}],
         "begin_nonnull": True, "buffer_bytes": 16})
    assert ops == [("free_string", 4), ("free_element", 0x20),
                   ("free_element", 0x20),
                   ("free_buffer", 16), ("free_inner", 0x18)]


def test_inner_free_always_last():
    ops = nested_array_teardown(
        {"elements": [{"string_alloc": True, "capacity": 0}],
         "begin_nonnull": True, "buffer_bytes": 8})
    assert ops[-1] == ("free_inner", 0x18)
