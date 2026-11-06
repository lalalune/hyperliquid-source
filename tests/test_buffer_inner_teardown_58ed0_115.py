#!/usr/bin/env python3
"""Tests for the node #115 buffer-inner teardown model 0x5d58ed0."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from buffer_inner_teardown_58ed0_115 import buffer_inner_teardown  # noqa: E402


def test_null_inner_frees_nothing():
    assert buffer_inner_teardown(None) == []


def test_null_buffer_still_frees_inner():
    ops = buffer_inner_teardown(
        {"buffer_begin": None, "buffer_cap_end": 0})
    assert ops == [("free_inner", 0x18)]


def test_buffer_freed_before_inner_with_computed_size():
    ops = buffer_inner_teardown(
        {"buffer_begin": 0x1000, "buffer_cap_end": 0x1040})
    assert ops == [("free_buffer", 0x40), ("free_inner", 0x18)]


def test_buffer_size_is_cap_end_minus_begin():
    ops = buffer_inner_teardown(
        {"buffer_begin": 0x2000, "buffer_cap_end": 0x2300})
    assert ops[0] == ("free_buffer", 0x300)
    assert ops[1] == ("free_inner", 0x18)


def test_zero_size_buffer_still_freed_when_non_null():
    ops = buffer_inner_teardown(
        {"buffer_begin": 0x1000, "buffer_cap_end": 0x1000})
    assert ops == [("free_buffer", 0), ("free_inner", 0x18)]


def test_inner_size_fixed_regardless_of_buffer():
    for begin, cap in ((0x1000, 0x1000), (0x1000, 0x2000), (None, 0)):
        ops = buffer_inner_teardown(
            {"buffer_begin": begin, "buffer_cap_end": cap})
        assert ops[-1] == ("free_inner", 0x18)


def test_buffer_free_order_is_buffer_then_inner():
    ops = buffer_inner_teardown(
        {"buffer_begin": 0x500, "buffer_cap_end": 0x600})
    assert [op[0] for op in ops] == ["free_buffer", "free_inner"]


def test_holder_itself_never_freed():
    ops = buffer_inner_teardown(
        {"buffer_begin": 0x1000, "buffer_cap_end": 0x1040})
    assert all(op[0] in ("free_buffer", "free_inner") for op in ops)
    assert not any(op[0] == "free_holder" for op in ops)
