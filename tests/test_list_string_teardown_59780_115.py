#!/usr/bin/env python3
"""Tests for tools/list_string_teardown_59780_115.py.

Run directly (pytest is not installed on this VM):
    python3 -c "import tests.test_list_string_teardown_59780_115 as t; ..."
or via the packet checker research/work-items/RE-001-list-string-teardown-59780-115/verify.py,
which invokes every test_ function here.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from list_string_teardown_59780_115 import list_string_teardown


def _holder(nodes, buffer, count):
    return {"nodes": nodes, "buffer": buffer, "count": count}


SHORT = ("short",)


def _heap(cap):
    return ("heap", cap)


def test_empty_list_heap_buffer():
    ops = list_string_teardown(_holder([], "heap", 3))
    assert ops == [("memset_buffer", 24), ("zero_slots", (0x10, 0x18)),
                   ("free_buffer", 24)], ops


def test_empty_list_inline_buffer():
    ops = list_string_teardown(_holder([], "inline", 2))
    assert ops == [("memset_buffer", 16), ("zero_slots", (0x10, 0x18)),
                   "return_inline_buffer"], ops


def test_single_short_node():
    ops = list_string_teardown(_holder([SHORT], "heap", 1))
    assert ops == [(0, "skip_string"), (0, "free_node", 0x38),
                   ("memset_buffer", 8), ("zero_slots", (0x10, 0x18)),
                   ("free_buffer", 8)], ops


def test_single_heap_node_size():
    # A heap string frees (pointer, capacity + 1); the node frees 0x38.
    ops = list_string_teardown(_holder([_heap(0x0F)], "heap", 0))
    assert ops[0] == (0, "free_string", 0x10), ops
    assert ops[1] == (0, "free_node", 0x38), ops
    assert ops[-1] == ("free_buffer", 0), ops


def test_zero_capacity_heap_string():
    ops = list_string_teardown(_holder([_heap(0)], "heap", 1))
    assert (0, "free_string", 1) in ops, ops


def test_node_order_head_to_tail():
    ops = list_string_teardown(
        _holder([_heap(0x03), SHORT, _heap(0x07)], "heap", 2))
    assert ops[0] == (0, "free_string", 0x04), ops
    assert ops[2] == (1, "skip_string"), ops
    assert ops[4] == (2, "free_string", 0x08), ops
    # Buffer ops come only after every node is freed.
    assert ops[6] == ("memset_buffer", 16), ops
    assert ops[-1] == ("free_buffer", 16), ops


def test_buffer_ops_after_last_node():
    ops = list_string_teardown(_holder([SHORT, SHORT], "inline", 4))
    assert ops[:4] == [(0, "skip_string"), (0, "free_node", 0x38),
                       (1, "skip_string"), (1, "free_node", 0x38)], ops
    assert ops[4:] == [("memset_buffer", 32),
                       ("zero_slots", (0x10, 0x18)),
                       "return_inline_buffer"], ops


def test_count_scales_buffer_size():
    ops = list_string_teardown(_holder([], "heap", 6))
    assert ("memset_buffer", 48) in ops, ops
    assert ("free_buffer", 48) in ops, ops
