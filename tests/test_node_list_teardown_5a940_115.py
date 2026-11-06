#!/usr/bin/env python3
"""Tests for the node #115 node-list teardown model."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from node_list_teardown_5a940_115 import (  # noqa: E402
    destroy_holder, destroy_node)


def test_null_head_heap_buffer_only_clears_and_frees():
    assert destroy_holder([], "heap", 3) == [
        ("memset_buffer", 24), ("zero_fields", ["+0x10", "+0x18"]),
        ("free_buffer", 24)]


def test_null_head_inline_buffer_is_not_freed():
    assert destroy_holder([], "inline", 2) == [
        ("memset_buffer", 16), ("zero_fields", ["+0x10", "+0x18"])]


def test_null_begin_zero_count_clears_nothing_and_frees_zero():
    # The code path still runs the buffer phase; the free size is 0.
    assert destroy_holder([], None, 0) == [
        ("memset_buffer", 0), ("zero_fields", ["+0x10", "+0x18"]),
        ("free_buffer", 0)]


def test_one_node_frees_exactly_0x38():
    assert destroy_node() == [("free_node", 0x38)]


def test_three_nodes_run_in_list_order_then_buffer_phase():
    assert destroy_holder([None, None, None], "heap", 1) == [
        ("free_node", 0x38), ("free_node", 0x38),
        ("free_node", 0x38), ("memset_buffer", 8),
        ("zero_fields", ["+0x10", "+0x18"]), ("free_buffer", 8)]


def test_nodes_free_before_buffer_phase():
    ops = destroy_holder([None], "inline", 0)
    assert ops[0] == ("free_node", 0x38)
    assert ops[1] == ("memset_buffer", 0)


def test_holder_itself_never_freed():
    ops = destroy_holder([None], "heap", 1)
    assert all(op[0] != "free_holder" for op in ops)


def test_null_begin_nonzero_count_is_not_modelled():
    try:
        destroy_holder([], None, 1)
    except ValueError:
        return
    raise AssertionError("null begin with nonzero count was modelled")
