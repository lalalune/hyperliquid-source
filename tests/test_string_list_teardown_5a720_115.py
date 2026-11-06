#!/usr/bin/env python3
"""Tests for the node #115 string-list teardown model."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from string_list_teardown_5a720_115 import (  # noqa: E402
    destroy_holder, destroy_node, dispose_string, empty_node)


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


def test_string_short_form_rule():
    assert dispose_string({"inline": True, "capacity": 15}) is None
    assert dispose_string({"inline": False, "capacity": 15}) == 16
    assert dispose_string({"inline": False, "capacity": 0}) == 1


def test_node_disposes_a_before_b_then_frees_node():
    node = {"a": {"inline": False, "capacity": 7},
            "b": {"inline": False, "capacity": 3}}
    assert destroy_node(node) == [
        ("free_string", "a", 8), ("free_string", "b", 4),
        ("free_node", 0x68)]


def test_node_with_inline_strings_only_frees_node():
    assert destroy_node(empty_node()) == [("free_node", 0x68)]


def test_two_nodes_run_in_list_order():
    first = {"a": {"inline": False, "capacity": 1},
             "b": {"inline": True, "capacity": 0}}
    assert destroy_holder([first, empty_node()], "heap", 1) == [
        ("free_string", "a", 2), ("free_node", 0x68),
        ("free_node", 0x68), ("memset_buffer", 8),
        ("zero_fields", ["+0x10", "+0x18"]), ("free_buffer", 8)]


def test_holder_itself_never_freed():
    ops = destroy_holder([empty_node()], "heap", 1)
    assert all(op[0] != "free_holder" for op in ops)
