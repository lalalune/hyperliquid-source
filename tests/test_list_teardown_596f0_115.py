#!/usr/bin/env python3
"""Tests for the node #115 list teardown model 0x5d596f0."""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from list_teardown_596f0_115 import list_teardown  # noqa: E402


def test_empty_list_inline_buffer():
    assert list_teardown(
        {"nodes": 0, "count": 0, "buffer_inline": True}) == [
        ("memset_buffer", 0), ("clear_list_slots",)]


def test_empty_list_heap_buffer():
    assert list_teardown(
        {"nodes": 0, "count": 3, "buffer_inline": False}) == [
        ("memset_buffer", 24), ("clear_list_slots",),
        ("free_buffer", 24)]


def test_two_nodes_heap_buffer_order():
    ops = list_teardown({"nodes": 2, "count": 2, "buffer_inline": False})
    assert ops == [
        ("free_node", 0x18), ("free_node", 0x18),
        ("memset_buffer", 16), ("clear_list_slots",),
        ("free_buffer", 16)]


def test_single_node_inline_buffer_no_free():
    ops = list_teardown({"nodes": 1, "count": 4, "buffer_inline": True})
    assert ops == [
        ("free_node", 0x18), ("memset_buffer", 32),
        ("clear_list_slots",)]
    assert not any(op[0] == "free_buffer" for op in ops)


def test_memset_size_is_count_times_eight():
    ops = list_teardown({"nodes": 0, "count": 5, "buffer_inline": False})
    assert ops[0] == ("memset_buffer", 40)
    assert ops[-1] == ("free_buffer", 40)


def test_free_size_equals_memset_size():
    ops = list_teardown({"nodes": 3, "count": 7, "buffer_inline": False})
    memset = [op for op in ops if op[0] == "memset_buffer"][0]
    freed = [op for op in ops if op[0] == "free_buffer"][0]
    assert memset[1] == freed[1] == 56


def test_heap_buffer_zero_count_frees_zero():
    assert list_teardown(
        {"nodes": 0, "count": 0, "buffer_inline": False}) == [
        ("memset_buffer", 0), ("clear_list_slots",),
        ("free_buffer", 0)]


def test_node_frees_precede_buffer_phase():
    ops = list_teardown({"nodes": 4, "count": 1, "buffer_inline": False})
    node_frees = [i for i, op in enumerate(ops) if op[0] == "free_node"]
    memset_at = [i for i, op in enumerate(ops)
                 if op[0] == "memset_buffer"][0]
    assert node_frees == [0, 1, 2, 3]
    assert all(i < memset_at for i in node_frees)
