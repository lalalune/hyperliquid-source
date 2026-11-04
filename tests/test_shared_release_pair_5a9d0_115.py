#!/usr/bin/env python3
"""Tests for the node #115 shared-release pair model 0x5d5a9d0.

Each test pins one observable of the routine: the drain order
of the counted array, the forward order and end reset of the
vector, the plain versus atomic decrement selection, the
destroy-helper call at old count 1, the sentinel path, null
controls, and the empty-collection exits.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from shared_release_pair_5a9d0_115 import (  # noqa: E402
    DESTROY_HELPER, release_control, release_counted_array,
    release_holder, release_vector)


def test_counted_array_drains_last_to_first():
    ops, final = release_counted_array(3, [5, 1, 2], True)
    assert final == 0
    assert ops == [("decrement_plain", 2),
                   ("decrement_plain", 1),
                   ("call_destroy_helper", DESTROY_HELPER),
                   ("decrement_plain", 5)]


def test_counted_array_empty_skips():
    ops, final = release_counted_array(0, [], True)
    assert (ops, final) == ([], 0)


def test_vector_forward_order_and_end_reset():
    ops = release_vector([2, 1], False)
    assert ops == [("decrement_atomic", 2),
                   ("decrement_atomic", 1),
                   ("call_destroy_helper", DESTROY_HELPER),
                   ("reset_end_to_begin",)]


def test_vector_empty_leaves_end_unchanged():
    assert release_vector([], True) == []


def test_plain_vs_atomic_selection():
    assert release_control(3, True) == [("decrement_plain", 3)]
    assert release_control(3, False) == [("decrement_atomic", 3)]


def test_sentinel_path():
    assert release_control(0x100000001, True) == [
        ("zero_count",), ("call_vtable_slot_0x10",),
        ("call_vtable_slot_0x18",)]


def test_null_controls_skipped():
    ops, final = release_counted_array(2, [None, 1], True)
    assert ops == [("decrement_plain", 1),
                   ("call_destroy_helper", DESTROY_HELPER),
                   ("skip_null",)]
    assert final == 0
    assert release_vector([None, 2], True) == [
        ("skip_null",), ("decrement_plain", 2),
        ("reset_end_to_begin",)]


def test_holder_end_to_end():
    ops, final = release_holder(1, [1], [2], False)
    assert final == 0
    assert ops == [("decrement_atomic", 1),
                   ("call_destroy_helper", DESTROY_HELPER),
                   ("decrement_atomic", 2),
                   ("reset_end_to_begin",)]
