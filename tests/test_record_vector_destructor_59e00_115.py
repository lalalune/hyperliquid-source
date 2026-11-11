#!/usr/bin/env python3
"""Tests for the node #115 record-vector destructor model."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from record_vector_destructor_59e00_115 import (  # noqa: E402
    SENTINEL, destroy_record, destroy_vector, empty_record, release,
    shared_vector, string_vector)


def test_null_outer_begin_frees_nothing():
    assert destroy_vector([empty_record()], None) == []


def test_empty_range_still_frees_outer_buffer():
    assert destroy_vector([], 0x600) == [("free_outer_buffer", 0x600)]


def test_empty_record_only_frees_outer_buffer():
    assert destroy_vector([empty_record()], 0x300) == [
        ("free_outer_buffer", 0x300)]


def test_release_outcomes():
    assert release(None) == "skip"
    assert release(SENTINEL) == "destroy"
    assert release(1) == "destroy"
    assert release(2) == "decrement"
    assert release(0x100000002) == "decrement"


def test_string_short_form_rule():
    ops = string_vector(
        [{"inline": True, "capacity": 15},
         {"inline": False, "capacity": 15},
         {"inline": False, "capacity": 0}], 0x50)
    assert ops == [("free_string", 16), ("free_string", 1),
                   ("free_buffer", 0x50)]


def test_shared_vector_skips_null_elements():
    ops = shared_vector([None, 5, 1, SENTINEL], 0x20)
    assert ops == [("release", "decrement"), ("release", "destroy"),
                   ("release", "destroy"), ("free_buffer", 0x20)]


def test_full_record_phase_order():
    rec = empty_record()
    rec["inlined"] = {"0x2f8": 3, "0x2e8": SENTINEL, "0x298": 1}
    rec["strings"] = ([{"inline": False, "capacity": 7}], 0x28)
    rec["helpers"] = {"0x2c0": 9, "0x210": None, "0x1f8": 1,
                      "0x1d8": SENTINEL, "0x130": 4}
    rec["shared"] = ([None, 2], 0x10)
    rec["plain"] = {"0xb0": 0x40, "0x70": None}
    rec["last"] = 1
    assert destroy_record(rec) == [
        ("release", "0x2f8", "decrement"),
        ("release", "0x2e8", "destroy"),
        ("free_string", 8), ("free_buffer", 0x28),
        ("release", "0x2c0", "decrement"),
        ("release", "0x298", "destroy"),
        ("release", "0x1f8", "destroy"),
        ("release", "0x1d8", "destroy"),
        ("release", "decrement"), ("free_buffer", 0x10),
        ("release", "0x130", "decrement"),
        ("free_buffer", "0xb0", 0x40),
        ("release", "0x58", "destroy"),
    ]


def test_holder_itself_never_freed():
    ops = destroy_vector([empty_record()], 0x300)
    assert all(op[0] != "free_holder" for op in ops)
    assert ops == [("free_outer_buffer", 0x300)]
