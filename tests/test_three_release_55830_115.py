"""Tests for the node #115 three-release model (routine 0x5d55830,
RE-001 work item).

Each test pins one observable of the binary behavior: the +0x28,
+0x18, +0x08 release order, the null skip, the packed-sentinel
destroy path, the low-to-zero destructor rule, the high-half gate
on the deleter, and the no-write-back property (the holder fields
keep their objects).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from three_release_55830_115 import RefCounted, teardown


def empty_holder():
    return {field: None for field in ("+0x28", "+0x18", "+0x08")}


def test_all_null_releases_nothing():
    assert teardown(empty_holder()) == []


def test_order_is_28_then_18_then_08():
    holder = empty_holder()
    holder["+0x28"] = RefCounted("a", 1, 1)
    holder["+0x18"] = RefCounted("b", 1, 1)
    holder["+0x08"] = RefCounted("c", 1, 1)
    assert teardown(holder) == [
        ("destructor", "a"), ("deleter", "a"),
        ("destructor", "b"), ("deleter", "b"),
        ("destructor", "c"), ("deleter", "c"),
    ]


def test_null_middle_field_is_skipped():
    holder = empty_holder()
    holder["+0x28"] = RefCounted("a", 1, 1)
    holder["+0x08"] = RefCounted("c", 1, 1)
    assert teardown(holder) == [
        ("destructor", "a"), ("deleter", "a"),
        ("destructor", "c"), ("deleter", "c"),
    ]


def test_sentinel_destroys_immediately():
    ref = RefCounted("s", 1, 1)
    holder = empty_holder()
    holder["+0x18"] = ref
    assert teardown(holder) == [("destructor", "s"), ("deleter", "s")]
    assert (ref.low, ref.high) == (0, 0)


def test_low_to_zero_calls_destructor_but_high_gate_holds_deleter():
    ref = RefCounted("g", 1, 3)
    holder = empty_holder()
    holder["+0x28"] = ref
    assert teardown(holder) == [("destructor", "g")]
    assert (ref.low, ref.high) == (0, 2)


def test_low_nonzero_decrements_without_destroy():
    ref = RefCounted("n", 4, 2)
    holder = empty_holder()
    holder["+0x08"] = ref
    assert teardown(holder) == []
    assert (ref.low, ref.high) == (3, 2)


def test_high_reaches_zero_only_then_deleter():
    ref = RefCounted("h", 1, 1)
    holder = empty_holder()
    holder["+0x08"] = ref
    assert teardown(holder) == [("destructor", "h"), ("deleter", "h")]
    assert (ref.low, ref.high) == (0, 0)


def test_holder_fields_are_not_cleared():
    holder = empty_holder()
    ref = RefCounted("k", 1, 1)
    holder["+0x18"] = ref
    teardown(holder)
    assert holder["+0x18"] is ref
