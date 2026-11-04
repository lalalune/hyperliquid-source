"""Tests for the node #115 three-array string teardown model
(routine 0x5d54fc0, RE-001 work item).

Each test pins one observable of the binary behavior: the A, B, C
order, the short-string skip, the capacity + 1 heap size, the
null-begin skip, the empty-but-non-null buffer free, and the
no-write-back property (the model returns only frees; the holder
triples are never mutated).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from three_array_string_teardown_54fc0_115 import teardown


def empty_holder():
    return {name: (False, [], 0) for name in ("A", "B", "C")}


def test_all_null_vectors_free_nothing():
    assert teardown(empty_holder()) == []


def test_order_is_a_then_b_then_c():
    holder = empty_holder()
    holder["A"] = (True, [(True, 10)], 32)
    holder["B"] = (True, [(True, 20)], 32)
    holder["C"] = (True, [(True, 30)], 32)
    assert teardown(holder) == [
        ("elem", "A", 0, 11), ("buffer", "A", 32),
        ("elem", "B", 0, 21), ("buffer", "B", 32),
        ("elem", "C", 0, 31), ("buffer", "C", 32),
    ]


def test_short_strings_free_nothing_but_buffer_still_freed():
    holder = empty_holder()
    holder["A"] = (True, [(False, 0), (False, 0)], 64)
    assert teardown(holder) == [("buffer", "A", 64)]


def test_mixed_heap_and_short_elements_in_order():
    holder = empty_holder()
    holder["B"] = (True, [(False, 0), (True, 5), (False, 0), (True, 0)], 128)
    assert teardown(holder) == [
        ("elem", "B", 1, 6), ("elem", "B", 3, 1), ("buffer", "B", 128),
    ]


def test_heap_size_is_capacity_plus_one():
    holder = empty_holder()
    holder["C"] = (True, [(True, 15), (True, 16)], 64)
    assert teardown(holder) == [
        ("elem", "C", 0, 16), ("elem", "C", 1, 17), ("buffer", "C", 64),
    ]


def test_empty_but_non_null_vector_still_frees_its_buffer():
    holder = empty_holder()
    holder["A"] = (True, [], 96)
    holder["C"] = (True, [], 0)
    assert teardown(holder) == [("buffer", "A", 96), ("buffer", "C", 0)]


def test_null_begin_with_elements_is_rejected():
    holder = empty_holder()
    holder["B"] = (False, [(True, 3)], 32)
    try:
        teardown(holder)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_holder_is_not_mutated():
    holder = empty_holder()
    holder["A"] = (True, [(True, 7)], 32)
    before = {k: (v[0], list(v[1]), v[2]) for k, v in holder.items()}
    teardown(holder)
    after = {k: (v[0], list(v[1]), v[2]) for k, v in holder.items()}
    assert before == after
