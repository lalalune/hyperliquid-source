"""Tests for the node #115 routine 0x5d50170 model (RE-001 object teardown).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from object_teardown_50170_115 import (  # noqa: E402
    Node, String, empty_obj, object_teardown)


def heap(pointer, capacity):
    return String(pointer, capacity, True)


def short():
    return String(None, 0, False)


def test_empty_object_frees_nothing():
    assert object_teardown(empty_obj()) == []


def test_heap_strings_use_capacity_plus_one():
    obj = empty_obj()
    obj["str_228"] = heap(0x1000, 15)
    obj["str_1e8"] = heap(0x2000, 0)
    obj["str_c8"] = heap(0x3000, 31)
    assert object_teardown(obj) == [
        ("delete", 0x1000, 16),
        ("delete", 0x2000, 1),
        ("delete", 0x3000, 32),
    ]


def test_single_strings_run_in_descending_offset_order():
    obj = empty_obj()
    for key, ptr in (("str_c8", 0xC00), ("str_228", 0x100),
                     ("str_108", 0x800), ("str_1a8", 0x500)):
        obj[key] = heap(ptr, 0)
    assert object_teardown(obj) == [
        ("delete", 0x100, 1),
        ("delete", 0x500, 1),
        ("delete", 0x800, 1),
        ("delete", 0xC00, 1),
    ]


def test_chain_node_order_call_then_strings_then_node():
    obj = empty_obj()
    obj["chain_288"] = Node(0x8000, "arg-a", heap(0x8100, 7), short(),
                            Node(0x9000, "arg-b", short(), heap(0x9100, 3)))
    assert object_teardown(obj) == [
        ("call", "arg-a"),
        ("delete", 0x8100, 8),
        ("delete", 0x8000, 0x60),
        ("call", "arg-b"),
        ("delete", 0x9100, 4),
        ("delete", 0x9000, 0x60),
    ]


def test_second_chain_runs_after_first_and_before_strings():
    obj = empty_obj()
    obj["chain_288"] = Node(0x1000, "first", short(), short())
    obj["chain_258"] = Node(0x2000, "second", short(), short())
    obj["str_228"] = heap(0x3000, 0)
    assert object_teardown(obj) == [
        ("call", "first"),
        ("delete", 0x1000, 0x60),
        ("call", "second"),
        ("delete", 0x2000, 0x60),
        ("delete", 0x3000, 1),
    ]


def test_short_form_strings_and_null_chains_free_nothing():
    obj = empty_obj()
    obj["chain_288"] = Node(0x1000, "arg", short(), short())
    # Node itself is still freed even when both its strings are short.
    assert object_teardown(obj) == [
        ("call", "arg"),
        ("delete", 0x1000, 0x60),
    ]
