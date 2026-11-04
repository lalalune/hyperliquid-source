"""Tests for the node #115 routine 0x5d516f0 model (RE-001 object teardown).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from object_teardown_516f0_115 import (  # noqa: E402
    Node, String, empty_obj, object_teardown)


def heap(pointer, capacity):
    return String(pointer, capacity, True)


def short():
    return String(None, 0, False)


def test_empty_object_frees_nothing():
    assert object_teardown(empty_obj()) == []


def test_heap_strings_use_capacity_plus_one():
    obj = empty_obj()
    obj["str_160"] = heap(0x1000, 15)
    obj["str_138"] = heap(0x2000, 0)
    obj["str_28"] = heap(0x3000, 31)
    obj["str_08"] = heap(0x4000, 7)
    assert object_teardown(obj) == [
        ("delete", 0x1000, 16),
        ("delete", 0x2000, 1),
        ("delete", 0x3000, 32),
        ("delete", 0x4000, 8),
    ]


def test_buffers_use_end_minus_begin_and_null_skips():
    obj = empty_obj()
    obj["buf_110"] = (0x5000, 0x5040)
    obj["buf_f8"] = (None, 0x9999)
    obj["buf_e0"] = (0x6000, 0x6000)
    assert object_teardown(obj) == [
        ("delete", 0x5000, 0x40),
        ("delete", 0x6000, 0),
    ]


def test_phase_order_and_loop_strides():
    obj = empty_obj()
    obj["str_160"] = heap(0x100, 1)
    obj["elems_e0"] = [
        {"str_38": heap(0x200, 2), "str_18": short()},
        {"str_38": short(), "str_18": heap(0x300, 3)},
    ]
    obj["buf_e0"] = (0x400, 0x410)
    obj["records_c8"] = [
        {"str_100": heap(0x500, 4), "str_e0": short(),
         "str_50": heap(0x600, 5), "str_30": short()},
    ]
    obj["buf_c8"] = (0x700, 0x720)
    obj["list_a8"] = Node(0x800, "arg-a", Node(0x900, "arg-b"))
    obj["elems_80"] = [{"str_08": heap(0xA00, 6)}]
    obj["buf_80"] = (0xB00, 0xB08)
    assert object_teardown(obj) == [
        ("delete", 0x100, 2),
        ("delete", 0x200, 3),
        ("delete", 0x300, 4),
        ("delete", 0x400, 0x10),
        ("delete", 0x500, 5),
        ("delete", 0x600, 6),
        ("delete", 0x700, 0x20),
        ("teardown_call", "arg-a"),
        ("delete", 0x800, 0x30),
        ("teardown_call", "arg-b"),
        ("delete", 0x900, 0x30),
        ("delete", 0xA00, 7),
        ("delete", 0xB00, 0x08),
    ]


def test_list_walk_ends_at_null_and_keeps_node_size():
    obj = empty_obj()
    obj["list_a8"] = Node(0x111, "only", None)
    assert object_teardown(obj) == [
        ("teardown_call", "only"),
        ("delete", 0x111, 0x30),
    ]


def test_short_form_strings_never_delete():
    obj = empty_obj()
    obj["elems_e0"] = [{"str_38": short(), "str_18": short()}]
    obj["records_c8"] = [{"str_100": short(), "str_e0": short(),
                          "str_50": short(), "str_30": short()}]
    obj["elems_80"] = [{"str_08": short()}]
    assert object_teardown(obj) == []


def test_object_itself_is_never_freed():
    obj = empty_obj()
    obj["str_160"] = heap(0xC00, 9)
    ops = object_teardown(obj)
    assert ops == [("delete", 0xC00, 10)]
    assert all(op[1] != "object" for op in ops)
