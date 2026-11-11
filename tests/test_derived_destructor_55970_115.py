"""Tests for the node #115 derived-class destructor pair model
(tools/derived_destructor_55970_115.py, RE-001 work item).

Run by importing this module and calling each test_* function (pytest
is not installed on this VM, so the packet checker invokes them
directly).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from derived_destructor_55970_115 import (
    BASE_VPTR,
    DERIVED_VPTR,
    MIDDLE_VPTR,
    Obj,
    Ref,
    complete_destroy,
    deleting_destroy,
)


def test_deleting_adds_self_free_only():
    vec = (True, [], 0)
    a = complete_destroy(Obj(vec))
    b = deleting_destroy(Obj(vec))
    assert a.frees == [("buffer", 0)]
    assert b.frees == [("buffer", 0), ("self", 0x48)]
    assert not a.self_freed and b.self_freed
    assert a.vptr == b.vptr == BASE_VPTR


def test_order_derived_then_middle_then_vector():
    r38 = Ref("r38", strong=1)
    r28 = Ref("r28", strong=1)
    vec = (True, [(True, 10)], 64)
    obj = deleting_destroy(Obj(vec, ptr28=r28, ptr38=r38))
    assert obj.frees == [("destroy", "r38"), ("destroy", "r28"),
                         ("elem", 0, 11), ("buffer", 64), ("self", 0x48)]
    assert r38.destroyed and r28.destroyed


def test_null_ref_fields_are_noops():
    obj = complete_destroy(Obj((True, [(False, 0)], 32)))
    assert obj.frees == [("buffer", 32)]


def test_short_string_frees_nothing():
    obj = complete_destroy(Obj((True, [(False, 0), (False, 0)], 48)))
    assert obj.frees == [("buffer", 48)]


def test_heap_string_uses_capacity_plus_one():
    obj = complete_destroy(Obj((True, [(True, 0), (True, 15), (True, 100)], 96)))
    assert obj.frees == [("elem", 0, 1), ("elem", 1, 16),
                         ("elem", 2, 101), ("buffer", 96)]


def test_null_vector_frees_nothing():
    obj = complete_destroy(Obj((False, [], 0)))
    assert obj.frees == []


def test_surviving_ref_is_not_destroyed():
    r = Ref("shared", strong=3)
    obj = complete_destroy(Obj((False, [], 0), ptr38=r))
    assert obj.frees == []
    assert not r.destroyed
    assert r.packed == 2


def test_special_packed_value_destroys():
    r = Ref("special", strong=1, weak=1)
    assert r.packed == 0x100000001
    obj = complete_destroy(Obj((False, [], 0), ptr28=r))
    assert obj.frees == [("destroy", "special")]
    assert r.destroyed and r.packed == 0


def test_vptr_constants():
    assert (DERIVED_VPTR, MIDDLE_VPTR, BASE_VPTR) == (
        0x64D08A8, 0x64CF200, 0x64D3430)


def test_null_vector_with_elements_is_an_error():
    try:
        complete_destroy(Obj((False, [(True, 5)], 0)))
    except ValueError:
        return
    raise AssertionError("expected ValueError")
