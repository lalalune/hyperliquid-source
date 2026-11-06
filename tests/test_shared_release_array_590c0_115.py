#!/usr/bin/env python3
"""Tests for tools/shared_release_array_590c0_115.py.

Run directly (pytest is not installed on this VM):
    python3 -c "import tests.test_shared_release_array_590c0_115 as t; ..."
or via the packet checker research/work-items/RE-001-shared-release-array-590c0-115/verify.py,
which invokes every test_ function here.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from shared_release_array_590c0_115 import Control, release_array


def _holder(elements, buffer):
    return {"elements": elements, "buffer": buffer}


def _elem(control, string):
    return {"control": control, "string": string}


def test_empty_null_buffer():
    ops = release_array(_holder([], None))
    assert ops == ["return_null_buffer"], ops


def test_empty_nonnull_buffer():
    ops = release_array(_holder([], 0x40))
    assert ops == [("free_buffer", 0x40)], ops


def test_null_control_short_string():
    ops = release_array(_holder([_elem(None, ("short",))], 0x40))
    assert ops == [(0, "skip_null_control"), (0, "skip_short_string"),
                   ("free_buffer", 0x40)], ops


def test_null_control_heap_string():
    ops = release_array(_holder([_elem(None, ("heap", 0x0F))], 0x40))
    assert ops == [(0, "skip_null_control"), (0, "free_string", 0x10),
                   ("free_buffer", 0x40)], ops


def test_decrement_no_destroy():
    ctrl = Control(3, 2)
    ops = release_array(_holder([_elem(ctrl, ("short",))], 0x40))
    assert (ctrl.use, ctrl.weak) == (2, 2)
    assert not ctrl.disposed and not ctrl.destroyed
    assert not ctrl.destroyer_called
    assert ops[0] == (0, "decrement"), ops


def test_old_use_one_weak_many():
    ctrl = Control(1, 3)
    ops = release_array(_holder([_elem(ctrl, ("short",))], 0x40))
    assert (ctrl.use, ctrl.weak) == (0, 2)
    assert ctrl.disposed and not ctrl.destroyed
    assert ctrl.destroyer_called
    assert ops[0] == (0, "destroyer_dispose_weakdec"), ops


def test_sentinel_dispose_destroy():
    ctrl = Control(1, 1)
    ops = release_array(_holder([_elem(ctrl, ("short",))], 0x40))
    assert (ctrl.use, ctrl.weak) == (0, 0)
    assert ctrl.disposed and ctrl.destroyed
    assert not ctrl.destroyer_called
    assert ops[0] == (0, "sentinel_dispose_destroy"), ops


def test_destroyer_never_destroys_from_here():
    # Old use 1 with any weak count other than 1 takes the helper
    # path, whose destroy arm needs old weak == 1 -- but (1, 1) is
    # intercepted by the sentinel path first, so it cannot fire.
    ctrl = Control(1, 5)
    release_array(_holder([_elem(ctrl, ("short",))], 0x40))
    assert (ctrl.use, ctrl.weak) == (0, 4)
    assert ctrl.disposed and not ctrl.destroyed
    assert ctrl.destroyer_called


def test_zero_use_wraps():
    ctrl = Control(0, 2)
    ops = release_array(_holder([_elem(ctrl, ("short",))], 0x40))
    assert ctrl.use == 0xFFFFFFFF
    assert not ctrl.disposed and not ctrl.destroyed
    assert ops[0] == (0, "decrement"), ops


def test_single_vs_multi_threaded_same():
    def run(mode):
        ctrl = Control(1, 4)
        holder = _holder([_elem(ctrl, ("heap", 0x07))], 0x80)
        return release_array(holder, single_threaded=mode), ctrl
    ops_plain, ctrl_plain = run(True)
    ops_locked, ctrl_locked = run(False)
    assert ops_plain == ops_locked
    assert (ctrl_plain.use, ctrl_plain.weak) == (ctrl_locked.use,
                                                 ctrl_locked.weak)


def test_two_elements_order():
    first = Control(2, 2)
    second = Control(1, 1)
    holder = _holder([_elem(first, ("heap", 0x03)),
                      _elem(second, ("short",))], 0x80)
    ops = release_array(holder)
    assert ops == [(0, "decrement"), (0, "free_string", 0x04),
                   (1, "sentinel_dispose_destroy"),
                   (1, "skip_short_string"),
                   ("free_buffer", 0x80)], ops
    assert second.disposed and second.destroyed


def test_string_capacity_plus_one():
    ops = release_array(_holder([_elem(None, ("heap", 0))], 0x40))
    assert (0, "free_string", 1) in ops, ops
