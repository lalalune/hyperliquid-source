"""Tests for the node #115 shared-pointer table replace model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_shared_table_resize_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from shared_table_resize_115 import (  # noqa: E402
    AllocationError, Control, Obj, Table, allocation_bytes, dispose_helper,
    free_size, release_entry, release_table, replace, size_for_hw,
)


def test_sizing_small():
    assert size_for_hw(0) == (3, 8)  # 0 = hardware_concurrency unknown
    assert size_for_hw(1) == (3, 8)
    assert size_for_hw(8) == (3, 8)


def test_sizing_loop():
    assert size_for_hw(9) == (4, 16)
    assert size_for_hw(16) == (4, 16)
    assert size_for_hw(17) == (5, 32)
    assert size_for_hw(33) == (6, 64)
    assert size_for_hw((1 << 32) - 1) == (32, 1 << 32)


def test_allocation_bytes_and_guard():
    assert allocation_bytes(8) == 0x88
    assert allocation_bytes(16) == 16 * 16 + 8
    try:
        allocation_bytes(1 << 60)
    except AllocationError:
        pass
    else:
        raise AssertionError("overflow guard did not raise")


def test_replace_fresh_object():
    obj = Obj()
    result = replace(obj, 4)
    assert obj.log == 3
    assert obj.array is not None
    assert obj.array.header_count == 8
    assert obj.array.entries == [(None, None)] * 8
    assert result["dropped_old"] is None
    assert result["freed"] is None
    assert result["released"] is False


def test_replace_installs_and_leaks_old():
    # The key finding: a previous table is dropped, never released.
    live = Control(5, 2)
    old = Table(1, [(object(), live)])
    obj = Obj(array=old, log=3)
    result = replace(obj, 24)
    assert obj.log == 5  # 24 -> smallest k >= 4 with 2**k >= 24 is 5
    assert obj.array.header_count == 32
    assert obj.array.entries == [(None, None)] * 32
    assert result["dropped_old"] is old
    assert result["freed"] is None
    assert live.use == 5 and live.weak == 2  # untouched: no release ran
    assert live.dispose_calls == 0 and live.destroy_calls == 0


def test_replace_alloc_failure_state():
    obj = Obj()
    try:
        replace(obj, (1 << 60) + 1)  # k = 61, N >> 59 trips the guard
    except AllocationError:
        pass
    else:
        raise AssertionError("expected AllocationError")
    assert obj.array is None  # zeroed at entry, never installed
    assert obj.log == 61  # log set before the allocation call


def test_release_backward_order():
    order = []

    class Tracking(Control):
        def dispose(self):
            super().dispose()
            order.append("dispose")

        def destroy(self):
            super().destroy()
            order.append("destroy")

    first, second, third = Tracking(1, 2), Tracking(1, 2), Tracking(1, 2)
    table = Table(3, [(None, first), (None, second), (None, third)])
    release_table(table, single_threaded=True)
    # Last entry first: third, second, first each disposed once.
    assert order == ["dispose", "dispose", "dispose"]
    assert (first.use, second.use, third.use) == (0, 0, 0)


def test_release_null_control_skipped():
    table = Table(2, [(None, None), (None, Control(3, 1))])
    release_table(table, single_threaded=False)
    assert table.entries[1][1].use == 2


def test_release_sentinel_path():
    control = Control(1, 1)  # combined qword 0x100000001
    release_entry(control, single_threaded=True)
    assert (control.use, control.weak) == (0, 0)
    assert control.dispose_calls == 1 and control.destroy_calls == 1
    assert control.call_order == ["dispose", "destroy"]


def test_release_plain_decrement():
    control = Control(3, 2)
    release_entry(control, single_threaded=True)
    assert (control.use, control.weak) == (2, 2)
    assert control.dispose_calls == 0 and control.destroy_calls == 0


def test_release_use_one_with_weak_left():
    control = Control(1, 2)
    release_entry(control, single_threaded=False)  # atomic arm
    assert (control.use, control.weak) == (0, 1)
    assert control.dispose_calls == 1 and control.destroy_calls == 0


def test_release_use_zero_wraps():
    control = Control(0, 4)
    release_entry(control, single_threaded=True)
    assert control.use == 0xFFFFFFFF
    assert control.dispose_calls == 0 and control.destroy_calls == 0


def test_dispose_helper_weak_paths():
    control = Control(9, 1)
    dispose_helper(control)
    assert (control.use, control.weak) == (9, 0)
    assert control.dispose_calls == 1 and control.destroy_calls == 1
    control = Control(9, 0)
    dispose_helper(control)
    assert control.weak == 0xFFFFFFFF  # wraps, no destroy
    assert control.dispose_calls == 1 and control.destroy_calls == 0


def test_free_sizes():
    assert free_size(0) == 8  # empty table: header only
    assert free_size(3) == 56
    assert free_size(8) == 0x88


TESTS = [
    test_sizing_small,
    test_sizing_loop,
    test_allocation_bytes_and_guard,
    test_replace_fresh_object,
    test_replace_installs_and_leaks_old,
    test_replace_alloc_failure_state,
    test_release_backward_order,
    test_release_null_control_skipped,
    test_release_sentinel_path,
    test_release_plain_decrement,
    test_release_use_one_with_weak_left,
    test_release_use_zero_wraps,
    test_dispose_helper_weak_paths,
    test_free_sizes,
]


def main():
    for test in TESTS:
        test()
        print("PASS", test.__name__)
    print("all %d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
