"""Tests for tools/foundation_report_accessor.py (node #94 0x5158ef0).

The refresh and the report builder are callees bound by their own
packets; here they are fakes that record their arguments, so the
tests pin this window's own control flow: the null guard, the
inverted flag, the lock/copy/unlock/render order, the full snapshot
copy, the in-place target render and the disposal branches.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from foundation_report_accessor import (
    CString,
    LockFailed,
    copy_snapshot,
    refresh_then_render,
    thunk_flag,
    thunk_refresh_flag,
)


def make_published():
    published = {}
    for off in (0x28, 0x38, 0x68, 0x78, 0x88, 0x98, 0xa8, 0xb8, 0xc8,
                0xd8, 0xe8, 0xf8, 0x108, 0x118, 0x128, 0x138, 0x148,
                0x150):
        published[off] = off
    published[0x48] = CString("snap-name", sso=True)
    return published


def make_outer(published=None):
    return {
        "inner": {"published": published if published is not None
                  else make_published()},
        "clock_holder": object(),
    }


class Target:
    """Render target mutated in place by the builder fake."""

    def __init__(self):
        self.content = "old"


def run(outer, flag=1, lock_result=0, snapshot_sso=True):
    calls = {"refresh": [], "render": [], "lock": [], "unlock": []}
    events = []
    target = Target()
    if not snapshot_sso:
        outer["inner"]["published"][0x48] = CString(
            "heap-name", sso=False, capacity=9)

    def refresh(o, f):
        calls["refresh"].append(f)

    def render(snapshot, tgt, holder):
        calls["render"].append((snapshot, holder))
        tgt.content = "report:" + snapshot[0x20].content

    def lock(inner):
        calls["lock"].append(inner)
        return lock_result

    def unlock(inner):
        calls["unlock"].append(inner)

    result = refresh_then_render(outer, target, flag, refresh, render,
                                 lock, unlock, events)
    return result, target, calls, events


class TestReportAccessor(unittest.TestCase):
    def test_null_inner_returns_zero_untouched(self):
        outer = {"inner": None, "clock_holder": object()}
        result, target, calls, events = run(outer)
        self.assertEqual(result, 0)
        self.assertEqual(target.content, "old")
        self.assertEqual(calls["refresh"], [])
        self.assertEqual(calls["lock"], [])
        self.assertEqual(events, [])

    def test_flag_inverted_both_arms(self):
        for flag, want in ((0, 1), (1, 0)):
            result, _, calls, _ = run(make_outer(), flag=flag)
            self.assertEqual(result, 1)
            self.assertEqual(calls["refresh"], [want])

    def test_thunk_flag_mapping(self):
        self.assertEqual(thunk_flag(0x5159130), 0)
        self.assertEqual(thunk_flag(0x5159140), 1)
        self.assertEqual(thunk_refresh_flag(0x5159130), 1)
        self.assertEqual(thunk_refresh_flag(0x5159140), 0)
        with self.assertRaises(ValueError):
            thunk_flag(0x5158EF0)

    def test_order_lock_copy_unlock_render_dispose(self):
        _, _, _, events = run(make_outer())
        kinds = [e[0] for e in events]
        self.assertEqual(kinds, ["refresh", "lock", "copy", "unlock",
                                 "render", "dispose_snapshot_string"])

    def test_render_receives_copy_target_and_clock_holder(self):
        outer = make_outer()
        _, target, calls, _ = run(outer)
        snapshot, holder = calls["render"][0]
        self.assertIs(holder, outer["clock_holder"])
        self.assertEqual(target.content, "report:snap-name")
        self.assertEqual(snapshot[0x00], 0x28)
        self.assertEqual(snapshot[0x10], 0x38)
        self.assertEqual(snapshot[0x20].content, "snap-name")
        self.assertEqual(snapshot[0x120], 0x148)
        self.assertEqual(snapshot[0x128], 0x150)
        self.assertEqual(len(snapshot), 19)

    def test_copy_is_independent_of_published(self):
        published = make_published()
        snap = copy_snapshot(published)
        published[0x48].content = "changed"
        published[0x28] = 999
        self.assertEqual(snap[0x20].content, "snap-name")
        self.assertEqual(snap[0x00], 0x28)

    def test_end_to_end_target_gets_report(self):
        _, target, _, events = run(make_outer())
        self.assertEqual(target.content, "report:snap-name")
        self.assertEqual(events[4], ("render",))

    def test_lock_failure_raises_before_render(self):
        outer = make_outer()
        calls = {"render": []}
        events = []
        target = Target()

        def render(snapshot, tgt, holder):
            calls["render"].append(True)

        with self.assertRaises(LockFailed):
            refresh_then_render(outer, target, 1, lambda o, f: None,
                                render, lambda i: 1, lambda i: None,
                                events)
        self.assertEqual(calls["render"], [])
        self.assertEqual(target.content, "old")
        self.assertEqual([e[0] for e in events], ["refresh"])

    def test_disposal_sso_arm_frees_nothing(self):
        _, _, _, events = run(make_outer(), snapshot_sso=True)
        self.assertEqual(events[-1],
                         ("dispose_snapshot_string", True, None))

    def test_disposal_heap_arm_uses_capacity_plus_one(self):
        _, _, _, events = run(make_outer(), snapshot_sso=False)
        self.assertEqual(events[-1],
                         ("dispose_snapshot_string", False, 10))

    def test_refresh_may_replace_inner(self):
        outer = make_outer()
        fresh = {"published": make_published()}
        fresh["published"][0x48] = CString("fresh-name", sso=True)

        def refresh(o, f):
            o["inner"] = fresh

        events = []
        target = Target()

        def render(snapshot, tgt, holder):
            tgt.content = snapshot[0x20].content

        result = refresh_then_render(
            outer, target, 1, refresh, render,
            lambda i: 0, lambda i: None, events)
        self.assertEqual(result, 1)
        self.assertEqual(target.content, "fresh-name")

    def test_no_move_assign_in_events(self):
        # Unlike 0x514fd60, this window builds no temp string, so
        # its event stream must contain no move-assign step.
        _, _, _, events = run(make_outer())
        self.assertNotIn("move_assign", [e[0] for e in events])
        self.assertNotIn("dispose_temp", [e[0] for e in events])


if __name__ == "__main__":
    unittest.main()
