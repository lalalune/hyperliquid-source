"""Tests for tools/foundation_refresh_render.py (node #94 0x514fd60).

The refresh and the formatter are callees bound by their own packets;
here they are fakes that record their arguments, so the tests pin
this window's own control flow: the null guard, the inverted flag,
the lock/copy/unlock/render order, the full snapshot copy, the
move-assign and the disposal branches.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from foundation_refresh_render import (
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


def run(outer, flag=1, lock_result=0, sso_temp=True):
    calls = {"refresh": [], "render": [], "lock": [], "unlock": []}
    events = []
    dest = [CString("old", sso=True)]

    def refresh(o, f):
        calls["refresh"].append(f)

    def render(temp, snapshot, holder):
        calls["render"].append((snapshot, holder))
        temp.content = "report:" + snapshot[0x20].content
        temp.sso = sso_temp

    def lock(inner):
        calls["lock"].append(inner)
        return lock_result

    def unlock(inner):
        calls["unlock"].append(inner)

    result = refresh_then_render(outer, dest, flag, refresh, render,
                                 lock, unlock, events)
    return result, dest, calls, events


class TestRefreshRender(unittest.TestCase):
    def test_null_inner_returns_zero_untouched(self):
        outer = {"inner": None, "clock_holder": object()}
        result, dest, calls, events = run(outer)
        self.assertEqual(result, 0)
        self.assertEqual(dest[0].content, "old")
        self.assertEqual(calls["refresh"], [])
        self.assertEqual(calls["lock"], [])
        self.assertEqual(events, [])

    def test_flag_inverted_both_arms(self):
        for flag, want in ((0, 1), (1, 0)):
            result, _, calls, _ = run(make_outer(), flag=flag)
            self.assertEqual(result, 1)
            self.assertEqual(calls["refresh"], [want])

    def test_thunk_flag_mapping(self):
        self.assertEqual(thunk_flag(0x514FFE0), 0)
        self.assertEqual(thunk_flag(0x514FFF0), 1)
        self.assertEqual(thunk_refresh_flag(0x514FFE0), 1)
        self.assertEqual(thunk_refresh_flag(0x514FFF0), 0)
        with self.assertRaises(ValueError):
            thunk_flag(0x514FD60)

    def test_order_lock_copy_unlock_render_assign_dispose(self):
        _, _, _, events = run(make_outer())
        kinds = [e[0] for e in events]
        self.assertEqual(kinds, ["refresh", "lock", "copy", "unlock",
                                 "render", "move_assign",
                                 "dispose_temp",
                                 "dispose_snapshot_string"])

    def test_render_receives_copy_and_clock_holder(self):
        outer = make_outer()
        _, _, calls, _ = run(outer)
        snapshot, holder = calls["render"][0]
        self.assertIs(holder, outer["clock_holder"])
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

    def test_end_to_end_dest_gets_report(self):
        _, dest, _, events = run(make_outer())
        self.assertEqual(dest[0].content, "report:snap-name")
        self.assertEqual(events[4], ("render", "report:snap-name"))

    def test_lock_failure_raises_before_render(self):
        outer = make_outer()
        calls = {"render": []}
        events = []
        dest = [CString("old", sso=True)]

        def render(temp, snapshot, holder):
            calls["render"].append(True)

        with self.assertRaises(LockFailed):
            refresh_then_render(outer, dest, 1, lambda o, f: None,
                                render, lambda i: 1, lambda i: None,
                                events)
        self.assertEqual(calls["render"], [])
        self.assertEqual(dest[0].content, "old")
        self.assertEqual([e[0] for e in events], ["refresh"])

    def test_disposal_records_sso_arms(self):
        _, _, _, events_sso = run(make_outer(), sso_temp=True)
        self.assertEqual(events_sso[-2], ("dispose_temp", True))
        _, _, _, events_heap = run(make_outer(), sso_temp=False)
        self.assertEqual(events_heap[-2], ("dispose_temp", False))

    def test_snapshot_string_disposal_recorded(self):
        outer = make_outer()
        outer["inner"]["published"][0x48] = CString("heap-name", sso=False)
        _, _, _, events = run(outer)
        self.assertEqual(events[-1], ("dispose_snapshot_string", False))

    def test_refresh_may_replace_inner(self):
        # The window re-reads [outer+0x128] after the refresh call.
        outer = make_outer()
        fresh = {"published": make_published()}
        fresh["published"][0x48] = CString("fresh-name", sso=True)
        orig_refresh = None

        def refresh(o, f):
            o["inner"] = fresh

        events = []
        dest = [CString("old", sso=True)]
        result = refresh_then_render(
            outer, dest, 1, refresh,
            lambda t, s, h: setattr(t, "content", s[0x20].content),
            lambda i: 0, lambda i: None, events)
        self.assertEqual(result, 1)
        self.assertEqual(dest[0].content, "fresh-name")


if __name__ == "__main__":
    unittest.main()
