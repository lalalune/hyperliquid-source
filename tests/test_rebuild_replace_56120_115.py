"""Tests for tools/rebuild_replace_56120_115.py (RE-001, node #115).

Run without pytest (not installed on this VM) by importing the module
and calling every test_* function; verify.py does exactly that.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from rebuild_replace_56120_115 import (
    Dest, NewObject, Ref, Singleton, apply, cleanup_delete, cleanup_full,
    cleanup_resume,
)


def test_full_apply_refcounts_and_install():
    a, b = Ref("A", owners=0), Ref("B", owners=0)
    old = NewObject()
    dest = Dest(owner=old)
    events = []
    new = apply(dest, ("a0", a), ("b0", b), Singleton(), events.append)
    assert a.owners == 2, a.owners  # dest copy + subobject copy
    assert b.owners == 2, b.owners  # dest copy + new-object copy
    assert dest.view is new.sub and dest.owner is new
    assert new.sub.table == 0x64D08A8 and new.table == 0x64C9830
    assert new.packed == 0x100000001 and new.singleton_link == "record_a+0x10"
    assert old.owners == 0 and old.destroyed is True
    assert ("release", "installed-object") in events
    assert ("destroy", "installed-object") in events


def test_old_owner_release_event():
    old_ref = Ref("old-owner", owners=1)
    dest = Dest(owner=None)
    # Simulate the previous owner as a refcounted target released by helper.
    dest.owner = old_ref
    events = []
    apply(dest, (None, None), (None, None), Singleton(), events.append)
    assert ("release", "old-owner") in events
    assert ("destroy", "old-owner") in events


def test_null_refs_and_null_owner():
    dest = Dest()
    events = []
    new = apply(dest, ("a0", None), ("b0", None), Singleton(), events.append)
    assert events.count(("incref",)) == 0
    assert ("return_no_release",) in events
    assert dest.owner is new and dest.view is new.sub


def test_singleton_lazy_init():
    s = Singleton()
    events = []
    first = s.get(events)
    second = s.get(events)
    assert first is second and s.builds == 1
    assert events == [("singleton_build",)]


def test_subobject_vptr_upgrade():
    dest = Dest()
    events = []
    new = apply(dest, (None, None), (None, None), Singleton(), events.append)
    assert ("sub_init_string_call",) in events
    assert new.sub.table == 0x64D08A8  # middle during init, derived after


def test_cleanup_full_event_order():
    a, b = Ref("A", owners=2), Ref("B", owners=2)
    dest = Dest(a1=a, b1=b, owner=Ref("O", owners=1))
    new = NewObject()
    new.sub.a1 = a
    new.b1 = b
    events = []
    cleanup_full(new, dest, events)
    assert events == [("release", "B"), ("release", "A"),
                      ("base_destroy_sub",), ("delete_new", 0x58),
                      ("release", "O"), ("destroy", "O"),
                      ("release", "B"), ("destroy", "B"),
                      ("release", "A"), ("destroy", "A"),
                      ("unwind_resume",)], events


def test_cleanup_delete_and_resume():
    dest = Dest(a1=Ref("A", owners=1), b1=None, owner=None)
    events = []
    cleanup_delete(NewObject(), dest, events)
    assert events == [("delete_new", 0x58), ("release", "A"), ("destroy", "A"),
                      ("unwind_resume",)], events
    events = []
    cleanup_resume(dest, events)
    assert events == [("release", "A"), ("unwind_resume",)], events


def test_dest_pairs_copied_verbatim():
    dest = Dest()
    apply(dest, ("x", None), ("y", None), Singleton(), lambda e: None)
    assert (dest.a0, dest.b0) == ("x", "y")
