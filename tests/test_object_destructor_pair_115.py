"""Tests for the node #115 destructor pair (tools/object_destructor_pair_115).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (pytest is not installed on this VM).
Each test drives the model end to end: object in, observable event
sequence out.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from object_destructor_pair_115 import (
    ARRAY_OFFSET,
    BASE_DESTRUCTOR,
    DELETING_DESTRUCTOR,
    MEMBER_DESTROY,
    MEMBER_OFFSET,
    OBJECT_SIZE,
    VPTR,
    Object,
    deleting_destroy,
    destroy,
)


def _member_stub(member, events):
    events.append(("member_body", member))


def test_base_installs_vptr():
    obj = Object(array=None, member="m")
    destroy(obj, [], _member_stub)
    assert obj.vptr == 0x64CC5D8 == VPTR


def test_base_calls_member_destroy_once():
    obj = Object(array=None, member="m")
    events = []
    destroy(obj, events, _member_stub)
    assert events[0] == ("member_destroy", MEMBER_DESTROY, MEMBER_OFFSET)
    assert events[1] == ("member_body", "m")
    assert [e for e in events if e[0] == "member_destroy"] == [
        ("member_destroy", 0x605CC30, 0x60)
    ]


def test_base_deletes_non_null_array():
    obj = Object(array="arr", member="m")
    events = []
    destroy(obj, events, _member_stub)
    assert ("delete_array", ARRAY_OFFSET) in events
    assert obj.array_deleted is True
    assert obj.array is None


def test_base_leaves_null_array_alone():
    obj = Object(array=None, member="m")
    events = []
    destroy(obj, events, _member_stub)
    assert not [e for e in events if e[0] == "delete_array"]


def test_base_does_not_free_self():
    obj = Object(array="arr", member="m")
    events = []
    destroy(obj, events, _member_stub)
    assert obj.freed is False
    assert obj.freed_size is None
    assert not [e for e in events if e[0] == "sized_delete_self"]


def test_base_order_member_then_array():
    obj = Object(array="arr", member="m")
    events = []
    destroy(obj, events, _member_stub)
    kinds = [e[0] for e in events]
    assert kinds.index("member_destroy") < kinds.index("delete_array")


def test_deleting_frees_self_with_size():
    obj = Object(array="arr", member="m")
    events = []
    deleting_destroy(obj, events, _member_stub)
    assert obj.freed is True
    assert obj.freed_size == 0x9B0 == OBJECT_SIZE
    assert events[-1] == ("sized_delete_self", 0x9B0)


def test_deleting_order_member_array_self():
    obj = Object(array="arr", member="m")
    events = []
    deleting_destroy(obj, events, _member_stub)
    kinds = [e[0] for e in events]
    assert kinds == [
        "member_destroy",
        "member_body",
        "delete_array",
        "sized_delete_self",
    ]


def test_deleting_with_null_array_still_frees_self():
    obj = Object(array=None, member="m")
    events = []
    deleting_destroy(obj, events, _member_stub)
    assert obj.freed is True
    assert obj.freed_size == 0x9B0
    assert not [e for e in events if e[0] == "delete_array"]


def test_window_addresses():
    assert BASE_DESTRUCTOR == 0x5F10180
    assert DELETING_DESTRUCTOR == 0x5F10D00
    assert MEMBER_DESTROY == 0x605CC30
    assert MEMBER_OFFSET == 0x60
    assert ARRAY_OFFSET == 0x48


def test_returns_none():
    obj = Object(array=None, member="m")
    assert destroy(obj, [], _member_stub) is None
    obj2 = Object(array=None, member="m")
    assert deleting_destroy(obj2, [], _member_stub) is None


def _run():
    tests = [
        test_base_installs_vptr,
        test_base_calls_member_destroy_once,
        test_base_deletes_non_null_array,
        test_base_leaves_null_array_alone,
        test_base_does_not_free_self,
        test_base_order_member_then_array,
        test_deleting_frees_self_with_size,
        test_deleting_order_member_array_self,
        test_deleting_with_null_array_still_frees_self,
        test_window_addresses,
        test_returns_none,
    ]
    for fn in tests:
        fn()
        print("ok", fn.__name__)
    print("%d tests passed" % len(tests))


if __name__ == "__main__":
    _run()
