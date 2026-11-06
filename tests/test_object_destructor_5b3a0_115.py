"""Tests for tools/object_destructor_5b3a0_115.py.

Each test drives the model end to end: holder state in, ordered
observable-effect trace out. Pytest is not installed on this VM,
so the packet's verify.py invokes these functions directly.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from object_destructor_5b3a0_115 import (
    HELPER_RELEASE,
    MEMBER_CALL,
    PLT_DELETE,
    PLT_MEMSET,
    SUB_CLEAR,
    Holder,
    destruct,
)


def test_empty_holder_buffer_phase_still_runs():
    # Null members, empty list, null buffer begin with count 0:
    # the buffer phase still runs (memset with size 0, zeroing,
    # and the delete with size 0 since null != inline), the
    # sub-clear call still runs, and an inline sub-buffer
    # (begin == holder + 0x88) takes the plain return.
    holder = Holder(sub_buf_begin=0x1088)
    trace = destruct(holder, inline_base=0x1000)
    assert trace == [
        ("memset", PLT_MEMSET, None, 0),
        ("zero", "+0xf0"),
        ("zero", "+0xe8"),
        ("free_buffer", PLT_DELETE, None, 0),
        ("call", SUB_CLEAR, "+0x58"),
    ]


def test_full_holder_phase_order():
    holder = Holder(
        member_160="m160",
        member_110=True,
        nodes=["n1", "n2"],
        buf_begin=0x5000,
        buf_count=3,
        member_d0="d0",
        member_c0="c0",
        member_b0="b0",
        sub_buf_begin=0x9000,
        sub_buf_count=2,
    )
    trace = destruct(holder, inline_base=0x1000)
    kinds = [t[0] for t in trace]
    assert kinds == [
        "release", "call",
        "free_node", "free_node",
        "memset", "zero", "zero", "free_buffer",
        "release", "release", "release",
        "call", "free_buffer_tail",
    ]
    assert trace[0] == ("release", HELPER_RELEASE, "+0x160")
    assert trace[1] == ("call", MEMBER_CALL, "+0x110")
    assert trace[4] == ("memset", PLT_MEMSET, 0x5000, 24)
    assert trace[7] == ("free_buffer", PLT_DELETE, 0x5000, 24)
    assert trace[8] == ("release", HELPER_RELEASE, "+0xd0")
    assert trace[11] == ("call", SUB_CLEAR, "+0x58")
    assert trace[12] == ("free_buffer_tail", PLT_DELETE, 0x9000, 16)


def test_inline_main_buffer_is_memset_but_not_freed():
    # begin == holder + 0x108: memset and zeroing still run,
    # but the buffer free is skipped.
    holder = Holder(buf_begin=0x1108, buf_count=1,
                    sub_buf_begin=0x1088)
    trace = destruct(holder, inline_base=0x1000)
    assert ("memset", PLT_MEMSET, 0x1108, 8) in trace
    assert not any(t[0] == "free_buffer" for t in trace)


def test_null_members_skipped_but_list_still_freed():
    holder = Holder(nodes=["n1"], sub_buf_begin=0x1088)
    trace = destruct(holder, inline_base=0x1000)
    assert trace == [
        ("free_node", PLT_DELETE, 0x18, "n1"),
        ("memset", PLT_MEMSET, None, 0),
        ("zero", "+0xf0"),
        ("zero", "+0xe8"),
        ("free_buffer", PLT_DELETE, None, 0),
        ("call", SUB_CLEAR, "+0x58"),
    ]


def test_null_sub_buffer_begin_still_tail_freed_with_size():
    # A null begin that is not the inline address still reaches
    # the tail jump with size count * 8 (count 0 here).
    holder = Holder(sub_buf_begin=None, sub_buf_count=0)
    trace = destruct(holder, inline_base=0x1000)
    assert trace[-1] == ("free_buffer_tail", PLT_DELETE, None, 0)


def test_release_order_d0_c0_b0():
    holder = Holder(member_d0="d", member_b0="b",
                    sub_buf_begin=0x1088)
    trace = destruct(holder, inline_base=0x1000)
    releases = [t for t in trace if t[0] == "release"]
    assert releases == [("release", HELPER_RELEASE, "+0xd0"),
                        ("release", HELPER_RELEASE, "+0xb0")]
