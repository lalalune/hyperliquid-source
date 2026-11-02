"""Tests for RE-001 node #94 global member replace (0x5169da0).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_global_member_replace.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from global_member_replace import (
    SENTINEL,
    VT_00,
    VT_38,
    VT_40,
    VT_CLEANUP,
    A58Object,
    Host,
    Hook,
    Member,
    Node60,
    Node80,
    NodeB0,
    VecElem,
    Wrapper,
    build_member,
    destroy_old,
    replace,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def make_host(**kw):
    kw.setdefault("a58", A58Object("v90-result"))
    kw.setdefault("c58", "c58-val")
    kw.setdefault("f10", "f10-val")
    kw.setdefault("b31", 0xAB)
    kw.setdefault("f6c", 0x12345678)
    kw.setdefault("f60", "f60-val")
    return Host(**kw)


def test_guard_noop():
    host = make_host(a60=1, ce0=Wrapper())
    member, wrapper, trace = replace(host, Hook(fn=lambda a, b, c: None))
    check(member is None and wrapper is None, "guard must build nothing")
    check(trace == ["guard_noop"], "guard must trace only the no-op")
    check(host.ce0 is not None and host.ce0 is not wrapper,
          "guard must leave the old wrapper installed")


def test_member_field_installs():
    host = make_host()
    m = build_member(host)
    check(m.vt00 == VT_00 and m.vt38 == VT_38 and m.vt40 == VT_40,
          "vtable address points must match the lea targets")
    check(m.f28 == 0, "+0x28 stays 0: no probe gate in this function")
    check(m.f30 == "c58-val", "+0x30 must be host +0xc58")
    check(m.f48 == "f10-val", "+0x48 must be host +0x10")
    check(m.f50 == "v90-result",
          "+0x50 must come from the host +0xa58 +0x90 virtual")
    check(m.f58 == 0, "+0x58 is 0 here, unlike #2011 which seeds 0x100")
    check(m.f5a == (0xAB ^ 1) & 0xFF, "+0x5a must be host +0x31 XOR 1")
    check(m.f60 == 0x12345678, "+0x60 must be host +0x6c zero-extended")
    check(m.f68 == 0 and m.f6c == 0 and m.f70 == 0,
          "+0x68/+0x6c/+0x70 must be zero")
    check(m.f78 == "f60-val", "+0x78 must be host +0x60")


def test_hook_called_with_field38_and_code3():
    calls = []
    host = make_host()
    member, wrapper, trace = replace(
        host, Hook(field38="hook-obj", fn=lambda a, b, c: calls.append((a, b, c))))
    check(calls == [("hook-obj", "hook-obj", 3)],
          "hook must be called with (field38, field38, 3)")
    check("hook_called" in trace, "trace must record the hook call")
    check(trace.index("member_built") < trace.index("hook_called") <
          trace.index("wrapper_built"), "hook runs between build and wrap")


def test_hook_skipped_when_unset():
    host = make_host()
    member, wrapper, trace = replace(host, Hook(field38="x", fn=None))
    check("hook_skipped" in trace, "null hook must be skipped")
    check(member.released, "member construction reference must be released")
    check(host.ce0 is wrapper, "new wrapper must be installed at +0xce0")


def test_swap_with_no_old_wrapper():
    host = make_host(ce0=None)
    member, wrapper, trace = replace(host)
    check(trace[-2:] == ["swapped", "old_none"],
          "null old wrapper must take the fast return path")
    check(host.ce0 is wrapper, "wrapper must be installed even with no old")


def test_old_destruction_common_tail_order():
    old = Wrapper()
    old.vec = None
    old.list80 = SENTINEL
    old.list60 = Node60("arg18-a", Node60("arg18-b"))
    old.s30 = ("p30", "e30")
    old.s18 = None
    old.s00 = ("p00", "e00")
    trace = []
    destroy_old(old, trace)
    check(trace == ["drain_98", "list60_node_serviced",
                    "list60_node_serviced", "string_freed", "string_freed",
                    "wrapper_freed"],
          "common tail order must be drain, +0x80 list, +0x60 list, "
          "strings +0x30/+0x18/+0x00, wrapper free; got %r" % (trace,))
    check(trace.count("string_freed") == 2, "null +0x18 string must be skipped")


def test_old_destruction_b8_path():
    calls = []
    old = Wrapper()
    old.b8 = 1
    old.vec = [VecElem(("k1", 1)), VecElem(("k2", 2))]
    old.cb98 = lambda a0, a8: calls.append((a0, a8))
    old.cb_a0, old.cb_a8 = "a0-val", "a8-val"
    old.list_b0 = NodeB0(lambda a, b: calls.append(("b0", a, b)), "x", "y")
    old.list80 = Node80(string=("hp", 41), nxt=SENTINEL)
    old.list60 = None
    trace = []
    destroy_old(old, trace)
    check(old.b8 == 0, "+0xb8 must be cleared first")
    check(old.vec[0].released and old.vec[1].released,
          "every +0xc0 element must be released via its +0x8 field")
    check(calls[0] == ("a0-val", "a8-val"),
          "+0x98 callback must get (old +0xa0, old +0xa8)")
    check(("b0", "x", "y") in calls, "+0xb0 node fn must be called")
    check(old.cb98 is None and old.list_b0 is None,
          "+0x98/+0xb0 must be zeroed after the b8 teardown")
    check(trace.index("b8_cleared") < trace.index("array_reordered") <
          trace.index("element_released") < trace.index("callback_called") <
          trace.index("b0_node_freed") < trace.index("cb_fields_zeroed") <
          trace.index("array_buffer_freed") < trace.index("drain_98"),
          "b8 path must precede the common tail; got %r" % (trace,))


def test_old_destruction_b8_zero_skips_teardown():
    old = Wrapper()
    old.b8 = 0
    old.vec = [VecElem(("k", 1))]
    old.cb98 = lambda a0, a8: None
    old.list_b0 = NodeB0(lambda a, b: None, "x", "y")
    old.list80 = SENTINEL
    trace = []
    destroy_old(old, trace)
    check("b8_cleared" not in trace and "callback_called" not in trace
          and "b0_node_freed" not in trace,
          "b8 == 0 must skip the reorder, callback and +0xb0 teardown")
    check(not old.vec[0].released,
          "b8 == 0 must not release +0xc0 elements")
    check("array_buffer_freed" in trace,
          "the +0xc0 buffer itself is still freed in the common tail")


def test_list80_inline_string_skipped():
    old = Wrapper()
    old.list80 = Node80(string=None,
                        nxt=Node80(string=("hp", 9), nxt=SENTINEL))
    trace = []
    destroy_old(old, trace)
    check(trace.count("node80_string_inline_skipped") == 1,
          "inline node string must not be heap-freed")
    check(trace.count("node80_string_freed") == 1,
          "heap node string must be freed")
    check(trace.count("node80_freed") == 2, "both nodes must be freed")


def test_full_replace_trace():
    host = make_host(ce0=Wrapper())
    host.ce0.list80 = SENTINEL
    member, wrapper, trace = replace(host)
    check(trace[:5] == ["member_built", "hook_skipped", "wrapper_built",
                        "member_release", "swapped"],
          "replace order must be build, hook, wrap, release, swap")
    check(trace[-1] == "wrapper_freed", "old wrapper must be freed last")
    check(wrapper is not member, "wrapper and member are distinct objects")


def test_cleanup_vtable_point():
    check(VT_CLEANUP == 0x57593F8,
          "cleanup resets the member vtable to 0x57593e8 + 0x10")


def test_packet_records():
    rec = json.load(open(os.path.join(
        ROOT, "research/work-items/RE-001-global-member-replace-94/"
        "records.json")))
    check(rec["task_id"] == "RE-001", "packet must serve RE-001")
    check(rec["window"]["start"] == "0x5169da0", "window start")
    check(rec["window"]["size_bytes"] == 1337, "window size")
    check(rec["window"]["artifact_sha256"].startswith("3b7179cd"),
          "packet must bind the digest-verified binary")
    check(rec["census"]["direct_calls"] == ["0x50e33db", "0x50ea47b",
                                            "0x513159d"],
          "census must list all three replace call sites")
    check(rec["member"]["f58"] == 0, "packet must pin +0x58 = 0")
    check(rec["member"]["f50_source"] == "host +0xa58 +0x90 virtual",
          "packet must pin the +0x50 source")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("%d tests passed" % len(TESTS))
