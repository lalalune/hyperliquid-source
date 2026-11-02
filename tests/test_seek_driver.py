"""Tests for RE-001 seek driver with its context build, +0x60 dispatch
and inline loop (0x516c7e0) and the generic loop (0x51651e0).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_seek_driver.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from seek_driver import (
    KNOWN_98,
    KNOWN_LOOP,
    SENTINEL,
    A50Object,
    Host,
    Iterator,
    SliceStruct,
    acquire_iterator,
    build_context,
    drive,
    run_loop,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def make_host(slot60, slot90, slot98):
    return Host(f50=0x1111, f58=0x2222, f60=0x3333, b31=0xAB,
                f68=0xCD, f6c=0x12345678, c70=0x4444,
                a50=A50Object(slot60, slot90, slot98))


def test_context_layout():
    host = make_host(KNOWN_LOOP, None, KNOWN_98)
    sl = SliceStruct(0x10, 0x20, 0x30)
    stack = ["s0", "s1", "s2", "s3", "s4", "out", "s6", "s7"]
    ctx = build_context(host, sl, "rdx", 0xEF, "r8", "r9", stack)
    check(ctx[0x00] == "s3", "ctx+0x00 must be stack3")
    check(ctx[0x08] is sl, "ctx+0x08 must be the slice struct")
    check(ctx[0x10] == "s6" and ctx[0x18] == "s7", "stack6/7 slots")
    check(ctx[0x20] == "s0" and ctx[0x28] == "s1", "stack0/1 slots")
    check(ctx[0x30] == SENTINEL, "result slot starts at the sentinel")
    check(ctx[0x38] == ("s2", 0x2222), "pair (stack2, host+0x58)")
    check(ctx[0x48] == "s4", "ctx+0x48 must be stack4")
    check(ctx[0x50] == "rdx", "ctx+0x50 must be rdx")
    check(ctx[0x58] == (host, 0x3333), "pair (host, host+0x60)")
    check(ctx[0x68] == 0x1111, "ctx+0x68 must be host+0x50")
    check(ctx[0x70] == 0xEFAB, "word: low host+0x31, high cl")
    check(ctx[0x78] == (0x4444, "r8"), "pair (host+0xc70, r8)")
    check(ctx[0x88] == "r9", "ctx+0x88 must be r9")
    check(ctx[0x90] == 0xCD, "ctx+0x90 must be host+0x68 byte")
    check(ctx[0x98] == 0x12345678, "ctx+0x98 must be host+0x6c")


def test_target_slice():
    sl = SliceStruct("first", 100, 130)
    check(sl.target() == (100, 30), "target is (start, end-start)")


def test_iterator_dispatch_known_98():
    seen = []
    it = Iterator([], [])
    obj = A50Object(KNOWN_LOOP, lambda o: seen.append("v90") or it,
                    KNOWN_98)
    check(acquire_iterator(obj) is it, "known +0x98 must use +0x90")
    check(seen == ["v90"], "+0x90 virtual must be called")


def test_iterator_dispatch_direct_98():
    it = Iterator([], [])
    obj = A50Object(KNOWN_LOOP, None, lambda o: it)
    check(acquire_iterator(obj) is it, "unknown +0x98 calls it directly")


def _drive_with(it, callback, slot98=KNOWN_98):
    host = make_host(KNOWN_LOOP, lambda o: it, slot98)
    sl = SliceStruct("first", 100, 130)
    stack = ["s0", "s1", "s2", "s3", "s4", "out", "s6", "s7"]
    return drive(host, sl, "rdx", 0xEF, "r8", "r9", stack, callback), it


def test_known_loop_full_iteration():
    calls = []
    it = Iterator([True, True, False], ["v1", "v2"])
    out, it = _drive_with(it, lambda ctx, v: calls.append(v) or True)
    check(it.seek_calls == [((100, 30), "first")],
          "seek30 must get target slice and first field")
    check(calls == ["v1", "v2"], "callback must see slot18 values in order")
    check(it.next_calls == 2, "advance once per true callback")
    check(it.slot18_calls == 2, "slot18 once per iteration")
    check(out == SENTINEL, "untouched result slot stays the sentinel")


def test_callback_false_stops_without_advance():
    it = Iterator([True, True], ["v1"])
    out, it = _drive_with(it, lambda ctx, v: False)
    check(it.next_calls == 0, "false callback must not advance")
    check(it.slot18_calls == 1, "callback checked once before stopping")


def test_valid_false_initially_calls_nothing():
    it = Iterator([False], ["v1"])
    out, it = _drive_with(it, lambda ctx, v: True)
    check(it.slot18_calls == 0, "invalid iterator never reaches callback")
    check(it.next_calls == 0, "invalid iterator never advances")
    check(it.seek_calls, "initial seek still runs")


def test_callback_result_slot_flows_to_out():
    def cb(ctx, v):
        ctx[0x30] = 0xABCDEF
        return True
    it = Iterator([True, False], ["v1"])
    out, _ = _drive_with(it, cb)
    check(out == 0xABCDEF, "out must be the callback-written +0x30")


def test_direct_arm_delegates_then_writes_out():
    seen = {}

    def delegate(obj, sl, ctx, cb):
        seen["args"] = (obj, sl, ctx, cb)
        ctx[0x30] = 0x777

    host = make_host(delegate, None, KNOWN_98)
    sl = SliceStruct("first", 100, 130)
    stack = ["s0", "s1", "s2", "s3", "s4", "out", "s6", "s7"]
    out = drive(host, sl, "rdx", 0xEF, "r8", "r9", stack,
                lambda ctx, v: True)
    check(seen["args"][0] is host.a50, "delegate gets the a50 object")
    check(seen["args"][1] is sl, "delegate gets the slice struct")
    check(seen["args"][2][0x30] == 0x777, "delegate sees built context")
    check(out == 0x777, "direct arm still exits through the out write")


def test_generic_loop_mirrors_driver_loop():
    calls = []
    it = Iterator([True, False], ["v1"])
    sl = SliceStruct("first", 5, 9)
    run_loop(it, sl, lambda ctx, v: calls.append((ctx, v)) or True,
             "ctx")
    check(it.seek_calls == [((5, 4), "first")], "generic seek args")
    check(calls == [("ctx", "v1")], "generic callback gets context first")
    check(it.next_calls == 1, "generic loop advances on true callback")


def test_packet_records():
    rec = json.load(open(os.path.join(
        ROOT, "research/work-items/RE-001-seek-driver-94/records.json")))
    check(rec["task_id"] == "RE-001", "packet must serve RE-001")
    check(rec["window"]["start"] == "0x516c7e0", "driver window start")
    check(rec["window"]["size_bytes"] == 503, "driver window size")
    check(rec["window"]["artifact_sha256"].startswith("3b7179cd"),
          "packet must bind the digest-verified binary")
    check(rec["census"]["direct_calls"] == ["0x516cf2c", "0x516d758"],
          "census must list both driver call sites")
    check(rec["dispatch"]["slot60_known"] == "0x51651e0",
          "dispatch must name the known loop")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("%d tests passed" % len(TESTS))
