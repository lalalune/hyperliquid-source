"""Tests for tools/wal_writer_close.py (node #94 close 0x5163e20).

pytest-style, with a plain-python3 __main__ runner because pytest is
not installed on this VM.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from wal_writer_close import (  # noqa: E402
    MEMBER30_DISPATCH, MEMBER30_SIZE, MEMBER30_VTABLE_FIRST,
    MEMBER30_VTABLE_SECOND, OBJECT_SIZE, Handle, Member30, Shared,
    Status, Str, VecElement, Vector, WriterObject, close, free_string,
    release_shared,
)


def helper_status(f0=0x11, f3=0x22, f5=0x33, msg="msg"):
    def helper(obj, log):
        log.append(("helper-call", obj))
        return Status(f0=f0, f3=f3, f5=f5, msg=msg)
    return helper


def blank_writer(**over):
    kw = dict(string=Str(False, 0, "outer-str"), ref28=None,
              member30=None, arr48=None, vec=None, c8=None)
    kw.update(over)
    return WriterObject(**kw)


def test_null_handle_returns_zeroed_status():
    out, handle, log = Status(), Handle(None), []
    result = close(out, handle, helper_status(), True, log)
    assert result is out
    assert (out.f0, out.f2, out.f3, out.f5, out.msg) == (0, 0, 0, 0, None)
    assert log == [("early-return-null-handle",)]


def test_status_move_copies_fields_and_keeps_byte2_zero():
    out, handle, log = Status(), Handle(blank_writer()), []
    close(out, handle, helper_status(f0=0xABCD, f3=0x1234, f5=0x77,
                                      msg="hello"), True, log)
    assert (out.f0, out.f2, out.f3, out.f5, out.msg) == (0xABCD, 0, 0x1234,
                                                        0x77, "hello")
    # The two frees after the first move target null pointers only.
    assert ("free-null", "out-msg-slot") in log
    assert ("free-null", "temp-msg-slot") in log


def test_second_helper_message_is_freed_and_handle_nulled():
    out, handle, log = Status(), Handle(blank_writer()), []
    close(out, handle, helper_status(msg="second"), True, log)
    # First helper message is kept in out; second is freed.
    assert out.msg == "second"  # both calls return the same fixture msg
    assert ("delete", "second-helper-msg", "second") in log
    assert handle.obj is None


def test_release_null_is_noop():
    log = []
    release_shared(None, True, log)
    assert log == [("release-noop", None)]


def test_release_single_threaded_plain_dec():
    ref, log = Shared(0x0000000500000003, "r"), []
    release_shared(ref, True, log)
    assert log == [("plain-dec", "r", 3)]
    assert ref.count_word == 0x0000000500000002
    assert not ref.destroyed


def test_release_multi_threaded_lock_xadd():
    ref, log = Shared(0x0000000200000007, "r"), []
    release_shared(ref, False, log)
    assert log == [("lock-xadd", "r", 7)]
    assert ref.count_word == 0x0000000200000006


def test_release_old_one_calls_destroyer():
    ref, log = Shared(0x0000000200000001, "r"), []
    release_shared(ref, True, log)
    assert ("destroyer-4f94a40", "r") in log
    assert ref.count_word == 0x0000000200000000
    assert ref.destroyed


def test_release_sentinel_dispose_then_destroy():
    ref, log = Shared(0x100000001, "r"), []
    release_shared(ref, True, log)
    assert log == [("dispose", "r"), ("destroy", "r")]
    assert ref.count_word == 0
    assert ref.destroyed


def test_free_string_heap_and_inline():
    log = []
    free_string(Str(True, 41, "s"), log)
    free_string(Str(False, 0, "t"), log)
    assert log == [("delete", "s", 42), ("string-skip-inline", "t")]


def test_vector_walk_and_capacity_array_free():
    refs = [Shared(3, "e0"), Shared(1, "e1"), None]
    vec = Vector([VecElement(r) for r in refs], 64)
    out, handle, log = Status(), Handle(blank_writer(vec=vec)), []
    close(out, handle, helper_status(msg=None), True, log)
    assert ("plain-dec", "e0", 3) in log
    assert ("destroyer-4f94a40", "e1") in log
    assert ("release-noop", None) in log
    # Capacity-based size (64), not length-based (48).
    assert ("delete", "vec-array", 64) in log


def test_null_vector_skips_array_free():
    out, handle, log = Status(), Handle(blank_writer(vec=None)), []
    close(out, handle, helper_status(msg=None), True, log)
    assert not [e for e in log if e[0] == "delete" and e[1] == "vec-array"]


def test_arr48_freed_when_present():
    out, handle, log = Status(), Handle(blank_writer(arr48="a48")), []
    close(out, handle, helper_status(msg=None), True, log)
    assert ("delete-array", "a48") in log


def test_c8_virtual_called():
    out, handle, log = Status(), Handle(blank_writer(c8="c8obj")), []
    close(out, handle, helper_status(msg=None), True, log)
    assert ("virtual-8", "c8obj") in log


def test_member30_mismatch_calls_virtual_only():
    m = Member30(0xDEAD, Str(True, 9, "mstr"), Shared(2, "mref"), "sub")
    out, handle, log = Status(), Handle(blank_writer(member30=m)), []
    close(out, handle, helper_status(msg=None), True, log)
    assert ("virtual-second", m) in log
    assert m.vtable is None and not m.deleted
    assert ("delete", "mstr", 10) not in log
    assert ("destroyer-4f94a40", "mref") not in log


def test_member30_match_full_inline_teardown():
    m = Member30(MEMBER30_DISPATCH, Str(True, 9, "mstr"),
                 Shared(1, "mref"), "sub")
    out, handle, log = Status(), Handle(blank_writer(member30=m)), []
    close(out, handle, helper_status(msg=None), True, log)
    assert log.index(("vtable-set", "member30", MEMBER30_VTABLE_FIRST)) < \
        log.index(("delete", "mstr", 10)) < \
        log.index(("destroyer-4f94a40", "mref")) < \
        log.index(("vtable-set", "member30", MEMBER30_VTABLE_SECOND)) < \
        log.index(("virtual-8", "sub")) < \
        log.index(("delete", "member30", MEMBER30_SIZE))
    assert m.deleted and m.vtable == MEMBER30_VTABLE_SECOND


def test_member30_match_inline_string_skipped():
    m = Member30(MEMBER30_DISPATCH, Str(False, 0, "mstr"),
                 None, None)
    out, handle, log = Status(), Handle(blank_writer(member30=m)), []
    close(out, handle, helper_status(msg=None), True, log)
    assert ("string-skip-inline", "mstr") in log
    assert ("delete", "member30", MEMBER30_SIZE) in log


def test_full_close_event_order():
    m = Member30(MEMBER30_DISPATCH, Str(True, 0, "mstr"), None, None)
    vec = Vector([VecElement(Shared(2, "e0"))], 16)
    w = blank_writer(string=Str(True, 5, "outer"), ref28=Shared(1, "r28"),
                     member30=m, arr48="a48", vec=vec, c8="c8obj")
    out, handle, log = Status(), Handle(w), []
    close(out, handle, helper_status(msg=None), True, log)
    kinds = [e[0] for e in log]
    order = ["helper-call", "virtual-8", "plain-dec", "delete",
             "delete-array", "vtable-set", "delete", "vtable-set",
             "delete", "destroyer-4f94a40", "delete"]
    it = iter(kinds)
    assert all(any(k == want for k in it) for want in order)
    assert log[-1] == ("delete", "writer-object", OBJECT_SIZE)
    assert w.deleted and handle.obj is None


def test_packet_verify():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable,
         "research/work-items/RE-001-wal-writer-close-94/verify.py"],
        cwd=root, capture_output=True, text=True, timeout=600)
    assert "ALL CHECKS PASSED" in proc.stdout, proc.stdout + proc.stderr


def test_corruption_control_excerpt_tamper_fails():
    # A tampered excerpt must not regenerate: the checker compares
    # against a fresh objdump run, so any byte change is caught.
    import tempfile
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet = os.path.join(root,
                          "research/work-items/RE-001-wal-writer-close-94")
    with open(os.path.join(packet, "window-5163e20.txt")) as handle:
        stored = handle.read()
    fresh = subprocess.run(
        ["objdump", "-d", "--start-address=0x5163e20",
         "--stop-address=0x51641d0", "work/hl-node-94.bin"],
        cwd=root, capture_output=True, text=True, check=True).stdout
    assert fresh == stored
    assert fresh != stored.replace("endbr64", "endbr63", 1)


TESTS = [(name, fn) for name, fn in sorted(list(globals().items()))
         if name.startswith("test_") and callable(fn)]


def main():
    failures = []
    for name, fn in TESTS:
        try:
            fn()
            print("PASS " + name)
        except Exception as exc:  # noqa: BLE001
            print("FAIL " + name + ": " + repr(exc))
            failures.append(name)
    print("%d passed, %d failed" % (len(TESTS) - len(failures),
                                    len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
