"""Tests for tools/wal_handle_release.py (node #94 handle release 0x51641d0).

pytest-style, runnable under plain python3 via the __main__ runner
(pytest is not installed on this VM).
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from wal_handle_release import (
    FINALIZE_ERROR_MESSAGE,
    Handle,
    InnerObject,
    Member30,
    Member48,
    Shared,
    Status,
    Str,
    VecElement,
    Vector,
    finalize_helper,
    release,
    release_shared,
)


def make_inner(**kw):
    kw.setdefault("string", Str(True, 10, "inner-str"))
    kw.setdefault("ref28", Shared(3, "ref28"))
    kw.setdefault("member30", None)
    kw.setdefault("arr48", None)
    kw.setdefault("vec", None)
    kw.setdefault("c8", None)
    kw.setdefault("seen_error", False)
    return InnerObject(**kw)


def status_helper_no_msg(inner, log):
    log.append(("status-helper-52b2550", inner))
    return Status(0, 0, None)


def completion_ok(log):
    log.append(("completion-step-52b13f0", 4))
    return Status(0, 0, "completion-msg")


def test_finalize_error_record():
    inner = make_inner(seen_error=True)
    log = []
    st = finalize_helper(inner, completion_ok, log)
    assert st.code == 5 and st.sub == 0
    assert st.msg == FINALIZE_ERROR_MESSAGE
    assert st.msg == "Seen error. Skip writing buffer."
    assert ("finalize-error-record", 5, 0, FINALIZE_ERROR_MESSAGE) in log


def test_finalize_clear_path_calls_completion():
    inner = make_inner(seen_error=False)
    log = []
    st = finalize_helper(inner, completion_ok, log)
    assert st.msg == "completion-msg"
    assert ("finalize-completion-step", 4) in log
    assert ("completion-step-52b13f0", 4) in log


def test_null_inner_still_frees_outer_members():
    # The key control-flow nuance: steps 2-3 run even when *handle is
    # null, then the routine returns without freeing the shell.
    handle = Handle(None, member48=Member48(0x51633E0, "m48-field"),
                    arr50="outer-array")
    log = []
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("vtable-set", "member48", 0x5766018) in log
    assert ("delete", "member48", 0x70) in log
    assert ("delete-array", "outer-array") in log
    assert ("early-return-null-inner",) in log
    assert ("shell-not-freed", 0x58) in log
    assert not any(e[0] == "status-helper-52b2550" for e in log)


def test_full_release_order_end_to_end():
    inner = make_inner(
        vec=Vector([VecElement(Shared(2, "el0")),
                    VecElement(Shared(0x100000001, "el1"))], 64),
        arr48="inner-array",
        c8="c8-obj",
        member30=Member30(0x505D960, Str(False, 0, "m30-str"),
                          Shared(1, "ref40"), "sub30"),
    )
    handle = Handle(inner, member48=Member48(0x51633E0, "m48-field"),
                    arr50="outer-array")
    log = []
    release(handle, status_helper_no_msg, completion_ok, False, log)
    kinds = [e[0] for e in log]
    # Binary order: finalize, member48, outer array, status helper,
    # c8 virtual, vector walk, vector free, inner array, member30,
    # ref28, inner string, inner delete, shell note.
    assert kinds.index("finalize-completion-step") < kinds.index("vtable-set")
    assert kinds.index("delete-array") < kinds.index("status-helper-52b2550")
    assert log.index(("virtual-8", "c8-obj")) < log.index(("delete", "vec-array", 64))
    assert log.index(("delete", "vec-array", 64)) < log.index(("delete", "member30", 112))
    assert ("delete", "inner-object", 0xE0) in log
    assert ("shell-not-freed", 0x58) in log
    assert inner.deleted
    assert handle.member48.deleted
    assert inner.member30.deleted


def test_member48_mismatch_calls_second_virtual():
    handle = Handle(None, member48=Member48(0x999, "m48-field"))
    log = []
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("virtual-second", handle.member48) in log
    assert not handle.member48.deleted
    assert not any(e == ("delete", "member48", 0x70) for e in log)


def test_member30_mismatch_skips_inline_teardown():
    inner = make_inner(member30=Member30(0x999, Str(True, 5, "m30-str"),
                                          Shared(2, "ref40"), "sub30"))
    handle = Handle(inner)
    log = []
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("virtual-second", inner.member30) in log
    assert not inner.member30.deleted
    assert not any(e == ("delete", "member30", 0x70) for e in log)


def test_shared_protocol_sentinel_and_decrement_modes():
    log = []
    s = Shared(0x100000001, "sent")
    release_shared(s, True, log)
    assert s.count_word == 0 and s.destroyed
    assert ("dispose", "sent") in log and ("destroy", "sent") in log
    log = []
    s = Shared(2, "plain")
    release_shared(s, True, log)
    assert ("plain-dec", "plain", 2) in log and s.count_word == 1
    log = []
    s = Shared(2, "atomic")
    release_shared(s, False, log)
    assert ("lock-xadd", "atomic", 2) in log and s.count_word == 1
    log = []
    s = Shared(1, "last")
    release_shared(s, False, log)
    assert ("destroyer-4f94a40", "last") in log and s.destroyed
    log = []
    s = Shared(0x100000002, "weak")
    release_shared(s, True, log)
    assert s.count_word == 0x100000001 and not s.destroyed


def test_shared_null_is_noop():
    log = []
    release_shared(None, True, log)
    assert log == [("release-noop", None)]


def test_string_rules():
    log = []
    inner = make_inner(string=Str(False, 0, "inline-str"))
    handle = Handle(inner)
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("string-skip-inline", "inline-str") in log
    log = []
    inner = make_inner(string=Str(True, 41, "heap-str"))
    handle = Handle(inner)
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("delete", "heap-str", 42) in log


def test_empty_vector_still_frees_storage():
    inner = make_inner(vec=Vector([], 48))
    handle = Handle(inner)
    log = []
    release(handle, status_helper_no_msg, completion_ok, True, log)
    assert ("delete", "vec-array", 48) in log


def test_status_helper_message_freed():
    def helper_with_msg(inner, log):
        log.append(("status-helper-52b2550", inner))
        return Status(0, 0, "helper-msg")

    inner = make_inner(seen_error=True)
    handle = Handle(inner)
    log = []
    release(handle, helper_with_msg, completion_ok, True, log)
    # Finalize message freed first, status-helper message freed later.
    assert ("delete-array", "finalize-msg", FINALIZE_ERROR_MESSAGE) in log
    assert ("delete-array", "status-helper-msg", "helper-msg") in log
    fi = log.index(("delete-array", "finalize-msg", FINALIZE_ERROR_MESSAGE))
    si = log.index(("delete-array", "status-helper-msg", "helper-msg"))
    assert fi < si


def test_packet_checker_passes():
    root = os.path.join(os.path.dirname(__file__), "..")
    packet = os.path.join(root, "research", "work-items",
                          "RE-001-wal-handle-release-94")
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    out = subprocess.run(
        [sys.executable, os.path.join(packet, "verify.py")],
        cwd=root, capture_output=True, text=True, env=env)
    assert "ALL CHECKS PASSED" in out.stdout, out.stdout + out.stderr
    assert out.returncode == 0


def test_corruption_control_wrong_dispatch_changes_outcome():
    # A packet claiming the wrong member dispatch value would route
    # the member through the virtual call instead of the inline
    # teardown; the model distinguishes the two paths.
    m = Member48(0x51633E0, "f")
    log = []
    release(Handle(None, member48=m), status_helper_no_msg,
            completion_ok, True, log)
    assert m.deleted
    m2 = Member48(0x51633E1, "f")
    log = []
    release(Handle(None, member48=m2), status_helper_no_msg,
            completion_ok, True, log)
    assert not m2.deleted


TESTS = [(k, v) for k, v in sorted(globals().items())
         if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print("PASS " + name)
        except Exception as exc:  # noqa: BLE001 - runner reports
            failed += 1
            print("FAIL " + name + ": " + repr(exc))
    print("%d tests, %d failed" % (len(TESTS), failed))
    sys.exit(1 if failed else 0)
