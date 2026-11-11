"""Tests for tools/twin_guarded_query_553c0_55520_115.py (RE-001).

The inner query is a test input in every case: the model pins the twin
wrapper only, never the inner query's computation. pytest is not
installed on this VM, so these functions are also invocable directly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from twin_guarded_query_553c0_55520_115 import (  # noqa: E402
    Holder, Triple, guarded_query, probe_call)


def _inner(code=11, tag=5, ptr="new-ptr"):
    calls = []

    def run(flag, key_struct, caller_arg, key16, pair16):
        calls.append((flag, key_struct, caller_arg, key16, pair16))
        return Triple(code, tag, ptr)

    run.calls = calls
    return run


def test_flag_zero_returns_zeroed_output_without_mutex_or_inner():
    holder = Holder(flag=None)
    out = Triple(code=7, tag=3, ptr="stale")
    inner = _inner()
    result = guarded_query(holder, out, inner, "ks", "ca", "k16", "p16")
    assert result is out
    assert (out.code, out.tag, out.ptr) == (0, 0, None)
    assert holder.ops == [] and inner.calls == [] and holder.freed == []


def test_entry_zeroing_drops_incoming_pointer_without_free():
    holder = Holder(flag=None)
    out = Triple(code=1, tag=1, ptr="stale")
    guarded_query(holder, out, _inner(), "ks", "ca", "k16", "p16")
    assert out.ptr is None and holder.freed == []


def test_happy_path_moves_temp_and_releases_in_order():
    holder = Holder(flag="flag-obj")
    out = Triple()
    inner = _inner(code=11, tag=5, ptr="new-ptr")
    guarded_query(holder, out, inner, "ks", "ca", "k16", "p16")
    assert (out.code, out.tag, out.ptr) == (11, 5, "new-ptr")
    assert holder.ops == ["acquire", "inner", "release"]
    assert holder.locked is False
    assert holder.freed == []  # the twin's conditional free never fires
    assert inner.calls == [("flag-obj", "ks", "ca", "k16", "p16")]


def test_temp_slots_cleared_after_move():
    holder = Holder(flag="f")
    temp_holder = []

    def inner(flag, ks, ca, k16, p16):
        temp = Triple(code=2, tag=4, ptr="p")
        temp_holder.append(temp)
        return temp

    out = Triple()
    guarded_query(holder, out, inner, "ks", "ca", "k16", "p16")
    assert (temp_holder[0].code, temp_holder[0].tag, temp_holder[0].ptr) == (0, 0, None)
    assert out.ptr == "p"


def test_reread_null_releases_without_inner_call():
    holder = Holder(flag="f", flag_at_reread=None)
    out = Triple()
    inner = _inner()
    guarded_query(holder, out, inner, "ks", "ca", "k16", "p16")
    assert (out.code, out.tag, out.ptr) == (0, 0, None)
    assert holder.ops == ["acquire", "release"]
    assert inner.calls == [] and holder.locked is False


def test_inner_exception_releases_and_rethrows_with_zeroed_output():
    holder = Holder(flag="f")
    out = Triple()

    def boom(flag, ks, ca, k16, p16):
        raise RuntimeError("inner failed")

    try:
        guarded_query(holder, out, boom, "ks", "ca", "k16", "p16")
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the inner exception to propagate")
    assert (out.code, out.tag, out.ptr) == (0, 0, None)
    assert holder.ops == ["acquire", "release"]
    assert holder.locked is False


def test_both_twins_share_wrapper_behavior():
    for inner_ptr in ("ptr-a", "ptr-b"):
        holder = Holder(flag="f")
        out = Triple()
        guarded_query(holder, out, _inner(ptr=inner_ptr), "ks", "ca", "k16", "p16")
        assert out.ptr == inner_ptr and holder.ops == ["acquire", "inner", "release"]


def test_scalar_fields_move_exactly_including_u16_boundary():
    holder = Holder(flag="f")
    out = Triple()
    guarded_query(holder, out, _inner(code=-1, tag=0xFFFF, ptr=None),
                  "ks", "ca", "k16", "p16")
    assert (out.code, out.tag, out.ptr) == (-1, 0xFFFF, None)


def test_probe_call_frees_returned_pointer():
    holder = Holder(flag="f")
    out = Triple()
    freed = probe_call(holder, out, _inner(ptr="ret-ptr"), "ks", "ca", "k16", "p16")
    assert freed == "ret-ptr" and holder.freed == ["ret-ptr"]


def test_probe_call_frees_nothing_on_flag_zero():
    holder = Holder(flag=None)
    out = Triple()
    assert probe_call(holder, out, _inner(), "ks", "ca", "k16", "p16") is None
    assert holder.freed == []


def test_probe_call_frees_nothing_when_inner_ptr_null():
    holder = Holder(flag="f")
    out = Triple()
    assert probe_call(holder, out, _inner(ptr=None), "ks", "ca", "k16", "p16") is None
    assert holder.freed == []


def test_output_pointer_identity_is_move_not_copy():
    holder = Holder(flag="f")
    token = object()
    out = Triple()
    guarded_query(holder, out, _inner(ptr=token), "ks", "ca", "k16", "p16")
    assert out.ptr is token


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} model tests pass")
