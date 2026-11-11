"""Tests for tools/lazy_cache_adapter_548a0_115.py (RE-001, node #115).

Run without pytest (not installed on this VM) by importing the module
and calling every test_* function; verify.py does exactly that.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from lazy_cache_adapter_548a0_115 import (  # noqa: E402
    CacheSlot, Holder, Out, adapter, build_record, cache_ensure, cleanup,
    getter)


def _fresh_holder():
    return Holder(g540=0x1122334455667788)


def _x():
    return bytes(range(64))


def test_getter_returns_holder_field():
    holder = _fresh_holder()
    assert getter(holder) == 0x1122334455667788


def test_cached_path_writes_status_and_skips_work():
    holder = _fresh_holder()
    slot = holder.cache
    slot.record = "already-cached"
    slot.present = 1
    out = Out("o")
    calls = []
    events = []
    result = adapter(out, holder, _x(), [7], lambda o, r: calls.append(r),
                     events)
    assert result is out
    assert out.writes == {0x00: ("dword", 11), 0x04: ("word", 0),
                          0x08: ("qword", 0)}
    assert calls == []
    assert events == [("acquire",), ("release",)]
    assert slot.key == bytearray(25)


def test_fresh_path_builds_installs_and_notifies():
    holder = _fresh_holder()
    out = Out("o")
    x = _x()
    y = [0xDEADBEEF]
    calls = []
    events = []
    result = adapter(out, holder, x, y,
                     lambda o, r: calls.append((o, r)), events)
    assert result is out
    assert holder.cache.key == x[:25]
    record = holder.cache.record
    assert record.g == 0x1122334455667788
    assert record.blob == x[:32]
    assert record.moved == 0xDEADBEEF
    assert y == [0]
    assert holder.cache.present == 1
    assert len(calls) == 1 and calls[0][0] is out and calls[0][1] is record
    kinds = [e[0] for e in events]
    assert kinds == ["acquire", "alloc", "build_record", "notifier",
                     "release"]


def test_fresh_then_cached_second_call_is_cached():
    holder = _fresh_holder()
    out = Out("o")
    x = _x()
    calls = []
    adapter(out, holder, x, [5], lambda o, r: calls.append(r), [])
    record = holder.cache.record
    out2 = Out("o2")
    events = []
    adapter(out2, holder, x, [9], lambda o, r: calls.append(r), events)
    assert holder.cache.record is record
    assert len(calls) == 1
    assert events == [("acquire",), ("release",)]
    assert out2.writes[0x00] == ("dword", 11)


def test_builder_unit_fields_and_y_consumed():
    y = [42]
    events = []
    record = build_record(7, bytes(range(40)), y, events)
    assert record.g == 7
    assert record.blob == bytes(range(32))
    assert record.moved == 42
    assert y == [0]
    assert events[0][0] == "build_record"


def test_key_and_blob_share_first_25_bytes():
    holder = _fresh_holder()
    x = bytes(range(64, 128))
    adapter(Out("o"), holder, x, [1], None, [])
    assert bytes(holder.cache.key) == holder.cache.record.blob[:25]


def test_adapter_returns_first_argument_on_fresh_path():
    holder = _fresh_holder()
    out = Out("o")
    assert adapter(out, holder, _x(), [3], None, []) is out


def test_cleanup_after_allocation_frees_then_releases():
    events = []
    cleanup("record", events)
    assert events == [("free_record", 0x30), ("release",), ("resume",)]


def test_cleanup_before_allocation_only_releases():
    events = []
    cleanup(None, events)
    assert events == [("release",), ("resume",)]


def test_null_inputs_raise():
    try:
        adapter(Out("o"), None, _x(), [1], None, [])
    except ValueError:
        pass
    else:
        raise AssertionError("null holder must raise")
    try:
        cache_ensure(None, CacheSlot(), 0, _x(), [1], None, [])
    except ValueError:
        pass
    else:
        raise AssertionError("null out must raise")
