"""Tests for tools/flanking_getters_115.py.

Run under pytest when available, or directly with plain python3 via
the ``__main__`` runner below (pytest is not installed on this VM).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from flanking_getters_115 import (  # noqa: E402
    virtual_getter, delegating_getter, refresh_field_getter)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-flanking-getters-115"


def test_virtual_getter_low_byte_masking():
    # The binary's movzbl keeps only the low byte of the slot's return.
    for raw, expected in ((0x1AB, 0xAB), (0x100, 0x00), (0x00, 0x00), (0xFF, 0xFF)):
        obj = {"vptr": {"slot478": lambda o, v=raw: v}}
        out = [None]
        assert virtual_getter(out, obj) == 1
        assert out[0] == expected


def test_virtual_getter_passes_obj_to_slot():
    seen = []
    obj = {"vptr": {"slot478": lambda o: seen.append(o) or 7}}
    out = [None]
    assert virtual_getter(out, obj) == 1
    assert seen == [obj]
    assert out[0] == 7


def test_virtual_getter_missing_vptr_raises():
    out = [None]
    try:
        virtual_getter(out, {})
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing vptr")


def test_delegating_getter_stores_full_target_result():
    outer = {"field788": {"field28": {"tag": "sub"}}}
    seen = []
    target = lambda sub: seen.append(sub) or 0x123456789ABCDEF0
    out = [None]
    assert delegating_getter(outer, out, target) == 1
    assert seen == [{"tag": "sub"}]
    assert out[0] == 0x123456789ABCDEF0


def test_delegating_getter_missing_field_raises():
    out = [None]
    try:
        delegating_getter({"field788": {}}, out, lambda sub: 0)
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing +0x28 field")


def test_refresh_getter_calls_refresh_then_reads_signed_field():
    calls = []
    obj = {"field700": "refresh-arg", "field1440": -42}
    out = [None]
    assert refresh_field_getter(out, obj, lambda arg: calls.append(arg) or 999) == 1
    assert calls == ["refresh-arg"]
    assert out[0] == -42


def test_refresh_getter_signed_boundaries():
    for value in (-2147483648, -1, 0, 2147483647):
        obj = {"field700": None, "field1440": value}
        out = [None]
        assert refresh_field_getter(out, obj, lambda arg: None) == 1
        assert out[0] == value


def test_refresh_getter_missing_field_raises():
    out = [None]
    try:
        refresh_field_getter(out, {"field700": None}, lambda arg: None)
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing +0x1440 field")


def test_packet_records_present():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["artifact_sha256"] == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    for name in ("function_0x5eeb220.txt", "function_0x5eeb3a0.txt",
                 "function_0x5eeb3c0.txt", "function_0x5d8c9c0.txt"):
        assert (PACKET_DIR / name).exists()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print("all %d tests passed" % len(tests))
