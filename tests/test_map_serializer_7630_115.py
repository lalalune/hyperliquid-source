"""Tests for the node #115 options-map serializer model (0x6097630)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from map_serializer_7630_115 import (
    BLOCK_A,
    BLOCK_B,
    BLOCK_C,
    SKIP,
    dispatch_full,
    emit_entry,
    serialize_map,
)


def entry(**kw):
    base = {
        "verification": 0,
        "flags": 0,
        "type": 1,
        "name": "opt",
        "value": "v",
        "serialize_error": 0,
        "rec_d9_bit0": False,
        "rec_d9_bit7": False,
    }
    base.update(kw)
    return base


def test_dispatch_block_a():
    # ConfigOptions+0x04 == 0 takes block A for every surviving entry.
    assert dispatch_full(0, 0, 1, 0, 0, False, False)[0] == BLOCK_A
    assert dispatch_full(0, 0, 21, 0, 0, True, True)[0] == BLOCK_A
    assert dispatch_full(3, 0, 22, 0, 99, False, False)[0] == BLOCK_A


def test_dispatch_skip_verification():
    # Verification 4 and 5 are both dropped at the map level.
    assert dispatch_full(4, 0, 1, 0, 0, False, False)[0] == SKIP
    assert dispatch_full(5, 0, 1, 0, 0, False, False)[0] == SKIP
    assert dispatch_full(5, 0, 21, 1, 2, True, False)[0] == SKIP


def test_dispatch_skip_flags():
    assert dispatch_full(0, 0x2000, 1, 0, 0, False, False)[0] == SKIP
    assert dispatch_full(0, 0x2001, 1, 0, 0, False, False)[0] == SKIP
    # Other flag bits do not skip.
    assert dispatch_full(0, 0x1000, 1, 0, 0, False, False)[0] == BLOCK_A


def test_dispatch_block_b():
    # +0x04 != 0 and record+0xd9 bit 0 set -> block B (ConfigOptions copy).
    assert dispatch_full(0, 0, 1, 1, 0, True, False)[0] == BLOCK_B
    assert dispatch_full(0, 0, 22, 7, 2, True, True)[0] == BLOCK_B


def test_dispatch_block_c():
    # +0x04 != 0, bit 0 clear, type 21/22 -> block C.
    assert dispatch_full(0, 0, 21, 1, 0, False, False)[0] == BLOCK_C
    assert dispatch_full(0, 0, 22, 1, 2, False, True)[0] == BLOCK_C
    # +0x28 == 2 also admits block C when bit 7 is set.
    assert dispatch_full(0, 0, 21, 1, 2, False, True)[0] == BLOCK_C
    # +0x28 != 2 with bit 7 set skips.
    assert dispatch_full(0, 0, 21, 1, 0, False, True)[0] == SKIP


def test_dispatch_skip_other_types():
    # +0x04 != 0, bit 0 clear, type outside {21, 22} -> skip.
    assert dispatch_full(0, 0, 1, 1, 0, False, False)[0] == SKIP
    assert dispatch_full(0, 0, 20, 1, 2, False, False)[0] == SKIP
    assert dispatch_full(0, 0, 23, 1, 2, False, False)[0] == SKIP


def test_emit_entry():
    assert emit_entry("", "opt", "v", "; ") == "opt=v; "
    assert emit_entry("pre.", "opt", "v", "; ") == "pre.opt=v; "
    # Empty value emits nothing.
    assert emit_entry("", "opt", "", "; ") == ""
    assert emit_entry("pre.", "opt", "", "; ") == ""


def test_serialize_map_empty_range():
    assert serialize_map([]) == (0, "")


def test_serialize_map_basic():
    code, out = serialize_map([
        entry(name="a", value="1"),
        entry(name="b", value="2"),
    ])
    assert code == 0
    assert out == "a=1; b=2; "


def test_serialize_map_skips():
    code, out = serialize_map([
        entry(name="a", value="1"),
        entry(name="gone4", value="x", verification=4),
        entry(name="gone5", value="x", verification=5),
        entry(name="goneflag", value="x", flags=0x2000),
        entry(name="empty", value=""),
        entry(name="b", value="2"),
    ])
    assert code == 0
    assert out == "a=1; b=2; "


def test_serialize_map_error_propagates_and_stops():
    code, out = serialize_map([
        entry(name="a", value="1"),
        entry(name="bad", value="x", serialize_error=3),
        entry(name="c", value="3"),
    ])
    assert code == 3
    assert out == "a=1; "


def test_serialize_map_block_b_and_c_paths():
    # +0x04 != 0: bit0 entries go block B, type-21/22 entries block C,
    # other types are skipped; all three emit the same text shape.
    code, out = serialize_map([
        entry(name="b1", value="1", rec_d9_bit0=True),
        entry(name="c1", value="2", type=21),
        entry(name="skip", value="9", type=3),
        entry(name="c2", value="3", type=22),
    ], opts_plus04=1, opts_plus28=2)
    assert code == 0
    assert out == "b1=1; c1=2; c2=3; "


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for t in tests:
        t()
    print(f"{len(tests)} tests passed")
