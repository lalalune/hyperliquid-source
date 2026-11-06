"""Tests for the node #115 routine 0x5d50400 model (RE-001 shared copy).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which runs every test_* function here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from shared_copy_refcount_50400_115 import (  # noqa: E402
    copy_shared, make_source)

BASE = bytes(range(16))
ALT = bytes(range(0x20, 0x30))


def test_null_selector_copies_base_and_skips_null_control():
    dest, ops = copy_shared(make_source(BASE, ALT, None), None, True)
    assert dest == BASE
    assert ops == [("copy", "base")]


def test_zero_selector_byte_copies_base():
    dest, ops = copy_shared(make_source(BASE, ALT, 0), None, False)
    assert dest == BASE
    assert ops == [("copy", "base")]


def test_nonzero_selector_byte_copies_alt():
    dest, ops = copy_shared(make_source(BASE, ALT, 1), None, True)
    assert dest == ALT
    assert ops == [("copy", "alt")]


def test_flag_nonzero_uses_plain_add():
    control = {"count": 41, "other": 7}
    dest, ops = copy_shared(make_source(BASE, ALT, None), control, True)
    assert dest == BASE
    assert ops == [("copy", "base"), ("add", control, 42)]
    assert control == {"count": 42, "other": 7}


def test_flag_zero_uses_locked_add():
    control = {"count": 41, "other": 7}
    dest, ops = copy_shared(make_source(BASE, ALT, 0), control, False)
    assert ops == [("copy", "base"), ("lock_add", control, 42)]
    assert control["count"] == 42
    assert control["other"] == 7


def test_alt_path_still_increments_control():
    control = {"count": 0}
    dest, ops = copy_shared(make_source(BASE, ALT, 9), control, False)
    assert dest == ALT
    assert ops == [("copy", "alt"), ("lock_add", control, 1)]


def test_alt_path_with_null_control_returns_without_increment():
    dest, ops = copy_shared(make_source(BASE, ALT, 1), None, False)
    assert dest == ALT
    assert ops == [("copy", "alt")]


def test_count_wraps_modulo_2_to_32():
    control = {"count": 0xFFFFFFFF}
    _, ops = copy_shared(make_source(BASE, ALT, None), control, True)
    assert ops[1] == ("add", control, 0)
    assert control["count"] == 0


def test_copy_is_exactly_16_bytes_and_source_unchanged():
    source = make_source(BASE, ALT, 1)
    dest, _ = copy_shared(source, None, True)
    assert len(dest) == 16
    assert dest == ALT
    assert source["base"] == BASE
    assert source["alt"] == ALT


def test_increment_touches_only_the_plus_8_slot():
    control = {"count": 5, "head": 11, "tail": 13}
    copy_shared(make_source(BASE, ALT, None), control, True)
    assert control == {"count": 6, "head": 11, "tail": 13}
