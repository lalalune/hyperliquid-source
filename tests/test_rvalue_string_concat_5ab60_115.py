"""Model tests for node #115 routine 0x5d5ab60 (rvalue string concat)."""
from tools.rvalue_string_concat_5ab60_115 import (
    MAX_SIZE, LengthError, concat, empty_sso, make_string)


def test_empty_plus_empty_is_append_sso():
    result, path, lhs_after, _ = concat(empty_sso(), empty_sso())
    assert path == "append" and result["bytes"] == b"" and result["sso"]


def test_short_plus_short_under_15_is_append_sso_copy():
    lhs = make_string(b"hello")
    rhs = make_string(b" world")
    result, path, lhs_after, _ = concat(lhs, rhs)
    assert path == "append"
    assert result["bytes"] == b"hello world" and result["sso"]
    assert lhs_after["bytes"] == b"hello world"  # SSO lhs keeps its copy


def test_short_plus_short_over_15_is_append_heap_and_lhs_reset():
    lhs = make_string(b"0123456789abcdef")
    rhs = make_string(b"XYZ")
    result, path, lhs_after, _ = concat(lhs, rhs)
    assert path == "append"
    assert result["bytes"] == b"0123456789abcdefXYZ" and not result["sso"]
    assert lhs_after == empty_sso()  # heap lhs stolen, reset to empty SSO


def test_heap_lhs_with_capacity_is_append():
    lhs = make_string(b"ab", capacity=64, sso=False)
    rhs = make_string(b"cd", capacity=64, sso=False)
    result, path, lhs_after, rhs_after = concat(lhs, rhs)
    assert path == "append" and result["bytes"] == b"abcd"
    assert lhs_after == empty_sso() and rhs_after == rhs


def test_heap_lhs_overflow_into_roomy_rhs_is_insert():
    lhs = make_string(b"a" * 20, capacity=20, sso=False)
    rhs = make_string(b"b" * 10, capacity=64, sso=False)
    result, path, lhs_after, rhs_after = concat(lhs, rhs)
    assert path == "insert"
    assert result["bytes"] == b"a" * 20 + b"b" * 10
    assert lhs_after == lhs and rhs_after == "moved_from"


def test_heap_lhs_overflow_into_tight_rhs_is_append():
    lhs = make_string(b"a" * 20, capacity=20, sso=False)
    rhs = make_string(b"b" * 10, capacity=10, sso=False)
    result, path, _, _ = concat(lhs, rhs)
    assert path == "append"


def test_boundary_15_is_sso_16_is_heap():
    result15, _, _, _ = concat(make_string(b"a" * 10), make_string(b"b" * 5))
    result16, _, _, _ = concat(make_string(b"a" * 10), make_string(b"b" * 6))
    assert result15["sso"] and not result16["sso"]


def test_append_path_length_overflow_raises():
    lhs = make_string(b"a", capacity=MAX_SIZE, sso=False)
    rhs = make_string(b"b" * 10, capacity=10, sso=False)
    # total <= lhs capacity would be append; force the overflow branch
    # by shrinking lhs capacity below total while rhs stays tight.
    lhs = make_string(b"a", capacity=1, sso=False)
    try:
        # total is tiny here, so this must NOT raise; the real guard
        # only fires when total exceeds MAX_SIZE, checked below.
        concat(lhs, rhs)
    except LengthError:
        raise AssertionError("small concat must not raise")
    big_lhs = {"bytes": b"a" * 10, "capacity": 10, "sso": False}
    big_rhs = {"bytes": b"b" * 10, "capacity": 10, "sso": False}
    import tools.rvalue_string_concat_5ab60_115 as m
    orig = m.MAX_SIZE
    try:
        m.MAX_SIZE = 15  # shrink the cap so total 20 overflows it
        try:
            m.concat(big_lhs, big_rhs)
        except LengthError as exc:
            assert str(exc) == "basic_string::append"
        else:
            raise AssertionError("overflow concat must raise")
    finally:
        m.MAX_SIZE = orig
