"""Model tests for node #115 routine 0x5d5ad20 (binary-search membership)."""
from tools.binary_search_membership_5ad20_115 import (
    lower_bound, present)


def _rec(data):
    return (data, len(data))


def test_empty_range_is_absent():
    assert present([], _rec(b"abc")) is False
    assert lower_bound([], _rec(b"abc")) == 0


def test_exact_record_is_present():
    records = [_rec(b"a"), _rec(b"ab"), _rec(b"b"), _rec(b"c")]
    assert present(records, _rec(b"ab")) is True
    assert present(records, _rec(b"c")) is True


def test_between_records_is_absent():
    records = [_rec(b"a"), _rec(b"c")]
    assert present(records, _rec(b"b")) is False
    assert lower_bound(records, _rec(b"b")) == 1


def test_outside_range_is_absent():
    records = [_rec(b"b"), _rec(b"c")]
    assert present(records, _rec(b"a")) is False
    assert present(records, _rec(b"d")) is False


def test_prefix_shorter_key_is_absent():
    records = [_rec(b"abc")]
    assert present(records, _rec(b"ab")) is False
    assert present(records, _rec(b"abcd")) is False


def test_duplicate_equal_records_are_present():
    records = [_rec(b"a"), _rec(b"b"), _rec(b"b"), _rec(b"c")]
    assert present(records, _rec(b"b")) is True
    assert lower_bound(records, _rec(b"b")) == 1  # first equal record


def test_length_field_truncates_buffer():
    records = [(b"abcXYZ", 3)]
    assert present(records, _rec(b"abc")) is True
    assert present(records, _rec(b"abcX")) is False


def test_empty_key_and_empty_record():
    records = [_rec(b""), _rec(b"a")]
    assert present(records, _rec(b"")) is True
    assert present(records, _rec(b"a")) is True
    assert present([_rec(b"a")], _rec(b"")) is False


def test_halving_path_over_larger_range():
    records = [_rec(bytes([c])) for c in range(ord("a"), ord("z") + 1)]
    for c in range(ord("a"), ord("z") + 1):
        assert present(records, _rec(bytes([c]))) is True
    assert present(records, _rec(b"aa")) is False
    assert lower_bound(records, _rec(b"aa")) == 1
