"""Tests for tools/memtable_iterator_seek.py (node #94 0x5168a20).

Run with plain python3 (pytest is not installed on this VM):
    python3 tests/test_memtable_iterator_seek.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from memtable_iterator_seek import (  # noqa: E402
    MemtableIteratorSeek,
    parse_length_prefix,
    probe_passes,
    ror64,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))


def entry(user, trailer):
    total = len(user) + 8
    assert total < 0x80
    return bytes([total]) + user + trailer.to_bytes(8, "little")


def target(user, trailer):
    return user + trailer.to_bytes(8, "little")


def test_ror64():
    assert ror64(1, 12) == 1 << 52
    assert ror64(0x40, 12) == 1 << 58


def test_probe_math():
    # hash 0: mask is bit 0 only.
    assert probe_passes([1], 1, 1, 0) is True
    assert probe_passes([0], 1, 1, 0) is False
    # hash 0x40: round 0 mask bits {0, 1}; after ror 12 the hash is
    # 2**58, so round 1 mask is bit 0 only. Round-1 word decides.
    assert probe_passes([0b11, 1], 1, 2, 0x40) is True
    assert probe_passes([0b11, 0], 1, 2, 0x40) is False
    # rounds == 0 still tests the round-0 word exactly once.
    assert probe_passes([1], 1, 0, 0) is True
    assert probe_passes([0], 1, 0, 0) is False
    # Base index is (hash * count) >> 32; count 2, hash 2**32 - 1 -> base 1.
    # The mask for that hash is bit 63 only (both bit positions coincide).
    assert probe_passes([0, 1 << 63], 2, 1, (1 << 32) - 1) is True
    assert probe_passes([0, 0], 2, 1, (1 << 32) - 1) is False


def test_parse_length_prefix():
    assert parse_length_prefix(bytes([5]) + b"abcde") == (5, 1)
    assert parse_length_prefix(bytes([0x80, 0x01]) + b"x" * 128) == (128, 2)
    for bad in (bytes([0x80]), bytes([0x80] * 6)):
        try:
            parse_length_prefix(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed varint must raise")


def test_seek_stops_at_first_ge_entry():
    entries = [entry(b"aaa", 5), entry(b"aab", 3), entry(b"aac", 1)]
    seek = MemtableIteratorSeek(entries, target(b"aab", 0))
    result = seek.seek()
    assert result.entry == entry(b"aab", 3)
    assert result.ready is True
    assert result.reports == []


def test_seek_advances_on_smaller_trailer():
    entries = [entry(b"aab", 3), entry(b"aab", 10)]
    seek = MemtableIteratorSeek(entries, target(b"aab", 9))
    assert seek.seek().entry == entry(b"aab", 10)


def test_seek_stops_when_current_exceeds_target():
    entries = [entry(b"aab", 1), entry(b"aac", 1)]
    seek = MemtableIteratorSeek(entries, target(b"aaa", 0))
    assert seek.seek().entry == entry(b"aab", 1)


def test_seek_past_end_returns_none():
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(entries, target(b"zzz", 0))
    result = seek.seek()
    assert result.entry is None
    assert result.ready is False


def test_probe_miss_returns_before_inner_seek():
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), table=([0], 1, 1),
        hash_fn=lambda s: 0, perf_level=2)
    result = seek.seek()
    assert result.entry is None and result.ready is False
    assert "inner_seek" not in seek.calls
    assert result.perf_events == [0x140, 0x208]


def test_probe_hit_then_seek():
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), table=([1], 1, 1),
        hash_fn=lambda s: 0, perf_level=2)
    result = seek.seek()
    assert result.entry == entry(b"aaa", 1)
    assert result.perf_events[0] == 0x140
    assert 0x200 in result.perf_events


def test_probe_skipped_when_table_null_or_gate_false():
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(entries, target(b"aaa", 0), table=None)
    assert seek.seek().entry == entry(b"aaa", 1)
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), table=([0], 1, 1),
        prefix_gate=lambda s: False, hash_fn=lambda s: 0)
    assert seek.seek().entry == entry(b"aaa", 1)


def test_initial_check_failure_reports_nothing():
    entries = [entry(b"aaa", 1)]

    def failing_refresh(state):
        state.code = 5

    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), refresh=failing_refresh)
    result = seek.seek()
    assert result.entry is None
    assert result.reports == []
    assert "snapshot" in seek.calls


def test_advance_check_failure_reports_then_returns_known():
    entries = [entry(b"aaa", 1), entry(b"aab", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aac", 0), width=1,
        reader=lambda buf, w: 7)
    result = seek.seek()
    assert result.entry is None
    assert result.reports == [(3, "check failed")]


def test_unknown_predicate_called_twice_on_first_false():
    answers = iter([False])

    def pred():
        try:
            return next(answers)
        except StopIteration:
            return False

    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), known_predicate=False, predicate=pred)
    result = seek.seek()
    assert result.entry is None
    assert seek.calls.count("predicate") == 2


def test_unknown_predicate_true_continues_after_report():
    entries = [entry(b"aaa", 1), entry(b"aab", 1), entry(b"aac", 1)]
    seen = []

    def reader(buf, w):
        seen.append(buf)
        return 7 if len(seen) == 1 else 0

    seek = MemtableIteratorSeek(
        entries, target(b"aac", 0), width=1, known_predicate=False,
        predicate=lambda: True, reader=reader)
    result = seek.seek()
    assert result.entry == entry(b"aac", 1)
    assert len(result.reports) == 1
    assert result.reports[0][0] == 3


def test_status_copy_clean_path_repositions_then_returns():
    # Inner cursor past the end: ready False, code 0 -> not clean ->
    # status copy with code 0 -> +0x20 gate -> inline reposition
    # (inner +0x50, valid, refresh) -> fill gate fails on ready False.
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), inner_start=1)
    result = seek.seek()
    assert result.entry is None
    assert "snapshot" in seek.calls
    assert "gate_0x20" in seek.calls
    assert "inner_reposition" in seek.calls
    assert seek.calls.count("refresh") == 2


def test_acquire_pointer_destroyed_on_exit():
    entries = [entry(b"aaa", 1)]
    seek = MemtableIteratorSeek(
        entries, target(b"aaa", 0), perf_level=3,
        acquire=lambda t: object())
    seek.seek()
    assert "acquire" in seek.calls
    assert "temp_destroyed" in seek.calls


def test_packet_records():
    packet = os.path.join(ROOT, "research", "work-items",
                          "RE-001-memtable-iterator-seek-94")
    records = json.load(open(os.path.join(packet, "records.json")))
    assert records["window"]["start"] == "0x5168a20"
    assert records["window"]["end"] == "0x5169220"
    assert records["window"]["artifact_sha256"].startswith("3b7179cd")
    assert records["caller_census"]["relative_slots"] == ["0x575b260"]
    assert records["caller_census"]["direct_call_sites"] == []
    window = open(os.path.join(packet, "window.txt")).read()
    assert "5168a20" in window and "5169218" in window


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - runner reports all
            failures += 1
            print("FAIL", test.__name__, ":", exc)
        else:
            print("ok", test.__name__)
    print("%d tests, %d failures" % (len(TESTS), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
