"""Tests for the node #115 memtable iterator seek loop model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_memtable_iterator_seek_loop_115.py

Every rule below is pinned to the verbatim disassembly in
research/work-items/RE-014-memtable-iterator-seek-loop-115/.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_iterator_seek_loop_115 import (
    MemtableIteratorSeekLoop,
    mask_bits,
    parse_length_prefix,
    probe_base,
    probe_passes,
    ror12,
)

MASK64 = (1 << 64) - 1
MASK_CONST = 0x9E3779B97F4A7C13


def entry(user_key, trailer):
    """One inner entry buffer: 1-byte length prefix + key + trailer."""
    body = user_key + trailer.to_bytes(8, "little")
    assert len(body) < 0x80
    return bytes([len(body)]) + body


def target(user_key, trailer):
    return user_key + trailer.to_bytes(8, "little")


def check(name, cond):
    if not cond:
        raise AssertionError(name)
    print("ok:", name)


def test_probe_math():
    # Base index: (count * hash32) >> 32.
    check("probe base", probe_base(100, 0x12345678) == (100 * 0x12345678) >> 32)
    # Mask bits of a value and of its ror12 rotation.
    h = 0x1122334455667788
    check("mask bits", mask_bits(h) == (h & 63, (h >> 6) & 63))
    check("ror12", ror12(h) == ((h >> 12) | ((h << 52) & MASK64)) & MASK64)
    # All-ones table always hits; a word missing one mask bit misses.
    h32 = 0xAABBCCDD
    hh = (h32 * MASK_CONST) & MASK64
    b0, b1 = mask_bits(hh)
    words = [(1 << 64) - 1] * 8
    check("probe all-ones hit", probe_passes(words, 8, 3, h32))
    bad = list(words)
    bad[probe_base(8, h32) & 7] &= ~(1 << b0)
    check("probe missing bit miss", not probe_passes(bad, 8, 3, h32))
    # Round 0 is always tested even when rounds is 0.
    check("probe rounds-0 hit", probe_passes(words, 8, 0, h32))
    check("probe rounds-0 miss", not probe_passes(bad, 8, 0, h32))
    # Rotation across rounds: round-0 word passes, round-1 word must
    # carry the rotated mask bits or the probe misses.
    h1 = ror12(hh)
    c0, c1 = mask_bits(h1)
    base = probe_base(8, h32)
    words2 = [0] * 8
    words2[base] = (1 << b0) | (1 << b1)
    words2[base ^ 1] = (1 << c0) | (1 << c1)
    check("probe rotation hit", probe_passes(words2, 8, 2, h32))
    words2[base ^ 1] &= ~(1 << c1)
    check("probe rotation miss", not probe_passes(words2, 8, 2, h32))
    # Corruption control: clearing one mask bit from the round-0 word
    # flips a hit to a miss.
    words3 = [0] * 8
    words3[base] = (1 << b0) | (1 << b1)
    corrupted = list(words3)
    corrupted[base] &= ~(1 << b0)
    check("probe corruption control",
          probe_passes(words3, 8, 1, h32)
          and not probe_passes(corrupted, 8, 1, h32))


def test_length_prefix():
    check("prefix 1-byte", parse_length_prefix(bytes([5]) + b"abcde") == (5, 1))
    # Varint: 0x80 0x01 decodes to 128, slice starts at offset 2.
    check("prefix varint", parse_length_prefix(bytes([0x80, 0x01]) + b"x" * 128)
          == (128, 2))
    try:
        parse_length_prefix(bytes([0x80] * 6))
        raise AssertionError("varint overrun must raise")
    except ValueError:
        print("ok: prefix varint overrun raises")


def test_stop_on_greater_entry():
    entries = [entry(b"aaa", 1), entry(b"bbb", 1), entry(b"ccc", 1)]
    it = MemtableIteratorSeekLoop(entries, target(b"bbb", 1))
    res = it.run()
    check("stop at equal user key, equal trailer", res.entry == 1)
    check("ready after stop", res.ready is True)


def test_trailer_check():
    # Equal user key: entry trailer below target advances, else stops.
    entries = [entry(b"bbb", 1), entry(b"bbb", 9)]
    it = MemtableIteratorSeekLoop(entries, target(b"bbb", 5))
    res = it.run()
    check("trailer below advances", res.entry == 1)
    it = MemtableIteratorSeekLoop(entries, target(b"bbb", 0))
    res = it.run()
    check("trailer above stops", res.entry == 0)


def test_advance_past_smaller_entries():
    entries = [entry(b"aaa", 1), entry(b"bbb", 1), entry(b"ddd", 1)]
    it = MemtableIteratorSeekLoop(entries, target(b"ccc", 1))
    res = it.run()
    check("advance past smaller", res.entry == 2)


def test_probe_miss_and_skip():
    entries = [entry(b"aaa", 1)]
    words = [0] * 8
    it = MemtableIteratorSeekLoop(entries, target(b"aaa", 1),
                                  table=(words, 8, 2), perf_level=2,
                                  hash_fn=lambda n: 0x12345678)
    res = it.run()
    check("probe miss ready False", res.ready is False)
    check("probe miss no inner seek", "inner-seek" not in res.calls)
    check("probe miss perf", 0x208 in res.perf_events)
    # Null table skips the probe entirely.
    it = MemtableIteratorSeekLoop(entries, target(b"aaa", 1))
    res = it.run()
    check("probe skipped, inner seek runs", "inner-seek" in res.calls)


def test_reader_report_and_initial_quirk():
    # Advance path with a failing reader: installs code, reports, and
    # the fill gate then returns (known predicate, code still set).
    entries = [entry(b"aaa", 1), entry(b"bbb", 1)]
    it = MemtableIteratorSeekLoop(
        entries, target(b"bbb", 1), width=16,
        reader=lambda buf, w: 7)
    res = it.run()
    check("reader fail reports", res.reports == [(3, "check-detail")])
    check("reader fail stops at entry", res.entry == 1)
    # Reader success on the advance path: no report, seek continues.
    it = MemtableIteratorSeekLoop(
        entries, target(b"bbb", 1), width=16,
        reader=lambda buf, w: 0)
    res = it.run()
    check("reader ok no report", res.reports == [])
    check("reader ok stops at entry", res.entry == 1)


def test_unknown_predicate_polarity():
    # Unknown predicate False on the first gate -> status copy runs,
    # then the fill gate calls it a second time (True -> fill).
    calls = {"n": 0}

    def pred():
        calls["n"] += 1
        return calls["n"] >= 2

    entries = [entry(b"aaa", 1)]
    it = MemtableIteratorSeekLoop(entries, target(b"aaa", 1),
                                  known_predicate=False, predicate=pred)
    res = it.run()
    check("unknown False -> status copy", "status-copy" in res.calls)
    check("unknown predicate called twice", calls["n"] == 2)
    check("unknown polarity stops at entry", res.entry == 0)
    # Unknown predicate True on the first gate -> no status copy.
    it = MemtableIteratorSeekLoop(entries, target(b"aaa", 1),
                                  known_predicate=False,
                                  predicate=lambda: True)
    res = it.run()
    check("unknown True -> no status copy", "status-copy" not in res.calls)


def test_perf_events():
    entries = [entry(b"aaa", 1)]
    it = MemtableIteratorSeekLoop(entries, target(b"aaa", 1), perf_level=3,
                                  acquire=lambda t: "timer")
    res = it.run()
    check("perf entry + fill counters",
          0x140 in res.perf_events and 0x0 in res.perf_events)
    check("perf timer destroyed", "timer-destroy" in res.calls)


def test_packet_checks():
    here = os.path.join(os.path.dirname(__file__), "..", "research",
                        "work-items", "RE-014-memtable-iterator-seek-loop-115")
    import json
    records = json.load(open(os.path.join(here, "records.json")))
    check("records window start", records["window"]["start"] == "0x5f09050")
    check("records window end", records["window"]["end"] == "0x5f09850")
    check("records window size", records["window"]["size_bytes"] == 2048)
    check("records digest",
          records["window"]["artifact_sha256"]
          == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    excerpt = open(os.path.join(here, "window-5f09050.objdump.txt")).read()
    lines = excerpt.splitlines()
    check("excerpt window entry",
          any("5f09050" in ln and "endbr64" in ln for ln in lines))
    check("excerpt has report call", "5fceda0" in excerpt)
    check("excerpt has reader call", "5f07670" in excerpt)
    check("records no mnemonic list",
          "mnemonics" not in json.dumps(records)
          and "instructions" not in records)


def main():
    test_probe_math()
    test_length_prefix()
    test_stop_on_greater_entry()
    test_trailer_check()
    test_advance_past_smaller_entries()
    test_probe_miss_and_skip()
    test_reader_report_and_initial_quirk()
    test_unknown_predicate_polarity()
    test_perf_events()
    test_packet_checks()
    print("ALL MODEL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
