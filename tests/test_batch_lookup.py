"""Tests for tools/batch_lookup.py (RE-001, node #94 0x516d110).

pytest-style, with a plain-python3 __main__ runner because pytest
is not installed on this VM.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from batch_lookup import (  # noqa: E402
    MASK_CONST, SEED, collect, driver_outcome, install_status,
    mark_bit, max_update, pair_index, probe_byte, probe_filter,
    probe_flag, run_batch, skip_word,
)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def toy_hash(ptr, length, seed):
    check(seed == SEED, "seed is 0xbc9f1d34")
    return 0x12345678


def entries_for():
    return {
        0: {"view": (0x2000, 4), "record": ("old", 1, 0x99),
            "max": 10, "string": "old", "sweep_add": 5},
        1: {"view": (0x3000, 4), "record": None,
            "max": 0, "string": "old", "sweep_add": 7},
        2: {"view": (0x4000, 4), "record": ("old", 1, 0x88),
            "max": 3, "string": "old", "sweep_add": 0},
    }


def test_skip_and_flag():
    check(skip_word(0x5, 0x2, 0x8) == 0xF, "skip word is the OR")
    check(probe_flag(0x35, 0) == 0x35, "options byte wins when nonzero")
    check(probe_flag(0, 1) == 1, "host +0xa60 nonzero gives 1")
    check(probe_flag(0, 0) == 0, "both zero gives 0 (thunk forwards)")


def test_collect_skips_set_bits_and_forms():
    entries = entries_for()
    views, idx = collect(entries, 0, 3, 0b010, 1, None, None)
    check(idx == [0, 2], "set-bit index 1 skipped: %r" % (idx,))
    check(views == [(0x2000, 4), (0x4000, 4)], "direct copy form")
    views, idx = collect(entries, 0, 3, 0, 0,
                         lambda v: v[0] != 0x3000,
                         lambda v: (v[0] + 0x10, v[1]))
    check(idx == [0, 2], "predicate-false entry dropped")
    check(views == [(0x2010, 4), (0x4010, 4)], "transform form")


def _word_with_bits(product):
    mask = (1 << (product & 63)) | (1 << ((product >> 6) & 63))
    return mask


def test_probe_all_rounds_and_round_zero():
    h = 0x12345678
    prod = (h * MASK_CONST) & ((1 << 64) - 1)
    good = _word_with_bits(prod)
    check(probe_byte(h, 1, [good], 0) == 1, "round 0 decides when rounds 0")
    check(probe_byte(h, 1, [0], 0) == 0, "round 0 fail fails when rounds 0")
    prod1 = ((prod >> 12) | (prod << 52)) & ((1 << 64) - 1)
    good1 = _word_with_bits(prod1)
    check(probe_byte(h, 1, [good, good1], 2) == 1, "both rounds pass")
    check(probe_byte(h, 1, [good, 0], 2) == 0, "a failing later round fails")
    check(probe_byte(h, 1, [0, good1], 2) == 0, "a failing round 0 fails")


def test_probe_filter_uses_seed():
    words = [_word_with_bits((0x12345678 * MASK_CONST) & ((1 << 64) - 1))]
    check(probe_filter([(0x2000, 4)], 1, words, 1, toy_hash) == [1],
          "filter passes with matching word")


def test_driver_outcomes_and_status():
    check(driver_outcome(1, 0) == "sweep", "result byte wins")
    check(driver_outcome(1, 1) == "sweep", "result beats flag")
    check(driver_outcome(0, 1) == "status6", "flag alone is status 6")
    check(driver_outcome(0, 0) == "next", "both zero moves on")
    rec, freed = install_status(6, 0x99)
    check(rec == (6, 0, None) and freed, "status 6 frees old pointer")
    rec, freed = install_status(10, None)
    check(rec == (10, 0, None) and not freed, "status 10 with no old ptr")


def test_pair_index_and_max_and_bit():
    check(pair_index(0x8008, 0x8000) == 1, "index 1")
    check(pair_index(0x8010, 0x8000) == 2, "index 2")
    check(max_update(10, 42) == 42, "larger updates")
    check(max_update(10, 5) == 10, "smaller keeps")
    check(mark_bit(0b100, 1) == 0b110, "bit set")


def test_run_batch_end_to_end():
    entries = entries_for()
    words = [_word_with_bits((0x12345678 * MASK_CONST) & ((1 << 64) - 1))]

    def driver(entry):
        return (0, 1) if entry["view"][0] == 0x2000 else (1, 0)

    def feed(entry):
        return 42, "new"

    events, records, done, counter = run_batch(
        True, 0, 3, 0, 0, entries, (1, words, 1), toy_hash,
        lambda v: True, lambda v: v, driver, feed)
    check("collected:3" in events, "three collected: %r" % (events,))
    check("member_feed:0" in events, "flag zero feeds member: %r" % (events,))
    check(entries[0]["max"] == 42 and entries[0]["string"] == "new",
          "feed updates max and string")
    check(records[0] == (6, 0, None), "status 6 installed: %r" % (records,))
    check(records[2] == (10, 0, None), "sweep installs status 10 later")
    check(counter == 7, "sweep adds entry counter: %r" % (counter,))
    check((done >> 1) & 1 and (done >> 2) & 1, "sweep marks bits")


def test_run_batch_gate_and_no_table():
    events, _, _, _ = run_batch(False, 0, 3, 0, 0, entries_for(), None,
                                toy_hash, None, None, None, None)
    check(events == ["early_gate"], "gate does nothing else")
    events, _, _, _ = run_batch(True, 0, 3, 0, 0, entries_for(), None,
                                toy_hash, None, None, None, None)
    check(events == ["no_probe_table"], "no probe table does nothing")


def test_run_batch_probe_fail_marks_done():
    entries = entries_for()
    events, _, done, _ = run_batch(
        True, 0, 3, 0, 1, entries, (1, [0], 1), toy_hash,
        None, None, lambda e: (0, 0), lambda e: (0, None))
    check(all("probe_fail" in e for e in events if "probe" in e),
          "all fail: %r" % (events,))
    check(done == 0b111, "failed entries marked done: %r" % (done,))


def test_packet_files_present():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-batch-lookup-94")
    for name in ("README.md", "records.json", "window.txt", "stub.txt",
                 "frames.txt", "relocations.txt", "verify.py",
                 "export_excerpts.py", "census.py", "MANIFEST.sha256"):
        check(os.path.exists(os.path.join(packet, name)), "missing " + name)


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for name, fn in tests:
        fn()
        print("PASS", name)
    print("ALL %d MODEL TESTS PASSED" % len(tests))
