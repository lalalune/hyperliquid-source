"""Tests for the node #115 batch lookup model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_batch_lookup_115.py

Every rule below is pinned to the verbatim disassembly in
research/work-items/RE-014-batch-lookup-115/.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from batch_lookup_115 import (
    batch_flag,
    collect_direct,
    driver_outcome,
    max_update,
    pair_address,
    pair_index,
    probe_base,
    probe_mask,
    probe_passes,
    ror12,
    run_batch,
    skip_word,
    sweep_aftermath,
)

MASK64 = (1 << 64) - 1
MASK_CONST = 0x9E3779B97F4A7C13

FAILURES = []


def check(name, cond):
    if cond:
        print("PASS:", name)
    else:
        print("FAIL:", name)
        FAILURES.append(name)


def words_for(hash32, count, rounds, flip_round=None):
    """A word table where every tested round passes, except
    flip_round (if given) which misses one mask bit."""
    base = probe_base(count, hash32)
    prod = (hash32 * MASK_CONST) & MASK64
    words = [0] * 4096
    n = rounds if rounds >= 1 else 1
    for k in range(n):
        mask = probe_mask(prod)
        words[base ^ k] = mask if k != flip_round else mask & (mask - 1)
        prod = ror12(prod)
    return words


def test_flag():
    check("flag options35 wins", batch_flag(5, 1) == 5)
    check("flag falls back to host a60", batch_flag(0, 3) == 1)
    check("flag zero when both zero", batch_flag(0, 0) == 0)


def test_collect_direct():
    check("collect direct when c58 null", collect_direct(False, 0) is True)
    check("collect direct when host30 set",
          collect_direct(True, 7) is True)
    check("collect predicate path when c58 present and host30 zero",
          collect_direct(True, 0) is False)


def test_skip_word():
    check("skip word ORs all three sources",
          skip_word(0b0010, 0b0100, 0b1000) == 0b1110)


def test_probe_math():
    check("probe base (3 * 2**31) >> 32 == 1",
          probe_base(3, 0x80000000) == 1)
    check("ror12(0x1000) == 1", ror12(0x1000) == 1)
    check("mask of product 0 is bit 0", probe_mask(0) == 1)
    check("mask of product 0x40 is bits 0 and 1",
          probe_mask(0x40) == 0b11)


def test_probe_filter():
    h, count = 0x12345678, 4
    check("probe passes when all rounds contain the mask",
          probe_passes(h, count, words_for(h, count, 2), 2) is True)
    check("probe fails when a round misses a mask bit",
          probe_passes(h, count, words_for(h, count, 2, flip_round=1),
                       2) is False)
    check("round 0 always tested even when rounds is 0",
          probe_passes(h, count, words_for(h, count, 0), 0) is True)
    check("round 0 failure fails even when rounds is 0",
          probe_passes(h, count,
                       words_for(h, count, 0, flip_round=0), 0) is False)
    # Corruption control: flipping one bit in a passing word fails.
    words = words_for(h, count, 1)
    base = probe_base(count, h)
    words[base] ^= 1 << (probe_mask((h * MASK_CONST) & MASK64).bit_length() - 1)
    check("corrupted probe word fails",
          probe_passes(h, count, words, 1) is False)


def test_driver_outcomes():
    check("result nonzero sweeps", driver_outcome(1, 0) == "sweep")
    check("flag only installs status6", driver_outcome(0, 1) == "status6")
    check("both zero advances", driver_outcome(0, 0) == "next")


def test_sweep():
    check("sweep limit resumes without filling",
          sweep_aftermath(100, 100, [5, 6]) == ("resume", []))
    check("sweep below limit fills later clear entries",
          sweep_aftermath(99, 100, [5, 6]) == ("epilogue", [5, 6]))


def test_member_feed():
    check("max-update keeps the larger value",
          max_update(10, 7) == 10 and max_update(10, 12) == 12)
    check("pair index rule",
          pair_index(0x1030, 0x1000) == 3)
    check("pair address rule",
          pair_address(0x1000, 3) == 0x1060)


def test_end_to_end():
    records, counters, f10, ended = run_batch(
        n=6, skip={1}, flag=1, probe_present=True,
        probe_pass={0: True, 2: False, 3: True, 4: True, 5: True},
        driver={0: "next", 3: "status6", 4: "sweep", 5: "next"},
        second_word={4: 7}, f10=0, options78=100)
    check("probe hit/miss counters", counters == {"hit": 4, "miss": 1})
    check("probe-fail entry never reaches the driver",
          2 not in records)
    check("status6 installed", records.get(3) == (6, 0, None))
    check("sweep adds the second word", f10 == 7)
    check("sweep fills later clear entries",
          records.get(5) == (10, 0, None))
    check("sweep fill ends the function", ended == "sweep-epilogue")


def test_end_to_end_no_probe():
    records, counters, f10, ended = run_batch(
        n=3, skip=set(), flag=0, probe_present=True,
        probe_pass={}, driver={0: "next", 1: "status6", 2: "next"},
        second_word={}, f10=0, options78=100)
    check("flag zero skips the probe entirely",
          counters == {"hit": 0, "miss": 0})
    check("driver still runs without the probe",
          records.get(1) == (6, 0, None) and ended == "normal")


def test_end_to_end_sweep_limit():
    records, counters, f10, ended = run_batch(
        n=4, skip=set(), flag=1, probe_present=False,
        probe_pass={}, driver={1: "sweep", 2: "status6", 3: "next"},
        second_word={1: 10}, f10=95, options78=100)
    check("sweep at the limit resumes the driver loop",
          ended == "normal" and records.get(2) == (6, 0, None))
    check("no fill when the limit is reached", 3 not in records)


def test_packet():
    here = os.path.join(os.path.dirname(__file__), "..", "research",
                         "work-items", "RE-014-batch-lookup-115")
    records = json.load(open(os.path.join(here, "records.json")))
    check("packet window bounds",
          records["window"]["start"] == "0x5f0d740"
          and records["window"]["end"] == "0x5f0e2c7"
          and records["window"]["size_bytes"] == 1415)
    check("packet digest matches provenance",
          records["window"]["artifact_sha256"]
          == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    check("packet census matches the scan",
          records["census"]["direct_calls"] == ["0x5d53d46", "0x5f12a7b"]
          and records["census"]["tail_jumps"] == []
          and records["census"]["relative_slots"] == [])


def main():
    test_flag()
    test_collect_direct()
    test_skip_word()
    test_probe_math()
    test_probe_filter()
    test_driver_outcomes()
    test_sweep()
    test_member_feed()
    test_end_to_end()
    test_end_to_end_no_probe()
    test_end_to_end_sweep_limit()
    test_packet()
    if FAILURES:
        print("FAILURES:", len(FAILURES))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
