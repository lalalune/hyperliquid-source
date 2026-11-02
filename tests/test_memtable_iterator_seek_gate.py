"""Tests for tools/memtable_iterator_seek_gate.py (node #94 0x5168610).

Run with plain python3 (pytest is not installed on this VM):
    python3 tests/test_memtable_iterator_seek_gate.py

The hash is injected: the tests pin the probe math (base index, two-bit
mask, rotation, at-least-round-0, miss/hit paths) against fixed hash
values, not the real 0x5422e70 internals, which the model takes by
contract from the neighbouring packets.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_iterator_seek_gate import (
    GOLDEN,
    MASK64,
    PrefixObject,
    ProbeTable,
    PerfState,
    InnerIterator,
    probe_base,
    probe_mask,
    run_seek,
)


def check(name, cond):
    if not cond:
        raise AssertionError(name)
    print("ok:", name)


def const_hash(value):
    def fn(transformed, seed):
        assert seed == 0xBC9F1D34
        return value
    return fn


def target():
    return (0x1000, 200)


def chain_all_known():
    fourth = PrefixObject(lambda sl: True)
    third = PrefixObject("known", fourth)
    second = PrefixObject("known", third)
    first = PrefixObject("known", second, transform=lambda sl: (0x2000, 64))
    return first


def test_null_table_skips_probe():
    inner = InnerIterator(valid_result=True)
    perf = PerfState(level=0)
    out = run_seek(target(), None, chain_all_known(), 16, inner, perf,
                   const_hash(0x1234))
    check("null table: ready from valid", out["ready"] is True)
    check("null table: inner seek called",
          ("seek", target()) in out["inner_events"])
    check("null table: no probe event",
          not any(e[0] == "probe" for e in out["events"]))
    check("null table: refresh runs",
          ("refresh_84d0",) in out["events"])


def test_predicate_false_goes_to_inner_seek():
    inner = InnerIterator(valid_result=False)
    perf = PerfState(level=0)
    first = PrefixObject(lambda sl: False, transform=lambda sl: (0, 0))
    out = run_seek(target(), ProbeTable(4, 1, [0] * 4), first, 16,
                   inner, perf, const_hash(0x1234))
    check("predicate false: ready from valid", out["ready"] is False)
    check("predicate false: inner seek called",
          ("seek", target()) in out["inner_events"])
    check("predicate false: no probe",
          not any(e[0] == "probe" for e in out["events"]))


def test_chain_slice_lengths():
    seen = []

    def recorder(sl):
        seen.append(sl)
        return True

    fourth = PrefixObject(recorder)
    third = PrefixObject("known", fourth)
    second = PrefixObject(recorder, third)
    first = PrefixObject("known", second, transform=lambda sl: (0x2000, 64))
    inner = InnerIterator()
    perf = PerfState(level=0)
    # probe_len = 200 - 8 - 16 = 176; words all-ones hit every round.
    out = run_seek(target(), ProbeTable(1, 1, [MASK64]), first, 16,
                   inner, perf, const_hash(0xABCD))
    check("chain: level slices shrink by 8",
          seen == [(0x1000, 168), (0x1000, 152)])
    check("chain: known levels skipped",
          out["events"].count(("chain_known_skip", 0)) == 1)
    check("chain: probe hit reaches inner seek", out["ready"] is True)


def test_probe_base_and_mask():
    check("base index math", probe_base(4, 0x80000000) == 2)
    check("base index zero", probe_base(4, 0) == 0)
    check("mask bits", probe_mask((2 << 6) | 1) == (1 << 2) | (1 << 1))
    # Bit positions wrap mod 64 through the shift count.
    check("mask high bits", probe_mask((63 << 6) | 63) == (1 << 63))


def test_probe_miss_sets_ready_false():
    inner = InnerIterator()
    perf = PerfState(level=0)
    out = run_seek(target(), ProbeTable(1, 1, [0]), chain_all_known(), 16,
                   inner, perf, const_hash(0xABCD))
    check("miss: ready false", out["ready"] is False)
    check("miss: no inner seek", out["inner_events"] == [])
    check("miss: no refresh",
          ("refresh_84d0",) not in out["events"])


def test_probe_round_zero_always_tested():
    # rounds == 0 still tests round 0; a zero word there is a miss.
    inner = InnerIterator()
    perf = PerfState(level=0)
    out = run_seek(target(), ProbeTable(1, 0, [0]), chain_all_known(), 16,
                   inner, perf, const_hash(0xABCD))
    check("rounds=0: round 0 still tested, miss",
          out["ready"] is False)
    # ...and an all-ones word there is a hit.
    inner = InnerIterator()
    perf = PerfState(level=0)
    out = run_seek(target(), ProbeTable(1, 0, [MASK64]), chain_all_known(),
                   16, inner, perf, const_hash(0xABCD))
    check("rounds=0: round 0 hit reaches inner seek",
          out["ready"] is True)


def test_probe_rotation_across_rounds():
    # Fixed hash; round 0 passes, round 1 passes only after ror 12.
    h = 0x0123456789ABCDEF
    h32 = h & 0xFFFFFFFF
    rotated1 = ((h32 * GOLDEN) & MASK64)
    rotated1 = ((rotated1 >> 12) | (rotated1 << 52)) & MASK64
    # Word for round 0 must carry both round-0 mask bits; round-1 word
    # must carry both rotated mask bits.  Build words with exactly the
    # needed bits plus a corruption control: clearing one bit misses.
    m0 = probe_mask((h32 * GOLDEN) & MASK64)
    m1 = probe_mask(rotated1)
    words = [m0, m1]
    inner = InnerIterator()
    perf = PerfState(level=0)
    out = run_seek(target(), ProbeTable(1, 2, words), chain_all_known(),
                   16, inner, perf, const_hash(h))
    check("rotation: two rounds hit", out["ready"] is True)
    check("rotation: both rounds logged",
          len([e for e in out["events"] if e[0] == "probe_round"]) == 2)
    # Corruption control: clear one round-1 mask bit -> miss.
    inner = InnerIterator()
    perf = PerfState(level=0)
    words_bad = [m0, m1 & ~(m1 & -m1)]
    out = run_seek(target(), ProbeTable(1, 2, words_bad), chain_all_known(),
                   16, inner, perf, const_hash(h))
    check("rotation: corrupted round-1 word misses",
          out["ready"] is False)


def test_perf_counters_and_timer():
    inner = InnerIterator()
    perf = PerfState(level=3, slot_nonzero=True)
    # Timer start 100, clock end 150 -> +50 into the 0x138 counter.
    clock = [100, lambda: 150]
    out = run_seek(target(), ProbeTable(1, 1, [MASK64]), chain_all_known(),
                   16, inner, perf, const_hash(0xABCD), timer_clock=clock)
    check("perf: entry counter", perf.counters[0x140] == 1)
    check("perf: hit counter", perf.counters[0x200] == 1)
    check("perf: miss counter untouched", perf.counters[0x208] == 0)
    check("perf: timer elapsed", perf.counters[0x138] == 50)
    check("perf: timer destroyed event",
          ("timer_destroyed", 100, 150) in out["events"])
    check("perf: getter called on perf blocks", perf.getter_calls == 3)
    # Miss path: +0x208, no +0x200, timer still destroyed.
    inner = InnerIterator()
    perf = PerfState(level=3, slot_nonzero=True)
    clock = [100, lambda: 130]
    out = run_seek(target(), ProbeTable(1, 1, [0]), chain_all_known(), 16,
                   inner, perf, const_hash(0xABCD), timer_clock=clock)
    check("perf miss: miss counter", perf.counters[0x208] == 1)
    check("perf miss: hit counter untouched", perf.counters[0x200] == 0)
    check("perf miss: timer elapsed", perf.counters[0x138] == 30)
    # Level 1: no counters, no timer.
    inner = InnerIterator()
    perf = PerfState(level=1, slot_nonzero=True)
    out = run_seek(target(), ProbeTable(1, 1, [MASK64]), chain_all_known(),
                   16, inner, perf, const_hash(0xABCD))
    check("perf level 1: no counters",
          all(v == 0 for v in perf.counters.values()))
    # Timer start 0: no destruction, no elapsed.
    inner = InnerIterator()
    perf = PerfState(level=3, slot_nonzero=True)
    clock = [0, lambda: 150]
    out = run_seek(target(), ProbeTable(1, 1, [MASK64]), chain_all_known(),
                   16, inner, perf, const_hash(0xABCD), timer_clock=clock)
    check("timer start 0: no destroy",
          not any(e[0] == "timer_destroyed" for e in out["events"]))
    check("timer start 0: no elapsed", perf.counters[0x138] == 0)


def test_packet_records_parse():
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-memtable-iterator-seek-gate-94")
    records = json.load(open(os.path.join(packet, "records.json")))
    check("packet: window start", records["window"]["start"] == "0x5168610")
    check("packet: digest bound",
          records["window"]["artifact_sha256"].startswith("3b7179cd"))
    window = open(os.path.join(packet, "window.txt")).read()
    check("packet: excerpt entry", "5168610:\tf3 0f 1e fa" in window)


def main():
    test_null_table_skips_probe()
    test_predicate_false_goes_to_inner_seek()
    test_chain_slice_lengths()
    test_probe_base_and_mask()
    test_probe_miss_sets_ready_false()
    test_probe_round_zero_always_tested()
    test_probe_rotation_across_rounds()
    test_perf_counters_and_timer()
    test_packet_records_parse()
    print("ALL MODEL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
