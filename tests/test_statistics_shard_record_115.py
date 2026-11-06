"""Tests for the StatisticsImpl shard-record model (node #115).

Run directly: python3 tests/test_statistics_shard_record_115.py
Each check exercises the behaviour end to end: the CPUID picker
and the per-thread seed pick a shard, and the record slots land the
value in that shard (or forward it to the delegate), honouring the
level gates exactly as the excerpts show.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import statistics_shard_record_115 as m  # noqa: E402

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        print("FAIL:", name)


class Delegate:
    """A mock delegate Statistics: records what its slots receive."""

    def __init__(self, level=3, exponent=3):
        self.inner = m.StatisticsImpl(level=level, exponent=exponent)
        self.ticker_forwards = []
        self.histogram_forwards = []

    def record_ticker(self, ticker_id, value, cpu_count, seed):
        self.ticker_forwards.append((ticker_id, value))
        return self.inner.record_ticker(ticker_id, value, cpu_count, seed)

    def record_histogram(self, hist_id, value, cpu_count, seed):
        self.histogram_forwards.append((hist_id, value))
        return self.inner.record_histogram(hist_id, value, cpu_count, seed)


def test_picker():
    check("picker: max leaf 0 -> -1", m.cpuid_logical_count(0, 0) == -1)
    check("picker: leaf1 ebx 0x01000000 -> 1",
          m.cpuid_logical_count(6, 0x01000000) == 1)
    check("picker: leaf1 ebx 0x08000000 -> 8",
          m.cpuid_logical_count(6, 0x08000000) == 8)
    check("picker: leaf1 ebx 0x10000000 -> 16",
          m.cpuid_logical_count(0x80000000, 0x10000000) == 16)
    check("picker: leaf1 ebx low bits ignored",
          m.cpuid_logical_count(6, 0x04FFFFFF) == 4)


def test_shard_pick():
    check("pick: cpu 8 exp 3 -> 0", m.pick_shard(8, 3) == 0)
    check("pick: cpu 9 exp 3 -> 1", m.pick_shard(9, 3) == 1)
    check("pick: cpu 17 exp 4 -> 1", m.pick_shard(17, 4) == 1)
    check("pick: cpu 0x100 exp 3 -> 0", m.pick_shard(0x100, 3) == 0)
    check("pick: seed 0x41a7 exp 3 -> 7",
          m.pick_shard(0x41A7, 3) == 7)


def test_seed():
    check("mersenne: step(1) == 0x41a7", m.mersenne_step(1) == 0x41A7)
    check("mersenne: small seeds are plain products",
          m.mersenne_step(100) == 100 * 0x41A7)
    check("mersenne: step(0x7fffffff) == 0x7fffffff (true 0 is kept "
          "as 0x7fffffff by the fold)",
          m.mersenne_step(0x7FFFFFFF) == 0x7FFFFFFF)
    check("mersenne: result stays in [0, 0x7fffffff]",
          all(0 <= m.mersenne_step(s) <= 0x7FFFFFFF
              for s in (1, 12345, 0x12345678, 0x7FFFFFFE)))
    seed = m.ThreadSeed(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    first = seed.pointer()
    check("seed: cached on repeat", seed.pointer() == first)
    check("seed: nonzero 31-bit", 0 < first <= 0x7FFFFFFF)
    seed2 = m.ThreadSeed(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    check("seed: same thread bytes give the same seed",
          seed2.pointer() == first)
    seed3 = m.ThreadSeed(b"\x08\x07\x06\x05\x04\x03\x02\x01")
    check("seed: different thread bytes differ",
          seed3.pointer() != first)


def test_ticker_record():
    seed = m.ThreadSeed(b"\x11" * 8)
    stats = m.StatisticsImpl(level=3, exponent=3)
    check("ticker: cpu 8 records into shard 0",
          stats.record_ticker(5, 10, 8, seed) is True
          and stats.shards[0].tickers[5] == 10)
    check("ticker: second record accumulates",
          stats.record_ticker(5, 10, 8, seed) is True
          and stats.shards[0].tickers[5] == 20)
    check("ticker: cpu 9 records into shard 1",
          stats.record_ticker(5, 7, 9, seed) is True
          and stats.shards[1].tickers[5] == 7)
    check("ticker: id 0xb1 (177) is the last recorded id",
          stats.record_ticker(0xB1, 3, 8, seed) is True
          and stats.shards[0].tickers[0xB1] == 3)
    check("ticker: id 0xb2 (178) is rejected",
          stats.record_ticker(0xB2, 3, 8, seed) is False
          and stats.shards[0].tickers[0xB1] == 3)
    off = m.StatisticsImpl(level=0, exponent=3)
    check("ticker: level 0 records nothing",
          off.record_ticker(5, 10, 8, seed) is False
          and all(t == 0 for s in off.shards for t in s.tickers))
    check("ticker: level 0 does not forward",
          _ticker_forward_level0(seed) is False)


def _ticker_forward_level0(seed):
    delegate = Delegate()
    off = m.StatisticsImpl(level=0, exponent=3, delegate=delegate)
    off.record_ticker(5, 10, 8, seed)
    return bool(delegate.ticker_forwards)


def test_ticker_delegate():
    seed = m.ThreadSeed(b"\x22" * 8)
    delegate = Delegate()
    stats = m.StatisticsImpl(level=3, exponent=3, delegate=delegate)
    stats.record_ticker(9, 4, 8, seed)
    check("ticker: delegate receives the forward",
          delegate.ticker_forwards == [(9, 4)])
    check("ticker: delegate records it in its own shard 0",
          delegate.inner.shards[0].tickers[9] == 4)
    check("ticker: local shard also has it",
          stats.shards[0].tickers[9] == 4)


def test_histogram_record():
    seed = m.ThreadSeed(b"\x33" * 8)
    stats = m.StatisticsImpl(level=3, exponent=3)
    check("histogram: cpu 8 records into shard 0 record 3",
          stats.record_histogram(3, 100, 8, seed) is True
          and stats.shards[0].records[3].count == 1
          and stats.shards[0].records[3].sum == 100)
    stats.record_histogram(3, 200, 8, seed)
    rec = stats.shards[0].records[3]
    check("histogram: second sample accumulates",
          rec.count == 2 and rec.sum == 300 and rec.min == 100
          and rec.max == 200)
    check("histogram: cpu 10 records into shard 2",
          stats.record_histogram(3, 50, 10, seed) is True
          and stats.shards[2].records[3].count == 1)
    low = m.StatisticsImpl(level=1, exponent=3)
    check("histogram: level 1 records nothing",
          low.record_histogram(3, 100, 8, seed) is False
          and low.shards[0].records[3].count == 0)
    zero = m.StatisticsImpl(level=0, exponent=3)
    check("histogram: level 0 records nothing",
          zero.record_histogram(3, 100, 8, seed) is False)


def test_histogram_delegate():
    seed = m.ThreadSeed(b"\x44" * 8)
    delegate = Delegate()
    stats = m.StatisticsImpl(level=3, exponent=3, delegate=delegate)
    stats.record_histogram(0x33, 10, 8, seed)
    check("histogram: id 0x33 is forwarded",
          delegate.histogram_forwards == [(0x33, 10)])
    stats.record_histogram(0x34, 10, 8, seed)
    check("histogram: id 0x34 is recorded locally but not forwarded",
          delegate.histogram_forwards == [(0x33, 10)]
          and stats.shards[0].records[0x34].count == 1)
    check("histogram: delegate recorded id 0x33 in its own shard",
          delegate.inner.shards[0].records[0x33].count == 1)


def test_histogram_wrapper():
    seed = m.ThreadSeed(b"\x55" * 8)
    stats = m.StatisticsImpl(level=3, exponent=3)
    check("wrapper: canonical slot runs the canonical body",
          stats.record_histogram_entry(3, 100, 8, seed) is True
          and stats.shards[0].records[3].count == 1)

    seen = []

    def override(stats_obj, hist_id, value, cpu_count, seed_obj):
        seen.append((hist_id, value))
        return "override"

    stats2 = m.StatisticsImpl(level=0, exponent=3)
    stats2.slot_d8 = override
    check("wrapper: override is called even at level 0",
          stats2.record_histogram_entry(3, 100, 8, seed) == "override"
          and seen == [(3, 100)])
    check("wrapper: override bypasses the canonical body",
          stats2.shards[0].records[3].count == 0)


def test_seed_fallback():
    # Picker unavailable (returns -1): the seed advances once per
    # record call and picks the shard.
    seed = m.ThreadSeed(b"\x66" * 8)
    before = seed.pointer()
    stats = m.StatisticsImpl(level=3, exponent=3)
    expect = m.mersenne_step(before)
    stats.record_ticker(1, 5, -1, seed)
    check("fallback: seed advanced by one mersenne step",
          seed.pointer() == expect)
    check("fallback: shard is the new seed masked by exp 3",
          stats.shards[expect & 7].tickers[1] == 5)
    expect2 = m.mersenne_step(expect)
    stats.record_histogram(2, 9, -1, seed)
    check("fallback: second call advances the seed again",
          seed.pointer() == expect2)
    check("fallback: histogram lands in the re-picked shard",
          stats.shards[expect2 & 7].records[2].count == 1)
    # The delegate's own pick advances the seed a second time.
    delegate = Delegate()
    stats2 = m.StatisticsImpl(level=3, exponent=3, delegate=delegate)
    seed2 = m.ThreadSeed(b"\x77" * 8)
    s0 = seed2.pointer()
    stats2.record_ticker(1, 5, -1, seed2)
    check("fallback: delegate pick advances the seed twice total",
          seed2.pointer() == m.mersenne_step(m.mersenne_step(s0)))


def test_boundaries():
    check("boundaries: 109 entries", len(m.BOUNDARIES) == 109)
    check("boundaries: first three are 1, 2, 3",
          m.BOUNDARIES[:3] == [1, 2, 3])
    check("boundaries: last is 13000000000000000000",
          m.BOUNDARIES[-1] == 13000000000000000000)
    check("bucket: value 100 lands in the 110 bucket",
          m.bucket_index(100) == m.BOUNDARIES.index(110))
    check("bucket: value 1 lands in bucket 0",
          m.bucket_index(1) == 0)


def main():
    test_picker()
    test_shard_pick()
    test_seed()
    test_ticker_record()
    test_ticker_delegate()
    test_histogram_record()
    test_histogram_delegate()
    test_histogram_wrapper()
    test_seed_fallback()
    test_boundaries()
    failed = [n for n, ok in CHECKS if not ok]
    print("checks: %d passed, %d failed" % (len(CHECKS) - len(failed),
                                            len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
