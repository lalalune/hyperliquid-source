"""Tests for the node #115 StatisticsImpl write-side model.

Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_write_side_115.py

Every expectation is pinned to the binary behavior documented in
tools/stats_write_side_115.py and the evidence packet
research/work-items/RE-001-stats-write-side-115/.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stats_write_side_115 as m

CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError("check failed: " + label)


def cpu(apic):
    """A CPUID result for the given APIC id (leaf 0 max != 0)."""
    return (1, apic << 24)


def fresh(bits=3, delegate=None, enabled=3):
    return m.StatisticsImpl(shard_bits=bits, delegate=delegate,
                            enabled=enabled)


def total_ticker(stats, tid):
    return sum(s.tickers[tid] for s in stats.shards)


def total_hist_count(stats, hid):
    return sum(s.histograms[hid].count for s in stats.shards)


# --- boundaries (generator 0x606bf10) -------------------------------
b = m.BOUNDARIES
check(len(b) == 109, "109 boundaries")
check(b[0] == 1 and b[1] == 2, "seeds 1, 2")
check(b[:6] == [1, 2, 3, 4, 6, 10], "first six boundaries")
check(b[10] == 76 and b[11] == 110 and b[12] == 170, "truncated values")
check(b[20] == 4400, "b[20] == 4400")
check(b[50] == 850000000, "b[50]")
check(b[100] == 540000000000000000, "b[100]")
check(b[-1] == 13000000000000000000, "ceiling is the last boundary")
check(b == sorted(b) and len(set(b)) == len(b), "strictly increasing")
check(m.histogram_boundaries() == b, "generator is deterministic")

# --- bucket index (0x606afa0 lower_bound) ---------------------------
check(m.bucket_index(0) == 0, "bucket 0 -> 0")
check(m.bucket_index(1) == 0, "bucket 1 -> 0")
check(m.bucket_index(2) == 1, "bucket 2 -> 1")
check(m.bucket_index(3) == 2, "bucket 3 -> 2")
check(m.bucket_index(4) == 3, "bucket 4 -> 3")
check(m.bucket_index(5) == 4, "bucket 5 -> 4")
check(m.bucket_index(6) == 4, "bucket 6 -> 4")
check(m.bucket_index(10) == 5, "bucket 10 -> 5")
check(m.bucket_index(11) == 6, "bucket 11 -> 6")
check(m.bucket_index(110) == 11, "bucket 110 -> 11")
check(m.bucket_index(111) == 12, "bucket 111 -> 12")
check(m.bucket_index(13000000000000000000) == 108, "ceiling -> last")
check(m.bucket_index(2 ** 64 - 1) == 108, "above ceiling -> last")

# --- CPU shard pick (0x60d5cd0) --------------------------------------
check(m.cpu_shard_pick(0, 0) == -1, "CPUID unavailable -> -1")
check(m.cpu_shard_pick(1, 0) == 0, "APIC 0")
check(m.cpu_shard_pick(1, 2 << 24) == 2, "APIC 2")
check(m.cpu_shard_pick(1, 0xFF000000) == 255, "APIC 255")
check(m.cpu_shard_pick(1, 0x01FFFFFF) == 1, "only EBX[31:24] counts")

# --- Park-Miller LCG (0x61c4080 fallback) ----------------------------
seed = m.ThreadSeed(1)
check([seed.next_state() for _ in range(5)] == [
    16807, 282475249, 1622650073, 984943658, 1144108930],
    "Park-Miller sequence from seed 1")
seed = m.ThreadSeed(0x7FFFFFFE)
check(seed.next_state() == (0x7FFFFFFE * 16807) % 0x7FFFFFFF,
      "LCG reduction matches modular arithmetic")
import random
rng = random.Random(20261106)
for _ in range(20):
    s = rng.randrange(1, 0x7FFFFFFF)
    seed = m.ThreadSeed(s)
    check(seed.next_state() == (s * 16807) % 0x7FFFFFFF,
          "LCG reduction matches mod for random state " + str(s))
seed = m.ThreadSeed.from_thread_id(b"\x01\x02\x03\x04\x05\x06\x07\x08")
check(1 <= seed.state <= 0x7FFFFFFE, "seeded state is in range")
check(m.ThreadSeed.from_thread_id(b"\x01\x02\x03\x04\x05\x06\x07\x08").state
      == seed.state, "thread seed is deterministic")
check(m._hash_bytes(b"abcdefgh", 0xC70F6907)
      == m._hash_bytes(b"abcdefgh", 0xC70F6907), "hash is deterministic")
check(m._hash_bytes(b"abcdefgh", 0xC70F6907)
      != m._hash_bytes(b"abcdefgi", 0xC70F6907),
      "hash changes with the input")
check(0 <= m._hash_bytes(b"abcdefgh", 0xC70F6907) <= m.MASK64,
      "hash stays in 64 bits")

# --- record_tick gates (slot 0xb0) -----------------------------------
s = fresh()
s.record_tick(5, 7, cpu=cpu(0))
check(total_ticker(s, 5) == 7, "tick lands on the picked shard")
check(s.shards[0].tickers[5] == 7, "CPU 0 -> shard 0")
check(s.shards[1].tickers[5] == 0, "other shards untouched")
s.record_tick(5, 3, cpu=cpu(0))
check(total_ticker(s, 5) == 10, "lock-add accumulates")
s.record_tick(5, 1, cpu=cpu(1))
check(s.shards[1].tickers[5] == 1, "CPU 1 -> shard 1 with 3 bits")
check(total_ticker(s, 5) == 11, "total across shards")
s2 = fresh(bits=2)
s2.record_tick(9, 4, cpu=cpu(5))
check(s2.shards[1].tickers[9] == 4, "APIC 5 & mask 3 -> shard 1")
s3 = fresh(enabled=0)
s3.record_tick(5, 7, cpu=cpu(0))
check(total_ticker(s3, 5) == 0, "enabled 0 records nothing")
s4 = fresh(enabled=1)
s4.record_tick(5, 7, cpu=cpu(0))
check(total_ticker(s4, 5) == 7, "enabled 1 still records ticks")
s.record_tick(178, 7, cpu=cpu(0))
check(total_ticker(s, 178) == 0, "ticker id 178 is out of range")
s.record_tick(177, 7, cpu=cpu(0))
check(total_ticker(s, 177) == 7, "ticker id 177 is the last valid one")

# --- LCG fallback shard pick -----------------------------------------
seed = m.ThreadSeed(1)
s5 = fresh()
s5.record_tick(3, 5, cpu=(0, 0), seed=seed)  # CPUID unavailable
check(seed.state == 16807, "fallback consumes one LCG step")
check(total_ticker(s5, 3) == 5, "fallback tick lands somewhere")
check(s5.shards[16807 & 7].tickers[3] == 5, "fallback shard is 16807 & 7")
seed = m.ThreadSeed(1)
s6 = fresh()
s6.record_tick(3, 5, cpu=(0, 0), seed=seed)
s6.record_tick(3, 5, cpu=(0, 0), seed=seed)
check(seed.state == 282475249, "second fallback advances the seed again")
check(total_ticker(s6, 3) == 10, "both fallback ticks recorded")

# --- delegate chain forwarding (slot 0xb0) ---------------------------
leaf = fresh()
mid = fresh(delegate=leaf)
top = fresh(delegate=mid)
top.record_tick(5, 7, cpu=cpu(0))
for obj in (top, mid, leaf):
    check(obj.shards[0].tickers[5] == 7, "tick forwarded down the chain")
check(top.lock_acquisitions == 0, "record_tick takes no lock")
top.record_tick(5, 7, cpu=cpu(0))
check(total_ticker(leaf, 5) == 14, "chain forwards every tick")
dead = fresh(enabled=0)
live = fresh(delegate=dead)
live.record_tick(5, 7, cpu=cpu(0))
check(total_ticker(dead, 5) == 0, "disabled delegate records nothing")
check(total_ticker(live, 5) == 7, "live level still records")

# --- set_core / set_ticker (0x6070ac0, slot 0xb8) --------------------
s = fresh()
for i in range(8):
    s.record_tick(5, 10, cpu=cpu(i))
check(total_ticker(s, 5) == 80, "spread over 8 shards first")
s.set_ticker(5, 42)
check(s.shards[0].tickers[5] == 42, "set lands on shard 0")
check(all(sh.tickers[5] == 0 for sh in s.shards[1:]),
      "set zeroes the other shards")
check(total_ticker(s, 5) == 42, "set total is the new value")
s.record_tick(5, 8, cpu=cpu(3))
check(s.shards[3].tickers[5] == 8, "record after set adds on shard 3")
check(total_ticker(s, 5) == 50, "set then add")
s.set_ticker(6, 9)
check(total_ticker(s, 5) == 50, "set of another id leaves id 5 alone")
check(s.lock_depth == 0, "lock released after set_ticker")
check(s.lock_acquisitions == 2, "two set_ticker calls took two locks")
leaf = fresh()
for i in range(8):
    leaf.record_tick(5, 1, cpu=cpu(i))
top = fresh(delegate=leaf)
top.set_ticker(5, 3)
check(total_ticker(top, 5) == 3, "set forwards: top set")
check(total_ticker(leaf, 5) == 3, "set forwards: delegate set to 0 then 3")
check(leaf.lock_acquisitions == 1, "delegate set took its own lock")
s.set_ticker(178, 11)
check(s.shards[0].tickers[178] == 11, "set_core accepts the capacity slot")
check(s.shards[0].tickers[177] == 0, "capacity slot is distinct")

# --- get_and_reset_ticker (slot 0xc0) --------------------------------
s = fresh()
s.record_tick(7, 5, cpu=cpu(0))
s.record_tick(7, 6, cpu=cpu(1))
s.record_tick(7, 7, cpu=cpu(2))
check(s.get_and_reset_ticker(7) == 18, "get-and-reset returns the sum")
check(total_ticker(s, 7) == 0, "all shards zeroed")
check(s.get_and_reset_ticker(7) == 0, "second get-and-reset is 0")
check(s.lock_depth == 0, "lock released after get-and-reset")
leaf = fresh()
leaf.record_tick(7, 4, cpu=cpu(0))
leaf.record_tick(7, 4, cpu=cpu(1))
top = fresh(delegate=leaf)
top.record_tick(7, 1, cpu=cpu(0))
check(top.get_and_reset_ticker(7) == 1, "top sum only counts the top")
check(total_ticker(leaf, 7) == 0, "delegate chain was reset too")
check(total_ticker(top, 7) == 0, "top zeroed")

# --- record_histogram gates and record (slots 0xd8/0xd0) -------------
s = fresh(enabled=1)
s.record_histogram(2, 100, cpu=cpu(0))
check(total_hist_count(s, 2) == 0, "enabled 1 records no histograms")
s = fresh(enabled=2)
s.record_histogram(2, 100, cpu=cpu(0))
rec = s.shards[0].histograms[2]
check(rec.count == 1 and rec.total == 100, "histogram record counted")
check(rec.minimum == 100 and rec.maximum == 100, "min/max set")
check(rec.buckets[m.bucket_index(100)] == 1, "value in the right bucket")
s.record_histogram(2, 50, cpu=cpu(0))
check(rec.count == 2 and rec.total == 150, "second record accumulates")
check(rec.minimum == 50 and rec.maximum == 100, "min/max track")
check(rec.total_sq == 100 * 100 + 50 * 50, "sum of squares")
s.record_histogram(2, 200, cpu=cpu(1))
check(s.shards[1].histograms[2].count == 1, "CPU 1 -> shard 1 record")
s.record_histogram(52, 10, cpu=cpu(0))
check(s.shards[0].histograms[52].count == 1, "hist id 52 records locally")
leaf = fresh()
top = fresh(delegate=leaf)
top.record_histogram(51, 10, cpu=cpu(0))
check(total_hist_count(top, 51) == 1, "hist 51 recorded on top")
check(total_hist_count(leaf, 51) == 1, "hist 51 forwarded to delegate")
top.record_histogram(52, 10, cpu=cpu(0))
check(total_hist_count(leaf, 52) == 0, "hist 52 is not forwarded")
seed = m.ThreadSeed(1)
s = fresh()
s.record_histogram(2, 100, cpu=(0, 0), seed=seed)
check(seed.state == 16807, "hist fallback consumes one LCG step")
check(s.shards[16807 & 7].histograms[2].count == 1, "hist fallback shard")

# --- histogram record init (slots 0x10/0x20 helpers) -----------------
rec = m.HistogramRecord()
check(rec.minimum == m.U64_CEILING and rec.maximum == 0,
      "fresh record starts at ceiling/0")
check(rec.count == 0 and rec.total == 0 and rec.total_sq == 0,
      "fresh record is empty")
check(all(v == 0 for v in rec.buckets), "fresh buckets are zero")
rec.record(5)
rec.record(5000)
check(rec.minimum == 5 and rec.maximum == 5000, "record min/max")
check(rec.count == 2, "record count")
rec.locked_init()
check(rec.minimum == m.U64_CEILING and rec.count == 0,
      "locked init clears the record")
check(all(v == 0 for v in rec.buckets), "locked init clears buckets")

# --- reset (slot 0xe0) ------------------------------------------------
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.record_tick(3, 9, cpu=cpu(4))
s.record_histogram(1, 42, cpu=cpu(0))
s.record_histogram(1, 43, cpu=cpu(2))
status = s.reset()
check(status.ok() and status.code == 0, "reset returns Status OK")
check(total_ticker(s, 3) == 0, "reset zeroes tickers")
check(total_hist_count(s, 1) == 0, "reset clears histograms")
check(s.shards[0].histograms[1].minimum == m.U64_CEILING,
      "reset restores the ceiling min")
check(s.lock_depth == 0, "lock released after reset")
leaf = fresh()
leaf.record_tick(3, 9, cpu=cpu(0))
top = fresh(delegate=leaf)
top.reset()
check(total_ticker(leaf, 3) == 9, "reset does not touch the delegate")
check(top.enabled == 3, "reset does not change the enable byte")
s_disabled = fresh(enabled=0)
s_disabled.record_tick(3, 5, cpu=cpu(0))
check(s_disabled.reset().ok(), "reset works while disabled")

# --- accessors (slots 0x70/0x88/0xf8) ----------------------------------
s = fresh()
check(s.name() == "BasicStatistics", "name accessor")
check(s.delegate_ptr() is None, "no delegate by default")
leaf = fresh()
check(fresh(delegate=leaf).delegate_ptr() is leaf, "delegate accessor")
check(m.StatisticsImpl.hist_id_valid(0), "hist id 0 valid")
check(m.StatisticsImpl.hist_id_valid(51), "hist id 51 valid")
check(not m.StatisticsImpl.hist_id_valid(52), "hist id 52 invalid")
check(not m.StatisticsImpl.hist_id_valid(200), "hist id 200 invalid")

# --- model tables match the packet ------------------------------------
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xB0] == 0x606FBA0, "slot 0xb0")
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xB8] == 0x6070DC0, "slot 0xb8")
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xC0] == 0x6070C50, "slot 0xc0")
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xD0] == 0x606FFD0, "slot 0xd0")
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xD8] == 0x606FEF0, "slot 0xd8")
check(m.STATISTICS_IMPL_VTABLE_SLOTS[0xE0] == 0x6070B30, "slot 0xe0")
check(len(m.STATISTICS_IMPL_VTABLE_SLOTS) == 32, "32 vtable slots")
check(m.DISPATCH_SITES == {0xB0: 400, 0xB8: 36, 0xC0: 42,
                           0xD0: 14, 0xD8: 48, 0xE0: 31},
      "dispatch site counts")

print("%d checks passed" % CHECKS)
