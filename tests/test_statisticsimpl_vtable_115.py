"""Tests for the node #115 StatisticsImpl vtable model.

Run directly (pytest is not installed on this VM):
    python3 tests/test_statisticsimpl_vtable_115.py

Every expectation is pinned to the binary behavior documented in
tools/statisticsimpl_vtable_115.py and the evidence packet
research/work-items/RE-001-statisticsimpl-vtable-115/.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import statisticsimpl_vtable_115 as m

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


# --- the 32-slot table matches the packet ---------------------------
check(len(m.SLOT_TARGETS) == 32, "32 vtable slots")
check(len(m.SLOT_ROLES) == 32, "32 slot roles")
check(m.SLOT_TARGETS[0x00] == 0x6070EA0, "slot 0x00 D1")
check(m.SLOT_TARGETS[0x08] == 0x6071040, "slot 0x08 D0")
check(m.SLOT_TARGETS[0x10] == 0x609D760, "slot 0x10 GetOption")
check(m.SLOT_TARGETS[0x18] == 0x609DC40, "slot 0x18 AreEquivalent")
check(m.SLOT_TARGETS[0x20] == 0x5D32560, "slot 0x20 empty string")
check(m.SLOT_TARGETS[0x28] == 0x6095E70, "slot 0x28 PrepareOptions")
check(m.SLOT_TARGETS[0x30] == 0x6096790, "slot 0x30 ValidateOptions")
check(m.SLOT_TARGETS[0x38] == 0x5D2E090, "slot 0x38 GetOptionsPtr")
check(m.SLOT_TARGETS[0x40] == 0x60956F0, "slot 0x40 empty Status")
check(m.SLOT_TARGETS[0x48] == 0x609D0E0, "slot 0x48 ConfigureOptions")
check(m.SLOT_TARGETS[0x50] == 0x60986B0, "slot 0x50 ParseOption")
check(m.SLOT_TARGETS[0x58] == 0x6095710, "slot 0x58 OptionsAreEqual")
check(m.SLOT_TARGETS[0x60] == 0x609DE80, "slot 0x60 SerializeOptions")
check(m.SLOT_TARGETS[0x68] == 0x609D980, "slot 0x68 GetOptionName")
check(m.SLOT_TARGETS[0x70] == 0x606FA20, "slot 0x70 Name")
check(m.SLOT_TARGETS[0x78] == 0x5D32A30, "slot 0x78 GetId")
check(m.SLOT_TARGETS[0x80] == 0x5D2E770, "slot 0x80 IsInstanceOf")
check(m.SLOT_TARGETS[0x88] == 0x606FA30, "slot 0x88 delegate getter")
check(m.SLOT_TARGETS[0x90] == 0x5D2CA10, "slot 0x90 NickName")
check(m.SLOT_TARGETS[0x98] == 0x6070490, "slot 0x98 locked read")
check(m.SLOT_TARGETS[0xA0] == 0x6070610, "slot 0xa0 percentiles")
check(m.SLOT_TARGETS[0xA8] == 0x6070700, "slot 0xa8 histogram text")
check(m.SLOT_TARGETS[0xB0] == 0x606FBA0, "slot 0xb0 record tick")
check(m.SLOT_TARGETS[0xB8] == 0x6070DC0, "slot 0xb8 set ticker")
check(m.SLOT_TARGETS[0xC0] == 0x6070C50, "slot 0xc0 get-and-reset")
check(m.SLOT_TARGETS[0xC8] == 0x5D48960, "slot 0xc8 forwarder")
check(m.SLOT_TARGETS[0xD0] == 0x606FFD0, "slot 0xd0 devirt twin")
check(m.SLOT_TARGETS[0xD8] == 0x606FEF0, "slot 0xd8 record histogram")
check(m.SLOT_TARGETS[0xE0] == 0x6070B30, "slot 0xe0 reset")
check(m.SLOT_TARGETS[0xE8] == 0x6070810, "slot 0xe8 ToString")
check(m.SLOT_TARGETS[0xF0] == 0x6076030, "slot 0xf0 ticker map")
check(m.SLOT_TARGETS[0xF8] == 0x606FA40, "slot 0xf8 hist check")
check(all(m.SLOT_ROLES[o] for o in m.SLOT_TARGETS),
      "every slot has a role")
check(m.VTABLE_STORED == 0x64D2D88, "stored vtable pointer")
check(m.VTABLE_BASE == 0x64D2D78, "Itanium vtable base")
check(m.TYPEINFO_NAME == "N7rocksdb14StatisticsImplE", "typeinfo name")
check(m.SIZEOF_STATISTICS_IMPL == 0x70, "sizeof is 0x70")
check(len(m.DISPATCH_SITES) == 32, "32 dispatch counts")
check(m.DISPATCH_SITES[0xC8] == 29, "slot 0xc8 dispatch count")
check(m.DISPATCH_SITES[0x98] == 241, "slot 0x98 dispatch count")
check(m.DISPATCH_SITES[0xA0] == 522, "slot 0xa0 dispatch count")
check(m.DISPATCH_SITES[0xB0] == 400, "slot 0xb0 dispatch count")
check(m.SHARED_SLOT_VTABLE_COUNTS[0x609D760] == 63, "GetOption shared")
check(m.SHARED_SLOT_VTABLE_COUNTS[0x6095E70] == 50,
      "PrepareOptions shared")
check(m.SHARED_SLOT_VTABLE_COUNTS[0x60956F0] == 68,
      "empty-Status shared")
check(m.SHARED_SLOT_VTABLE_COUNTS[0x5D2E770] == 44,
      "IsInstanceOf shared")

# --- identity slots (0x70/0x78/0x80/0x88/0x90/0xf8) ------------------
s = fresh()
check(s.name() == "BasicStatistics", "Name is BasicStatistics")
check(s.nickname() == "", "NickName is empty")
check(s.get_id() == "BasicStatistics", "GetId is the Name")
check(s.is_instance_of("BasicStatistics"), "IsInstanceOf(Name)")
check(s.is_instance_of(""), "IsInstanceOf(NickName)")
check(not s.is_instance_of("Statistics"), "IsInstanceOf(other)")
check(not s.is_instance_of("BasicStatisticsX"),
      "IsInstanceOf(wrong length)")
check(s.delegate_ptr() is None, "no delegate by default")
leaf = fresh()
check(fresh(delegate=leaf).delegate_ptr() is leaf, "delegate accessor")
check(m.StatisticsImpl.hist_id_valid(0), "hist id 0 valid")
check(m.StatisticsImpl.hist_id_valid(51), "hist id 51 valid")
check(not m.StatisticsImpl.hist_id_valid(52), "hist id 52 invalid")
check(not m.StatisticsImpl.hist_id_valid(200), "hist id 200 invalid")

# --- level inlines (non-virtual; ctor is the single writer) --------
s = fresh()
check(s.get_stats_level() == 3, "ctor writes level 3")
s.set_stats_level(1)
check(s.get_stats_level() == 1, "set/get level round trip")
s.set_stats_level(3)

# --- record tick end to end (slot 0xb0) ----------------------------
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.record_tick(3, 9, cpu=cpu(4))
check(total_ticker(s, 3) == 18, "ticks add across shards")
check(s.shards[0].tickers[3] == 9, "tick lands on shard 0")
check(s.shards[4].tickers[3] == 9, "tick lands on shard 4")
s_disabled = fresh(enabled=0)
s_disabled.record_tick(3, 5, cpu=cpu(0))
check(total_ticker(s_disabled, 3) == 0, "level 0 records nothing")
s_level1 = fresh(enabled=1)
s_level1.record_tick(3, 5, cpu=cpu(0))
check(total_ticker(s_level1, 3) == 5, "level 1 records ticks")
s.record_tick(178, 5, cpu=cpu(0))
check(total_ticker(s, 178) == 0, "ticker 178 is out of range")
leaf = fresh()
top = fresh(delegate=leaf)
top.record_tick(3, 7, cpu=cpu(0))
check(total_ticker(leaf, 3) == 7, "tick forwarded to delegate")
check(total_ticker(top, 3) == 7, "tick recorded locally too")

# --- measure time (slot 0xc8): level > 2 only ----------------------
s = fresh(enabled=3)
s.measure_time(2, 100, cpu=cpu(0))
check(total_hist_count(s, 2) == 1, "level 3 measures time")
s2 = fresh(enabled=2)
s2.measure_time(2, 100, cpu=cpu(0))
check(total_hist_count(s2, 2) == 0, "level 2 does not measure time")
s1 = fresh(enabled=1)
s1.measure_time(2, 100, cpu=cpu(0))
check(total_hist_count(s1, 2) == 0, "level 1 does not measure time")
leaf = fresh()
top = fresh(delegate=leaf)
top.measure_time(3, 50, cpu=cpu(0))
check(total_hist_count(leaf, 3) == 1, "measure time forwards")
top.measure_time(52, 50, cpu=cpu(0))
check(total_hist_count(leaf, 52) == 0, "hist 52 not forwarded")

# --- record histogram (slots 0xd8/0xd0) -----------------------------
s = fresh()
s.record_histogram(1, 42, cpu=cpu(0))
check(total_hist_count(s, 1) == 1, "histogram recorded")
s_disabled = fresh(enabled=1)
s_disabled.record_histogram(1, 42, cpu=cpu(0))
check(total_hist_count(s_disabled, 1) == 0,
      "level 1 records no histograms")


class OverridingStats(m.StatisticsImpl):
    """A subclass that overrides slot 0xd8 (record_histogram)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.overridden_calls = []

    def record_histogram(self, hist_id, value, cpu=None, seed=None):
        self.overridden_calls.append((hist_id, value))


ov = OverridingStats()
ov.record_histogram_devirt(4, 77, cpu=cpu(0))
check(ov.overridden_calls == [(4, 77)],
      "slot 0xd0 dispatches to the overriding slot 0xd8")
check(total_hist_count(ov, 4) == 0,
      "override replaces the base body")
s = fresh()
s.record_histogram_devirt(4, 77, cpu=cpu(0))
check(total_hist_count(s, 4) == 1,
      "slot 0xd0 inlines the base body when unoverridden")

# --- locked read / percentiles / text (slots 0x98/0xa0/0xa8) --------
s = fresh()
s.record_tick(5, 10, cpu=cpu(0))
s.record_tick(5, 20, cpu=cpu(2))
check(s.get_ticker_count(5) == 30, "locked read sums shards")
check(s.lock_depth == 0, "lock released after locked read")
s.record_histogram(1, 10, cpu=cpu(0))
s.record_histogram(1, 20, cpu=cpu(0))
s.record_histogram(1, 30, cpu=cpu(0))
data = s.get_histogram_data(1)
check(data["count"] == 3, "percentile struct count")
check(data["sum"] == 60, "percentile struct sum")
check(data["min"] == 10.0, "percentile struct min")
check(data["p100"] == 30.0, "percentile struct p100 is max")
check(data["average"] == 20.0, "percentile struct average")
check(s.lock_depth == 0, "lock released after percentiles")
text = s.get_histogram_string(1)
check("Count: 3" in text, "histogram text has the Count line")
check("Min: 10" in text, "histogram text has the Min line")
check("Percentiles:" in text, "histogram text has Percentiles")
check("---" in text, "histogram text has the dashes separator")
check(s.lock_depth == 0, "lock released after histogram text")
check(s.get_histogram_string(7).startswith("Count: 0"),
      "empty histogram renders a zero count")

# --- set / get-and-reset (slots 0xb8/0xc0) ---------------------------
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.record_tick(3, 9, cpu=cpu(4))
s.set_ticker(3, 5)
check(total_ticker(s, 3) == 5, "set ticker replaces the total")
check(s.shards[4].tickers[3] == 0, "set zeroes other shards")
leaf = fresh()
leaf.record_tick(3, 9, cpu=cpu(0))
top = fresh(delegate=leaf)
top.set_ticker(3, 4)
check(total_ticker(leaf, 3) == 4, "set forwards to delegate")
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.record_tick(3, 9, cpu=cpu(4))
check(s.get_and_reset_ticker(3) == 18, "get-and-reset returns the sum")
check(total_ticker(s, 3) == 0, "get-and-reset zeroes the counter")
leaf = fresh()
leaf.record_tick(3, 9, cpu=cpu(0))
top = fresh(delegate=leaf)
check(top.get_and_reset_ticker(3) == 0, "top sum is zero")
check(total_ticker(leaf, 3) == 0, "get-and-reset resets the delegate")

# --- reset (slot 0xe0) -----------------------------------------------
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.record_histogram(1, 42, cpu=cpu(0))
status = s.reset()
check(status.ok() and status.code == 0, "reset returns Status OK")
check(total_ticker(s, 3) == 0, "reset zeroes tickers")
check(total_hist_count(s, 1) == 0, "reset clears histograms")
check(s.lock_depth == 0, "lock released after reset")
leaf = fresh()
leaf.record_tick(3, 9, cpu=cpu(0))
top = fresh(delegate=leaf)
top.reset()
check(total_ticker(leaf, 3) == 9, "reset does not touch the delegate")

# --- ToString / ticker map (slots 0xe8/0xf0) -------------------------
s = fresh()
s.record_tick(0, 7, cpu=cpu(0))
s.record_tick(1, 3, cpu=cpu(0))
s.record_histogram(0, 100, cpu=cpu(0))
out = s.to_string(["tick.a", "tick.b"], ["hist.a"])
check("tick.a COUNT : 7\n" in out, "ToString ticker line")
check("tick.b COUNT : 3\n" in out, "ToString second ticker line")
check("hist.a P50 : " in out and "COUNT : 1 SUM : 100" in out,
      "ToString histogram line")
check(s.lock_depth == 0, "lock released after ToString")
mapt = s.get_ticker_map(["tick.a", "tick.b"])
check(mapt == {"tick.a": 7, "tick.b": 3}, "ticker map contents")
check(s.lock_depth == 0, "lock released after ticker map")

# --- destructors (slots 0x00/0x08) ------------------------------------
s = fresh()
s.record_tick(3, 9, cpu=cpu(0))
s.destroy()
check(s.destroyed, "D1 marks the object destroyed")
check(s.shards == [] and s.delegate is None, "D1 frees the store")
try:
    s.record_tick(3, 1, cpu=cpu(0))
    check(False, "use after destroy must raise")
except RuntimeError:
    check(True, "use after destroy raises")
s = fresh()
check(s.delete() == 0x70, "D0 sized delete is 0x70 bytes")
check(s.destroyed, "D0 runs D1 first")

# --- helpers: boundaries, seed, CPU pick ------------------------------
check(len(m.BOUNDARIES) == 109, "109 histogram boundaries")
check(m.BOUNDARIES[:2] == [1, 2], "boundary seeds 1, 2")
check(m.BOUNDARIES[-1] == m.U64_CEILING, "last boundary is the ceiling")
check(m.bucket_index(0) == 0, "bucket 0 for value 0")
check(m.bucket_index(1) == 0, "bucket 0 for value 1")
check(m.bucket_index(2) == 1, "bucket 1 for value 2")
check(m.bucket_index(m.U64_CEILING) == 108, "ceiling bucket is last")
seed = m.ThreadSeed(1)
check(seed.next_state() == 16807, "Park-Miller first step")
check(m.cpu_shard_pick(0, 0) == -1, "CPUID unavailable returns -1")
check(m.cpu_shard_pick(1, 5 << 24) == 5, "CPUID returns the APIC id")
seed_a = m.ThreadSeed.from_thread_id(b"\x01\x02\x03\x04\x05\x06\x07\x08")
seed_b = m.ThreadSeed.from_thread_id(b"\x01\x02\x03\x04\x05\x06\x07\x08")
check(seed_a.state == seed_b.state, "thread seed is deterministic")
check(1 <= seed_a.state <= m.PARK_MILLER_MOD - 1,
      "thread seed is in range")

print("%d checks passed" % CHECKS)
