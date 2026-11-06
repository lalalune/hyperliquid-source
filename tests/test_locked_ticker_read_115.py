"""Tests for tools/locked_ticker_read_115.py (node #115 StatisticsImpl
locked read accessors: vtable slots 0x98/0xa0/0xa8).

Run directly (pytest is not installed on this VM):
    python3 tests/test_locked_ticker_read_115.py

Every expected value below is hand-computed from the binary's
constants and control flow (see the RE-001-locked-ticker-read-115
packet); the only computed inputs are the boundary list itself,
which the generator test pins at spot indices.
"""

import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from locked_ticker_read_115 import (  # noqa: E402
    BOUNDARIES, BUCKET_COUNT, BUCKET_FORMAT, CEILING, COUNT_FORMAT,
    DASHES, DISPATCH_SITES, FOLLOWING_VTABLES, HISTOGRAM_BASE,
    HISTOGRAM_SIZE, LOCKED_HISTOGRAM_TEXT, LOCKED_PERCENTILES,
    LOCKED_TICKER_READ, MIN_MAX_FORMAT, MUTEX_LOCK, MUTEX_UNLOCK,
    PERCENTILES_FORMAT, SHARD_SIZE, STATISTICS_IMPL_TYPEINFO_NAME,
    STATISTICS_IMPL_VTABLE_SLOTS, STATISTICS_TYPEINFO_NAME,
    TICKER_GETTER, TICKER_MAX, Histogram, MutexError, Statistics,
    bucket_index, generate_boundaries, u64_to_f64,
)

CHECKS = 0
FAILURES = []


def check(name, got, want):
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILURES.append("%s: got %r, want %r" % (name, got, want))


def check_close(name, got, want, tol=1e-12):
    global CHECKS
    CHECKS += 1
    if abs(got - want) > tol:
        FAILURES.append("%s: got %r, want %r" % (name, got, want))


def check_raises(name, fn, exc):
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except exc:
        return
    except Exception as other:  # noqa: BLE001
        FAILURES.append("%s: raised %r, want %r" % (name, other, exc))
        return
    FAILURES.append("%s: no exception, want %r" % (name, exc))


def make_stats():
    """Two shards; shard 0 counters {0: 3, 1: 10}, shard 1
    counters {0: 4, 2: 7}; histogram 0 merged from [1,2,3] on
    shard 0 and [4,5] on shard 1; histogram 1 has [100] on
    shard 1 only."""
    stats = Statistics(shard_bits=1)
    stats.set_ticker(0, 0, 3)
    stats.set_ticker(0, 1, 10)
    stats.set_ticker(1, 0, 4)
    stats.set_ticker(1, 2, 7)
    h0 = Histogram()
    for value in (1, 2, 3):
        h0.add(value)
    stats.set_histogram(0, 0, h0)
    h1 = Histogram()
    for value in (4, 5):
        h1.add(value)
    stats.set_histogram(1, 0, h1)
    h2 = Histogram()
    h2.add(100)
    stats.set_histogram(1, 1, h2)
    return stats


# --- Boundaries and bucket index (from #3371's pinned generator) ---
check("boundary count", BUCKET_COUNT, 109)
check("boundaries == generator", BOUNDARIES, generate_boundaries())
check("boundaries[0]", BOUNDARIES[0], 1)
check("boundaries[1]", BOUNDARIES[1], 2)
check("boundaries[2]", BOUNDARIES[2], 3)
check("boundaries[3]", BOUNDARIES[3], 4)
check("boundaries[4]", BOUNDARIES[4], 6)
check("boundaries[100]", BOUNDARIES[100], 540000000000000000)
check("boundaries[-1] == ceiling", BOUNDARIES[-1], 13000000000000000000)
check("ceiling", CEILING, 13000000000000000000)
check("bucket_index(1)", bucket_index(1), 0)
check("bucket_index(2)", bucket_index(2), 1)
check("bucket_index(3)", bucket_index(3), 2)
check("bucket_index(5)", bucket_index(5), 4)
check("bucket_index(ceiling)", bucket_index(CEILING), 108)
check("bucket_index(above ceiling)", bucket_index(CEILING + 5), 108)
check("u64_to_f64 small", u64_to_f64(7), 7.0)
check("u64_to_f64 2**63", u64_to_f64(1 << 63), float(1 << 63))

# --- Vtable: 32 slots, the three locked reads, neighbours ---
check("vtable slot count", len(STATISTICS_IMPL_VTABLE_SLOTS), 32)
check("slot 0x98 locked ticker read",
      STATISTICS_IMPL_VTABLE_SLOTS[0x98], LOCKED_TICKER_READ)
check("slot 0xa0 locked percentiles",
      STATISTICS_IMPL_VTABLE_SLOTS[0xA0], LOCKED_PERCENTILES)
check("slot 0xa8 locked histogram text",
      STATISTICS_IMPL_VTABLE_SLOTS[0xA8], LOCKED_HISTOGRAM_TEXT)
check("slot 0x98 address", LOCKED_TICKER_READ, 0x6070490)
check("slot 0xa0 address", LOCKED_PERCENTILES, 0x6070610)
check("slot 0xa8 address", LOCKED_HISTOGRAM_TEXT, 0x6070700)
check("slot 0xe8 ToString", STATISTICS_IMPL_VTABLE_SLOTS[0xE8], 0x6070810)
check("slot 0xf0 ticker-map fill",
      STATISTICS_IMPL_VTABLE_SLOTS[0xF0], 0x6076030)
check("slot 0xb0 record", STATISTICS_IMPL_VTABLE_SLOTS[0xB0], 0x606FBA0)
check("slot 0x00 dtor", STATISTICS_IMPL_VTABLE_SLOTS[0x00], 0x6070EA0)
check("slot 0x08 deleting dtor",
      STATISTICS_IMPL_VTABLE_SLOTS[0x08], 0x6071040)
check("typeinfo name", STATISTICS_IMPL_TYPEINFO_NAME,
      "N7rocksdb14StatisticsImplE")
check("base typeinfo name", STATISTICS_TYPEINFO_NAME,
      "N7rocksdb10StatisticsE")
check("mutex lock", MUTEX_LOCK, 0x60D5230)
check("mutex unlock", MUTEX_UNLOCK, 0x60D52F0)
check("ticker getter", TICKER_GETTER, 0x6070430)
check("dispatch slot 0x98", DISPATCH_SITES[0x98], 241)
check("dispatch slot 0xa0", DISPATCH_SITES[0xA0], 522)
check("dispatch slot 0xa8", DISPATCH_SITES[0xA8], 54)
check("following vtable count", len(FOLLOWING_VTABLES), 3)
check("FactoryEntry vtable", 0x64D2E98 in FOLLOWING_VTABLES, True)
check("FactoryEntry typeinfo",
      FOLLOWING_VTABLES[0x64D2E98][0],
      "N7rocksdb13ObjectLibrary12FactoryEntryINS_10StatisticsEEE")

# --- Shard layout constants ---
check("histogram records end", HISTOGRAM_BASE + 53 * HISTOGRAM_SIZE, 0xCE00)
check("shard tail", SHARD_SIZE - 0xCE00, 0x40)
check("counter slots per shard", HISTOGRAM_BASE // 8, 179)
check("ticker max below counter slots", TICKER_MAX < 179, True)

# --- Ticker getter: shard sums ---
stats = make_stats()
check("getter ticker 0 over 2 shards", stats.ticker_getter(0), 7)
check("getter ticker 1 (shard 0 only)", stats.ticker_getter(1), 10)
check("getter ticker 2 (shard 1 only)", stats.ticker_getter(2), 7)
check("getter missing ticker", stats.ticker_getter(9), 0)
check("getter u32 index mask",
      stats.ticker_getter(0x100000000 + 0), stats.ticker_getter(0))
single = Statistics(shard_bits=0)
single.set_ticker(0, 3, 5)
check("getter single shard", single.ticker_getter(3), 5)
wrap = Statistics(shard_bits=1)
wrap.set_ticker(0, 0, (1 << 64) - 1)
wrap.set_ticker(1, 0, 1)
check("getter wraps u64", wrap.ticker_getter(0), 0)

# --- Locked ticker read: value, lock discipline ---
stats = make_stats()
check("locked read ticker 0", stats.locked_ticker_read(0), 7)
check("locked read ticker 1", stats.locked_ticker_read(1), 10)
check("mutex free after reads", stats._locked, False)
check("lock events pair up",
      stats.lock_events,
      [("lock", "locked_ticker_read"), ("unlock", "locked_ticker_read"),
       ("lock", "locked_ticker_read"), ("unlock", "locked_ticker_read")])
check("locked read again after unlock", stats.locked_ticker_read(0), 7)


class FailingGetter(Statistics):
    def ticker_getter(self, index):
        raise RuntimeError("boom")


failing = FailingGetter(shard_bits=0)
check_raises("locked read propagates getter error",
              lambda: failing.locked_ticker_read(0), RuntimeError)
check("mutex unlocked after getter error", failing._locked, False)
check("lock events after getter error",
      failing.lock_events,
      [("lock", "locked_ticker_read"), ("unlock", "locked_ticker_read")])


class ReentrantGetter(Statistics):
    def ticker_getter(self, index):
        return self.locked_ticker_read(index)


reentrant = ReentrantGetter(shard_bits=0)
check_raises("double lock refused",
              lambda: reentrant.locked_ticker_read(0), MutexError)
check("mutex free after double-lock refusal", reentrant._locked, False)

# --- Histogram builder: per-shard merge ---
stats = make_stats()
merged = stats.build_histogram(0)
check("merged count", merged.count, 5)
check("merged sum", merged.sum, 15)
check("merged min", merged.min, 1)
check("merged max", merged.max, 5)
check("merged buckets 0..4", merged.buckets[:5], [1, 1, 1, 1, 1])
check("merged bucket 5 empty", merged.buckets[5], 0)
check("merged temp not destroyed by build", merged.destroyed, False)
other = stats.build_histogram(1)
check("other histogram independent count", other.count, 1)
check("other histogram value", other.sum, 100)
check("other histogram min", other.min, 100)
empty = stats.build_histogram(7)
check("missing histogram is empty", empty.count, 0)
check("missing histogram min is ceiling", empty.min, CEILING)

# --- Locked percentiles: the 9-field struct, end to end ---
stats = make_stats()
out = stats.locked_percentiles(0)
check("percentiles p50", out["p50"], 2.5)
check("percentiles p95", out["p95"], 5.0)
check("percentiles p99", out["p99"], 5.0)
check_close("percentiles average", out["average"], 3.0)
check_close("percentiles stddev", out["stddev"], math.sqrt(2.0))
check("percentiles p100", out["p100"], 5.0)
check("percentiles count", out["count"], 5)
check("percentiles sum", out["sum"], 15)
check("percentiles min", out["min"], 1.0)
check("percentiles temp destroyed once", stats.destroyed_temps, 1)
check("mutex free after percentiles", stats._locked, False)
check("percentiles lock events",
      stats.lock_events,
      [("lock", "locked_percentiles"), ("unlock", "locked_percentiles")])
empty_out = stats.locked_percentiles(7)
check("empty percentiles count", empty_out["count"], 0)
check("empty percentiles average", empty_out["average"], 0.0)
check("empty percentiles stddev", empty_out["stddev"], 0.0)


class FailingStruct(Statistics):
    def build_histogram(self, hist_id):
        hist = super().build_histogram(hist_id)
        orig = hist.percentile_struct

        def boom():
            raise RuntimeError("struct boom")
        hist.percentile_struct = boom
        return hist


failing_struct = FailingStruct(shard_bits=0)
check_raises("percentiles propagate delegate error",
              lambda: failing_struct.locked_percentiles(0), RuntimeError)
check("temp destroyed after delegate error",
      failing_struct.destroyed_temps, 1)
check("mutex unlocked after delegate error", failing_struct._locked, False)


class FailingBuild(Statistics):
    def build_histogram(self, hist_id):
        raise RuntimeError("build boom")


failing_build = FailingBuild(shard_bits=0)
check_raises("percentiles propagate build error",
              lambda: failing_build.locked_percentiles(0), RuntimeError)
check("no temp destroyed when build fails",
      failing_build.destroyed_temps, 0)
check("mutex unlocked after build error", failing_build._locked, False)

# --- Locked histogram text: the rendered form, end to end ---
stats = make_stats()
text = stats.locked_histogram_text(0)
lines = text.splitlines(keepends=True)
check("render count line", lines[0],
      COUNT_FORMAT % (5, 3.0, math.sqrt(2.0)))
check("render min line", lines[1],
      MIN_MAX_FORMAT % (1, 2.5, 5))
check("render percentiles line", lines[2],
      PERCENTILES_FORMAT % (2.5, 3.75, 5.0, 5.0, 5.0))
check("render dashes line", lines[3], DASHES)
check("render bucket row count", len(lines) - 4, 5)
check("render bucket row 0",
      lines[4], BUCKET_FORMAT % ("[", 0, 1, 1, 20.0, 20.0) + "#" * 4 + "\n")
check("render bucket row 1",
      lines[5], BUCKET_FORMAT % ("(", 1, 2, 1, 20.0, 40.0) + "#" * 4 + "\n")
check("render bucket row 4",
      lines[8], BUCKET_FORMAT % ("(", 4, 6, 1, 20.0, 100.0) + "#" * 4 + "\n")
check("render temp destroyed once", stats.destroyed_temps, 1)
check("mutex free after render", stats._locked, False)
check("render lock events",
      stats.lock_events,
      [("lock", "locked_histogram_text"),
       ("unlock", "locked_histogram_text")])
empty_text = stats.locked_histogram_text(7)
check("empty render has 4 lines", len(empty_text.splitlines()), 4)
check("empty render min line",
      empty_text.splitlines()[1],
      (MIN_MAX_FORMAT % (0, 0.0, 0)).rstrip("\n"))


class FailingRender(Statistics):
    def build_histogram(self, hist_id):
        hist = super().build_histogram(hist_id)
        orig = hist.render

        def boom():
            raise RuntimeError("render boom")
        hist.render = boom
        return hist


failing_render = FailingRender(shard_bits=0)
check_raises("render propagates delegate error",
              lambda: failing_render.locked_histogram_text(0), RuntimeError)
check("temp destroyed after render error",
      failing_render.destroyed_temps, 1)
check("mutex unlocked after render error", failing_render._locked, False)

print("%d checks, %d failed" % (CHECKS, len(FAILURES)))
for failure in FAILURES:
    print("FAIL: " + failure)
sys.exit(1 if FAILURES else 0)
