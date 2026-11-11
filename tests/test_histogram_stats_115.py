"""Tests for tools/histogram_stats_115.py (node #115 HistogramImpl).

Run directly (pytest is not installed on this VM):
    python3 tests/test_histogram_stats_115.py

Every expected value below is hand-computed from the binary's
constants and control flow (see the RE-001-histogram-stats-
family-115 packet); the only computed inputs are the boundary
list itself, which the generator test pins at spot indices.
"""

import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from histogram_stats_115 import (  # noqa: E402
    BOUNDARIES, BUCKET_COUNT, CEILING, FIRST_BOUNDARY, Histogram,
    _truncate_boundary, bucket_index, generate_boundaries,
    u64_to_f64,
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


def spread():
    """Histogram with values [1, 2, 6]: buckets 0, 1, 4."""
    hist = Histogram()
    for value in (1, 2, 6):
        hist.add(value)
    return hist


def main():
    # --- boundary generator (0x606bf10) ---
    check("boundary count", BUCKET_COUNT, 109)
    check("buckets end at count field",
          0x28 + BUCKET_COUNT * 8, 0x390)
    check("first boundary", FIRST_BOUNDARY, 1)
    check("last boundary", CEILING, 13000000000000000000)
    check("seed prefix", BOUNDARIES[:12],
          [1, 2, 3, 4, 6, 10, 15, 22, 34, 51, 76, 110])
    check("spot boundaries 12..19", BOUNDARIES[12:20],
          [170, 250, 380, 580, 870, 1300, 1900, 2900])
    check("spot boundary 20", BOUNDARIES[20], 4400)
    check("spot boundary 100", BOUNDARIES[100], 540000000000000000)
    check("boundaries strictly increasing",
          all(b > a for a, b in zip(BOUNDARIES, BOUNDARIES[1:])), True)
    check("generator is deterministic",
          generate_boundaries(), BOUNDARIES)
    # Every generated boundary survives its own rounding step.
    check("rounding is idempotent",
          all(_truncate_boundary(b) == b for b in BOUNDARIES), True)
    check("rounding keeps small values", _truncate_boundary(109), 109)
    check("rounding 115 -> 110", _truncate_boundary(115), 110)
    check("rounding 1099 -> 1090", _truncate_boundary(1099), 1090)
    check("rounding 1234 -> 1200", _truncate_boundary(1234), 1200)
    check("rounding 108000000000000 stays",
          _truncate_boundary(108000000000000), 108000000000000)

    # --- unsigned double conversion (0x606b3c0-style fixup) ---
    check("u64_to_f64(0)", u64_to_f64(0), 0.0)
    check("u64_to_f64(2**63)", u64_to_f64(1 << 63), 9.223372036854776e18)
    check("u64_to_f64(2**64-1)", u64_to_f64((1 << 64) - 1),
          1.8446744073709552e19)

    # --- bucket index (0x606afa0) ---
    for value, want in ((0, 0), (1, 0), (2, 1), (3, 2), (4, 3),
                        (5, 4), (6, 4), (7, 5), (10, 5), (11, 6),
                        (109, 11), (110, 11), (111, 12),
                        (13000000000000000000, 108),
                        ((1 << 64) - 1, 108)):
        check("bucket_index(%d)" % value, bucket_index(value), want)

    # --- empty histogram ---
    empty = Histogram()
    check("empty is_empty", empty.is_empty(), True)
    check("empty min is ceiling", empty.min, CEILING)
    check("empty max", empty.max, 0)
    check("empty count", empty.count, 0)
    check("empty name", empty.name(), "HistogramImpl")
    check("empty average", empty.average(), 0.0)
    check("empty stddev", empty.stddev(), 0.0)
    check("empty median", empty.median(), 0.0)
    check("empty percentile(95)", empty.percentile(95.0), 0.0)
    check("empty render", empty.render(),
          "Count: 0 Average: 0.0000  StdDev: 0.00\n"
          "Min: 0  Median: 0.0000  Max: 0\n"
          "Percentiles: P50: 0.00 P75: 0.00 P99: 0.00 "
          "P99.9: 0.00 P99.99: 0.00\n"
          "------------------------------------------------------\n")

    # --- spread histogram [1, 2, 6] ---
    hist = spread()
    check("spread is_empty", hist.is_empty(), False)
    check("spread min", hist.min, 1)
    check("spread max", hist.max, 6)
    check("spread count", hist.count, 3)
    check("spread sum", hist.sum, 9)
    check("spread sum_sq", hist.sum_sq, 41)
    check("spread buckets", [hist.buckets[i] for i in (0, 1, 4)],
          [1, 1, 1])
    check("spread other buckets zero",
          sum(hist.buckets) - 3, 0)
    check_close("spread average", hist.average(), 3.0)
    check_close("spread stddev", hist.stddev(), 2.160246899469287)
    check("spread median", hist.median(), 1.5)
    check("spread p0 clamps to min", hist.percentile(0.0), 1.0)
    # threshold 0.75 lands in bucket 0 -> 0.75, clamped up to min 1.0.
    check("spread p25 clamps to min", hist.percentile(25.0), 1.0)
    check_close("spread p75", hist.percentile(75.0), 4.5)
    check_close("spread p90", hist.percentile(90.0), 5.4)
    check_close("spread p95", hist.percentile(95.0), 5.7)
    check_close("spread p99", hist.percentile(99.0), 5.94)
    check("spread p100", hist.percentile(100.0), 6.0)
    check("spread p100+ returns max", hist.percentile(150.0), 6.0)
    struct = hist.percentile_struct()
    check("struct p50", struct["p50"], 1.5)
    check_close("struct p95", struct["p95"], 5.7)
    check_close("struct p99", struct["p99"], 5.94)
    check_close("struct average", struct["average"], 3.0)
    check_close("struct stddev", struct["stddev"], 2.160246899469287)
    check("struct p100", struct["p100"], 6.0)
    check("struct count", struct["count"], 3)
    check("struct sum", struct["sum"], 9)
    check("struct min", struct["min"], 1.0)
    check("spread render", hist.render(),
          "Count: 3 Average: 3.0000  StdDev: 2.16\n"
          "Min: 1  Median: 1.5000  Max: 6\n"
          "Percentiles: P50: 1.50 P75: 4.50 P99: 5.94 "
          "P99.9: 5.99 P99.99: 6.00\n"
          "------------------------------------------------------\n"
          "[       0,       1 ]        1  33.333%  33.333% #######\n"
          "(       1,       2 ]        1  33.333%  66.667% #######\n"
          "(       4,       6 ]        1  33.333% 100.000% #######\n")

    # --- single-bucket interpolation (0x606b260) ---
    single = Histogram()
    for _ in range(10):
        single.add(5)
    check("single bucket", single.buckets[4], 10)
    # 4.5 before the clamp, then clamped into [min, max] = [5, 5].
    check("single p25 clamps to min", single.percentile(25.0), 5.0)
    check("single p50", single.percentile(50.0), 5.0)
    check("single p95 clamps to max", single.percentile(95.0), 5.0)
    check("single average", single.average(), 5.0)
    check("single stddev", single.stddev(), 0.0)

    # --- merge (0x606be40 + 0x606b1d0) ---
    other = Histogram()
    for value in (6, 100):
        other.add(value)
    check("merge returns True", hist.merge(other), True)
    check("merged count", hist.count, 5)
    check("merged min", hist.min, 1)
    check("merged max", hist.max, 100)
    check("merged sum", hist.sum, 115)
    check("merged bucket 4", hist.buckets[4], 2)
    check("merged bucket 11", hist.buckets[11], 1)

    class NotAHistogram:
        def name(self):
            return "SomethingElse"

    fresh = spread()
    check("merge rejects other names",
          fresh.merge(NotAHistogram()), False)
    check("rejected merge leaves count", fresh.count, 3)

    # --- corruption controls ---
    corrupt = spread()
    corrupt.count = 0
    check("corrupt count-0 average", corrupt.average(), 0.0)
    check("corrupt count-0 stddev", corrupt.stddev(), 0.0)

    print("%d checks, %d failed" % (CHECKS, len(FAILURES)))
    for failure in FAILURES:
        print("FAIL: " + failure)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
