"""Model tests for the node #115 statistics produce path
(RE-001-stats-produce-115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_produce_115.py

Every expectation is grounded in the pinned excerpts:
ticker sums from 0x6070430, the snprintf formats at
0x44fd60 / 0x9609a0, the percentile struct layout from
0x606bce0, the stats-emit gate from 0x5d52020, the
shared_ptr copy from 0x5d35c00 and the copy site in
0x5d57770.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stats_produce_115 import (
    LengthError,
    histogram_data,
    histogram_delete_check,
    histogram_line,
    shared_ptr_copy,
    stats_copy_site,
    stats_emit,
    statistics_to_string,
    ticker_line,
    ticker_sum,
)

CHECKS = 0
FAILED = 0


def check(name, got, want):
    global CHECKS, FAILED
    CHECKS += 1
    if got != want:
        FAILED += 1
        print("FAIL %s: got %r want %r" % (name, got, want))


def main():
    # --- ticker_sum (0x6070430): sum over 2**bits shards ---
    check("sum-1shard", ticker_sum([{5: 7}], 0, 5), 7)
    check("sum-4shards", ticker_sum([{5: 1}, {5: 2}, {5: 3}, {5: 4}], 2, 5), 10)
    check("sum-missing", ticker_sum([{5: 1}, {}, {5: 3}, {}], 2, 5), 4)
    check("sum-other-ticker", ticker_sum([{5: 9, 6: 4}], 0, 6), 4)
    check("sum-zero", ticker_sum([{}, {}], 1, 0), 0)
    check("sum-u64-wrap", ticker_sum([{0: 0xFFFFFFFFFFFFFFFF}, {0: 1}], 1, 0), 0)
    check("sum-8shards", ticker_sum([{3: 10}] * 8, 3, 3), 80)

    # --- ticker_line: "%s COUNT : %lu\\n" at 0x44fd60 ---
    check("ticker-line", ticker_line("rocksdb.db.get.micros", 42),
          "rocksdb.db.get.micros COUNT : 42\n")
    check("ticker-line-zero", ticker_line("x", 0), "x COUNT : 0\n")
    check("ticker-line-big", ticker_line("x", 18446744073709551615),
          "x COUNT : 18446744073709551615\n")

    # --- histogram_line: "%s P50 : %f P95 : %f P99 : %f P100 : %f
    #     COUNT : %lu SUM : %lu\\n" at 0x9609a0 ---
    data = histogram_data(10.0, 20.0, 30.0, 15.5, 5.25, 40.0, 7, 123, 1.0)
    check("hist-line", histogram_line("rocksdb.db.write.micros", data),
          "rocksdb.db.write.micros P50 : 10.000000 P95 : 20.000000 "
          "P99 : 30.000000 P100 : 40.000000 COUNT : 7 SUM : 123\n")
    # average/stddev/min are computed but NOT printed by the format.
    data2 = histogram_data(1.0, 2.0, 3.0, 999.0, 888.0, 4.0, 5, 6, 777.0)
    check("hist-line-unprinted", histogram_line("h", data2),
          "h P50 : 1.000000 P95 : 2.000000 P99 : 3.000000 "
          "P100 : 4.000000 COUNT : 5 SUM : 6\n")
    # %f rounding: 1/3 -> 0.333333, 2/3 -> 0.666667.
    data3 = histogram_data(1.0 / 3.0, 2.0 / 3.0, 0.1, 0.0, 0.0, 1.0, 0, 0, 0.0)
    check("hist-line-rounding", histogram_line("h", data3),
          "h P50 : 0.333333 P95 : 0.666667 P99 : 0.100000 "
          "P100 : 1.000000 COUNT : 0 SUM : 0\n")
    check("hist-data-fields", (data["average"], data["stddev"], data["min"]),
          (15.5, 5.25, 1.0))

    # --- statistics_to_string: tickers first, then histograms,
    #     mutex bracketing, empty vectors -> empty string ---
    out, trace = statistics_to_string(
        [("tick.a", 0, [{0: 3}, {0: 4}]), ("tick.b", 1, [{1: 5}, {}])],
        [("hist.a", 2, [{}, {}],
          lambda t, s: histogram_data(1.0, 2.0, 3.0, 0.0, 0.0, 4.0, 9, 10, 0.0))],
        1)
    check("tostring-order", out,
          "tick.a COUNT : 7\ntick.b COUNT : 5\n"
          "hist.a P50 : 1.000000 P95 : 2.000000 P99 : 3.000000 "
          "P100 : 4.000000 COUNT : 9 SUM : 10\n")
    check("tostring-trace", trace, ["lock:+0x38", "unlock:+0x38"])
    out2, _ = statistics_to_string([], [], 0)
    check("tostring-empty", out2, "")

    # --- stats_emit (0x5d52020): null producer emits nothing ---
    check("emit-null", stats_emit(None), None)
    check("emit-ok", stats_emit("tick.a COUNT : 7\n"),
          "[db/db_impl/db_impl.cc:774] STATISTICS:\n tick.a COUNT : 7\n")

    # --- shared_ptr_copy (0x5d35c00): bump use count by one ---
    ctrl = {"use_count": 1}
    dst = {"ptr": 0, "control": None}
    check("sp-copy-count", shared_ptr_copy(dst, {"ptr": 0x1234, "control": ctrl}), 2)
    check("sp-copy-dst", (dst["ptr"], dst["control"] is ctrl), (0x1234, True))
    check("sp-copy-null", shared_ptr_copy({"ptr": 0, "control": None},
                                           {"ptr": 0x99, "control": None}), None)
    ctrl2 = {"use_count": 41}
    shared_ptr_copy({"ptr": 0, "control": None}, {"ptr": 1, "control": ctrl2})
    check("sp-copy-bump", ctrl2["use_count"], 42)

    # --- stats_copy_site (0x5d57770 0x5d58249..0x5d5828c) ---
    ctrl3 = {"use_count": 5}
    src = {0x2A0: 0x1111, 0x2A8: 0x2222, 0x2B0: 0x1,
           0x2B8: 0xABCD, 0x2C0: ctrl3}
    dst = {}
    check("site-use", stats_copy_site(dst, src), 6)
    check("site-fields", (dst[0x530], dst[0x538], dst[0x540]), (0x1111, 0x2222, 1))
    check("site-shared", (dst[0x548], dst[0x550] is ctrl3), (0xABCD, True))
    check("site-bool-mask", stats_copy_site(
        {}, {0x2A0: 0, 0x2A8: 0, 0x2B0: 0x1FF, 0x2B8: 0, 0x2C0: None}), None)

    # --- histogram_delete_check: slot 1 vs GOT 0x64ed2f0 ---
    check("delete-direct", histogram_delete_check(0x5D8B3B0), "direct")
    check("delete-virtual", histogram_delete_check(0x5D89570), "virtual")
    check("delete-other", histogram_delete_check(0x0), "virtual")

    print("%d checks, %d failed" % (CHECKS, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
