"""Tests for tools/compaction_consumer_a010_115.py (node #115, RE-001).

Run directly:  python3 tests/test_compaction_consumer_a010_115.py
(pytest is not installed on this VM, so the checks run as plain
functions and the script exits non-zero on the first failure.)

Every check is target-grounded: the literal decimal conversion and the
u64->double fixup are compared against Python's own str()/float() on
large random samples plus the boundary values the binary's dispatch
thresholds create; the "%f" rendering is cross-checked against the C
library's snprintf through ctypes; the 21 metric formulas are checked
against hand-computed values on a level built from exact powers of two;
the filler / main / summary behaviours are checked end to end on small
synthetic inputs whose expected out maps are computed by hand.
"""

import ctypes
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from compaction_consumer_a010_115 import (
    DIGIT_TABLE,
    MAGIC100,
    MAGIC10000,
    PAIR_FIRST,
    PAIR_TABLE,
    build_map,
    compaction_key,
    digit_count,
    div100,
    emit_compaction_stats,
    fill_outer,
    final_summary,
    format_f,
    insert_or_assign,
    label_for,
    level_skip,
    map_at,
    metric_values,
    name_builder,
    part_a,
    part_b,
    ratio_for_level,
    scalar_sum,
    snapshot_add,
    sum_ratio,
    tag_index,
    to_decimal,
    u64_to_double,
    zero_level,
)

LIBC = ctypes.CDLL("libc.so.6")
LIBC.snprintf.restype = ctypes.c_int
LIBC.snprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.c_char_p, ctypes.c_double]


def c_printf_f(x):
    buf = ctypes.create_string_buffer(64)
    LIBC.snprintf(buf, 64, b"%f", ctypes.c_double(x))
    return buf.value.decode("ascii")


def test_div100():
    rng = random.Random(97)
    for _ in range(200000):
        v = rng.getrandbits(64)
        assert div100(v) == (v // 100, v % 100), v
    for v in (0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999,
              100000, 999999, 10**7, 10**12, 2**63, 2**64 - 1):
        assert div100(v) == (v // 100, v % 100), v


def test_digit_count():
    rng = random.Random(98)
    values = [rng.getrandbits(64) for _ in range(50000)]
    values += [0, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999, 100000,
               999999, 10**6, 10**7 - 1, 10**7, 10**8 - 1, 10**8,
               10**9, 10**12, 10**18, 10**19, 2**63, 2**64 - 1]
    for v in values:
        assert digit_count(v) == len(str(v)), (v, digit_count(v))


def test_to_decimal():
    rng = random.Random(99)
    values = [rng.getrandbits(64) for _ in range(200000)]
    values += [0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 9999, 10000,
               99999, 100000, 999999, 10**6, 10**7 - 1, 10**7,
               10**8 - 1, 10**8, 10**12, 10**18, 10**19 - 1, 10**19,
               2**63, 2**63 - 1, 2**64 - 1]
    for v in values:
        assert to_decimal(v) == str(v), (v, to_decimal(v))
    assert to_decimal(18446744073709551615) == "18446744073709551615"


def test_digit_table_shape():
    assert len(DIGIT_TABLE) == 200
    assert DIGIT_TABLE == b"".join(("%02d" % i).encode() for i in range(100))


def test_u64_to_double():
    rng = random.Random(100)
    for _ in range(200000):
        v = rng.getrandbits(64)
        assert u64_to_double(v) == float(v), v
    for v in (0, 1, 2**52, 2**53, 2**53 + 1, 2**62, 2**63, 2**63 + 1,
              2**64 - 1):
        assert u64_to_double(v) == float(v), v


def test_format_f_against_libc():
    for x in (0.0, 0.5, 1.0, 1.5, 123456.789, 1000000.0, 1e13,
              18446744073709551615.0 / 1e6, float("inf"), float("-inf")):
        assert format_f(x) == c_printf_f(x), (x, format_f(x))
    assert format_f(float("nan")) == "nan"
    neg_nan = math.copysign(float("nan"), -1.0)
    assert format_f(neg_nan) == "-nan"
    assert c_printf_f(neg_nan) == "-nan"


def test_pair_table():
    assert len(PAIR_TABLE) == 21
    assert [k for k, _, _ in PAIR_TABLE] == list(range(1, 22))
    assert PAIR_TABLE[0] == (1, "NumFiles", "Files")
    assert PAIR_TABLE[4] == (5, "ReadGB", "Read(GB)")
    assert PAIR_TABLE[10] == (11, "WriteAmp", "W-Amp")
    assert PAIR_TABLE[20] == (21, "WblobGB", "Wblob(GB)")
    assert PAIR_FIRST[1] == "NumFiles"
    assert PAIR_FIRST[21] == "WblobGB"
    assert len(PAIR_FIRST) == 21


def test_map_at():
    assert map_at(PAIR_FIRST, 1) == "NumFiles"
    assert map_at(PAIR_FIRST, 21) == "WblobGB"
    try:
        map_at(PAIR_FIRST, 22)
    except ValueError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("map::at must raise on a missing key")


def test_scalar_sum():
    # 0x5f6c300 -> 0x5da4de0: only non-null pointers contribute +0x10.
    assert scalar_sum([]) == 0
    assert scalar_sum([(True, 5), (True, 7)]) == 0
    assert scalar_sum([(False, 5), (False, 7), (True, 100)]) == 12
    assert scalar_sum([(False, 2**63), (False, 2**63)]) == 0  # wraps mod 2**64


def test_level_skip():
    zero = zero_level()
    assert level_skip(zero, 0)
    assert not level_skip(zero, 1)
    assert not level_skip({**zero, "f00": 1}, 0)
    assert not level_skip({**zero, "f08": 1}, 0)


def test_ratio_for_level():
    level = {**zero_level(), "f10": 2**30, "f20": 2**30,
             "f28": 2**30, "f30": 2**30}
    assert ratio_for_level(level, 0) == 0.0  # level 0 is always 0.0
    assert ratio_for_level(level, 1) == 1.0
    assert ratio_for_level(zero_level(), 1) == 0.0  # zero denominator
    assert ratio_for_level({**zero_level(), "f28": 2**30}, 2) == 0.0


def _hand_level():
    return {"f00": 1_000_000, "f08": 2_000_000, "f10": 2**30,
            "f18": 2**30, "f20": 2**30, "f28": 2**30, "f30": 2**30,
            "f38": 2**30, "f50": 12345, "f58": 6789, "f60": 0, "f68": 4}


def test_metric_values():
    m = metric_values(_hand_level(), 7, 3, 42.5, 1.25, 0.75)
    assert len(m) == 21
    assert sorted(m) == list(range(1, 22))
    assert m[1] == 7.0
    assert m[2] == 3.0
    assert m[3] == 42.5
    assert m[4] == 1.25
    assert m[5] == 3.0
    assert m[6] == 1.0
    assert m[7] == 1.0
    assert m[8] == 1.0
    assert m[9] == 0.0
    assert m[10] == 1.0
    assert m[11] == 0.75
    # base = (1_000_000 + 1) / 1e6 = 1.000001; metric 12 = 3072 / base,
    # metric 13 = 2048 / base (2**-20 * the i64 totals, then / base).
    assert math.isclose(m[12], 3072 / 1.000001, rel_tol=1e-12)
    assert math.isclose(m[13], 2048 / 1.000001, rel_tol=1e-12)
    assert m[14] == 1.0
    assert m[15] == 2.0
    assert m[16] == 4.0
    assert m[17] == 0.25
    assert m[18] == 12345.0
    assert m[19] == 6789.0
    assert m[20] == 1.0
    assert m[21] == 1.0


def test_metric_values_edges():
    # f68 == 0: metric 17 is 0.0 (the binary zeroes xmm0 and jumps).
    assert metric_values({**_hand_level(), "f68": 0}, 0, 0, 0.0, 0.0,
                         0.0)[17] == 0.0
    # f00 == -1 (all bits): base is 0.0, so metrics 12/13 are inf for a
    # nonzero total and NaN for a zero total, as x86 divsd produces.
    neg = {**zero_level(), "f00": 2**64 - 1, "f10": 2**30}
    m = metric_values(neg, 0, 0, 0.0, 0.0, 0.0)
    assert math.isinf(m[12]) and m[12] > 0
    assert math.isnan(m[13])
    assert format_f(m[12]) == "inf"
    assert format_f(m[13]) == "-nan"
    assert format_f(m[13]) == c_printf_f(m[13])
    # A negative-as-signed i64 field converts through the fixup.
    assert metric_values({**zero_level(), "f10": 2**63}, 0, 0, 0.0, 0.0,
                         0.0)[6] == float(2**63) * 2.0**-30


def test_snapshot_add():
    a = {**zero_level(), "f00": 5, "f10": 2**30, "f68": 3}
    b = {**zero_level(), "f00": 7, "f10": 2**30, "f68": -1}
    s = snapshot_add(a, b)
    assert s["f00"] == 12
    assert s["f10"] == 2**31
    assert s["f68"] == 2  # i32 lane adds, wraps as signed


def test_sum_ratio():
    snap = {**zero_level(), "f28": 2**30, "f30": 2**30}
    assert sum_ratio(snap, 100, 200) == 2**31 / 300.0
    assert sum_ratio(snap, 0, 0) == 0.0


def _fill_inputs():
    l0 = {"f00": 2_000_000, "f08": 0, "f10": 2**30, "f18": 0,
          "f20": 0, "f28": 0, "f30": 0, "f38": 0, "f50": 0, "f58": 0,
          "f60": 0, "f68": 2}
    l1 = zero_level()
    l2 = {"f00": 1_000_000, "f08": 1_000_000, "f10": 2**30,
          "f18": 2**30, "f20": 2**30, "f28": 2**30, "f30": 2**30,
          "f38": 0, "f50": 7, "f58": 8, "f60": 0, "f68": 0}
    levels = [l0, l1, l2]
    # Level 1 is all-zero with no elements, so the filler skips it -- but
    # its flagged count still joins the Sum totals and its S/dense do not.
    per_level = [(10, 2, 100.0, 5.0), (0, 1, 999.0, 888.0),
                 (4, 1, 50.0, 2.0)]
    return levels, per_level


def test_fill_outer():
    levels, per_level = _fill_inputs()
    outer = fill_outer(levels, per_level, 100, 200)
    # Level 1 is skipped (all-zero struct, no elements): no node for it.
    assert sorted(outer) == [-1, 0, 2]
    assert outer[0][1] == 10.0
    assert outer[0][2] == 2.0
    assert outer[0][3] == 100.0
    assert outer[0][4] == 5.0
    assert outer[0][5] == 1.0
    assert outer[0][11] == 0.0  # level 0 ratio is always 0.0
    assert outer[0][14] == 2.0
    assert outer[0][16] == 2.0
    assert outer[0][17] == 1.0
    assert outer[2][1] == 4.0
    assert outer[2][5] == 3.0
    assert outer[2][11] == 1.0
    assert outer[2][16] == 0.0
    assert outer[2][17] == 0.0
    # Sum: snapshot L0+L2, totals 14/4/150.0, dense 0.0.  The skipped
    # level's flagged count (1) joins the total; its S (999.0) does not.
    s = outer[-1]
    assert s[1] == 14.0
    assert s[2] == 4.0
    assert s[3] == 150.0
    assert s[4] == 0.0
    assert s[5] == 4.0
    assert s[11] == 2**31 / 300.0
    assert s[14] == 3.0
    assert s[16] == 2.0
    assert s[17] == 1.5
    assert s[18] == 7.0
    assert s[19] == 8.0


def test_label_for():
    assert label_for(-1) == "Sum"
    assert label_for(0) == "L0"
    assert label_for(12) == "L12"
    assert compaction_key("L0", "NumFiles") == "compaction.L0.NumFiles"
    assert compaction_key("Sum", "ReadGB") == "compaction.Sum.ReadGB"


def test_emit_compaction_stats():
    levels, per_level = _fill_inputs()
    outer = fill_outer(levels, per_level, 100, 200)
    out = emit_compaction_stats(outer)
    assert out["compaction.L0.NumFiles"] == "10.000000"
    assert out["compaction.L0.SizeBytes"] == "100.000000"
    assert out["compaction.L2.WriteAmp"] == "1.000000"
    assert out["compaction.Sum.NumFiles"] == "14.000000"
    assert out["compaction.Sum.ReadGB"] == "4.000000"
    assert out["compaction.Sum.AvgSec"] == "1.500000"
    assert "compaction.L1.NumFiles" not in out  # skipped level: no keys
    assert len(out) == 21 * 3
    try:
        emit_compaction_stats({0: {22: 1.0}})
    except ValueError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("unknown metric id must raise map::at")


def test_tag_index_and_names():
    assert tag_index(0, 0) == 0
    assert tag_index(0, 1) == 1
    assert tag_index(1, 0) == 2
    assert tag_index(1, 1) == 3
    assert tag_index(2, 0) == 4
    assert tag_index(2, 1) == 5
    assert tag_index(0, 2) == 0xE
    assert tag_index(3, 0) == 0xE
    assert part_a(0) == "memtable-limit"
    assert part_a(1) == "l0-file-count-limit"
    assert part_a(2) == "pending-compaction-bytes"
    assert part_a(4) == "write-buffer-manager-limit"
    assert part_b(0) == "delays"
    assert part_b(1) == "stops"
    assert name_builder(0, 0) == "memtable-limit-delays"
    assert name_builder(1, 1) == "l0-file-count-limit-stops"
    assert name_builder(2, 1) == "pending-compaction-bytes-stops"
    assert name_builder(3, 0) == ""
    assert name_builder(0, 2) == ""


def test_final_summary():
    owner = {0xB8: 100, 0xD0: 250, 0xE0: 50, 0xE8: 7, 0xF0: 9}
    out = final_summary(owner)
    assert out == {
        "memtable-limit-delays": "100",
        "l0-file-count-limit-stops": "250",
        "pending-compaction-bytes-stops": "50",
        "cf-l0-file-count-limit-delays-with-ongoing-compaction": "7",
        "cf-l0-file-count-limit-stops-with-ongoing-compaction": "9",
        "total-stops": "300",
        "total-delays": "100",
    }


def test_build_map():
    levels, per_level = _fill_inputs()
    owner = {0xB8: 100, 0xD0: 250, 0xE0: 50, 0xE8: 7, 0xF0: 9}
    out = build_map(levels, per_level, 100, 200, owner)
    assert len(out) == 21 * 3 + 7
    assert out["compaction.L0.NumFiles"] == "10.000000"
    assert out["compaction.L2.WriteAmp"] == "1.000000"
    assert out["compaction.Sum.NumFiles"] == "14.000000"
    assert out["memtable-limit-delays"] == "100"
    assert out["total-stops"] == "300"
    assert out["total-delays"] == "100"


def test_insert_or_assign():
    out = {"a": "1"}
    insert_or_assign(out, "a", "2")
    assert out["a"] == "2"
    insert_or_assign(out, "b", "3")
    assert out["b"] == "3"


def main():
    tests = [test_div100, test_digit_count, test_to_decimal,
             test_digit_table_shape, test_u64_to_double,
             test_format_f_against_libc, test_pair_table, test_map_at,
             test_scalar_sum, test_level_skip, test_ratio_for_level,
             test_metric_values, test_metric_values_edges,
             test_snapshot_add, test_sum_ratio, test_fill_outer,
             test_label_for, test_emit_compaction_stats,
             test_tag_index_and_names, test_final_summary,
             test_build_map, test_insert_or_assign]
    for fn in tests:
        fn()
        print("PASS", fn.__name__)
    print("ALL TESTS PASSED (%d)" % len(tests))


if __name__ == "__main__":
    main()
