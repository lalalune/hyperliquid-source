"""Tests for tools/snapshot_consumer_97b0_115.py (node #115, RE-001).

Run directly:  python3 tests/test_snapshot_consumer_97b0_115.py
(pytest is not installed on this VM, so the checks run as plain
functions and the script exits non-zero on the first failure.)

Every check is target-grounded: the literal decimal conversion and the
u64->double fixup are compared against Python's own str()/float() on
large random samples plus the boundary values the binary's dispatch
thresholds create; the "%f" rendering is cross-checked against the C
library's snprintf through ctypes.
"""

import ctypes
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from snapshot_consumer_97b0_115 import (
    DIGIT_TABLE,
    MAGIC100,
    MAGIC10000,
    PAIR_TABLE,
    REGISTRY,
    WALKER,
    build_map,
    digit_count,
    div100,
    format_f,
    insert_or_assign,
    map_at,
    select_slot_now,
    to_decimal,
    u64_to_double,
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


def test_registry():
    assert REGISTRY == [
        "db.wal_bytes_written",
        "db.wal_syncs",
        "db.user_bytes_written",
        "db.user_keys_written",
        "db.user_writes_by_other",
        "db.user_writes_by_self",
        "db.user_writes_with_wal",
        "db.user_write_stall_micros",
        "write-buffer-manager-limit-stops",
    ]
    assert len(PAIR_TABLE) == 21
    assert PAIR_TABLE[0] == (1, "NumFiles", "Files")
    assert PAIR_TABLE[10] == (11, "WriteAmp", "W-Amp")
    assert PAIR_TABLE[20] == (21, "WblobGB", "Wblob(GB)")


def test_map_at():
    reg = {k: REGISTRY[k] for k in range(9)}
    assert map_at(reg, 0) == "db.wal_bytes_written"
    assert map_at(reg, 8) == "write-buffer-manager-limit-stops"
    try:
        map_at(reg, 9)
    except ValueError as exc:
        assert str(exc) == "map::at"
    else:
        raise AssertionError("map::at must raise on a missing key")


def test_insert_or_assign():
    out = {"db.wal_syncs": "3"}
    insert_or_assign(out, "db.wal_syncs", "7")
    assert out["db.wal_syncs"] == "7"
    insert_or_assign(out, "db.uptime", "0.000000")
    assert out["db.uptime"] == "0.000000"


def test_select_slot_now():
    other = 0x5EEC680
    links = [(WALKER, 111), (WALKER, 222), (WALKER, 333), (WALKER, 444),
             (other, 555)]
    assert select_slot_now(links) == 555
    assert select_slot_now([(other, 10), (WALKER, 20), (WALKER, 30),
                            (WALKER, 40), (WALKER, 50)]) == 10
    assert select_slot_now([(WALKER, 10), (other, 20), (WALKER, 30),
                            (WALKER, 40), (WALKER, 50)]) == 20
    assert select_slot_now([(WALKER, 10), (WALKER, 20), (WALKER, 30),
                            (other, 40), (WALKER, 50)]) == 40


def test_build_map():
    counters = [0, 1, 99, 100, 12345, 999999, 1000000, 2**63, 2**64 - 1]
    out = build_map(counters, slot_now=1_500_000, last=500_000)
    assert out == {
        "db.wal_bytes_written": "0",
        "db.wal_syncs": "1",
        "db.user_bytes_written": "99",
        "db.user_keys_written": "100",
        "db.user_writes_by_other": "12345",
        "db.user_writes_by_self": "999999",
        "db.user_writes_with_wal": "1000000",
        "db.user_write_stall_micros": "9223372036854775808",
        "write-buffer-manager-limit-stops": "18446744073709551615",
        "db.uptime": "1.000000",
    }
    # Zero elapsed time.
    assert build_map([0] * 9, 700_000, 700_000)["db.uptime"] == "0.000000"
    # slot_now behind last: the unsigned wrap, secs = (2**64 - 3) / 1e6.
    wrapped = build_map([0] * 9, 1, 4)["db.uptime"]
    assert wrapped == format_f(u64_to_double(2**64 - 3) / 1e6)
    assert wrapped == c_printf_f(u64_to_double(2**64 - 3) / 1e6)


def main():
    tests = [test_div100, test_digit_count, test_to_decimal,
             test_digit_table_shape, test_u64_to_double,
             test_format_f_against_libc, test_registry, test_map_at,
             test_insert_or_assign, test_select_slot_now, test_build_map]
    for fn in tests:
        fn()
        print("PASS", fn.__name__)
    print("ALL TESTS PASSED (%d)" % len(tests))


if __name__ == "__main__":
    main()
