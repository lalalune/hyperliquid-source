"""Tests for the node #115 compaction-stats per-level data-row formatter.

The formatter (0x5eed6f0) writes one data row into the caller's buffer:
label + the 21 metric values of one map<int, double>, keys 1..21, with
the row format at 0x96c040.  Expected outputs below are pinned from the
binary: the format literal, the integer/human-size formatter semantics
(0x61d0940, 0x61d0ba0), and the pair map's names.  The ctypes
cross-checks run the same row format through the C library's snprintf
to prove the model's vararg order, truncation and float rendering
match the binary's __snprintf_chk call byte for byte.
"""

import ctypes
import math
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import compaction_data_row_115 as m

LIBC = ctypes.CDLL(None)
LIBC.snprintf.restype = ctypes.c_int
LIBC.snprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.c_char_p]


def c_row(label, metrics):
    """Run C snprintf(buf, 2000, ROW_FORMAT, ...) with the binary's
    vararg layout; return the bytes written (truncated at 1999)."""
    buf = ctypes.create_string_buffer(2000)
    args = [
        ctypes.c_char_p(label.encode("utf-8")),
        ctypes.c_int(m.cvttsd2si32(metrics[1])),
        ctypes.c_int(m.cvttsd2si32(metrics[2])),
        ctypes.c_char_p(
            m.human_size(m.u64_of_double(metrics[3])).encode("utf-8")),
    ]
    for key, _w, _p in m.DOUBLE_COLUMNS[:12]:
        args.append(ctypes.c_double(metrics[key]))
    args.append(ctypes.c_int(m.cvttsd2si32(metrics[16])))
    args.append(ctypes.c_double(metrics[17]))
    args.append(ctypes.c_char_p(
        m.int_format(m.cvttsd2si(metrics[18])).encode("utf-8")))
    args.append(ctypes.c_char_p(
        m.int_format(m.cvttsd2si(metrics[19])).encode("utf-8")))
    for key, _w, _p in m.DOUBLE_COLUMNS[13:]:
        args.append(ctypes.c_double(metrics[key]))
    ret = LIBC.snprintf(buf, 2000, m.ROW_FORMAT.encode("utf-8"), *args)
    assert ret >= 0
    return buf.raw.split(b"\x00", 1)[0]


def sample_metrics():
    return {
        1: 7.0, 2: 3.0, 3: 123456789.0, 4: 1.5, 5: 2.25, 6: 0.5,
        7: 10.0, 8: 0.125, 9: 100.0, 10: 3.14159, 11: 2.0, 12: 500.0,
        13: 250.5, 14: 12.345, 15: 0.001, 16: 42.0, 17: 0.333333,
        18: 123456.0, 19: 9999.0, 20: 7.75, 21: 0.0,
    }


def test_spot_row():
    expected = (
        "  L0      7/3   117.74 MB   1.5      2.2     0.5     10.0"
        "       0.1    100.0       3.1   2.0    500.0    250.5"
        "     12.35              0.00        42    0.333    123K"
        "   9999       7.8       0.0\n")
    assert m.format_row("L0", sample_metrics()) == expected


def test_row_matches_c():
    assert m.format_row_bytes("L0", sample_metrics()) == \
        c_row("L0", sample_metrics())


def test_row_matches_c_random():
    rng = random.Random(20261105)
    for _ in range(200):
        metrics = {}
        for k in range(1, 22):
            choice = rng.random()
            if choice < 0.6:
                metrics[k] = rng.uniform(-1000.0, 100000.0)
            elif choice < 0.8:
                metrics[k] = float(rng.randint(-10 ** 6, 10 ** 9))
            elif choice < 0.9:
                metrics[k] = rng.uniform(0.0, 1.0)
            else:
                metrics[k] = rng.choice(
                    [0.0, -0.0, 1e-9, 1e15, -1e15, 2.0 ** 62,
                     2.0 ** 63 - 1024.0])
        label = rng.choice(["L0", "L12", "Sum", "Int", "Bottom", "Low",
                            "High", "User", "Invalid", "L123456"])
        got = m.format_row_bytes(label, metrics)
        want = c_row(label, metrics)
        assert got == want, (label, metrics, got, want)


def test_row_nan_inf():
    metrics = sample_metrics()
    metrics[17] = float("nan")
    assert b"    nan" in m.format_row_bytes("L0", metrics)
    neg_nan = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000000))[0]
    metrics[17] = neg_nan
    assert b"   -nan" in m.format_row_bytes("L0", metrics)
    assert m.format_row_bytes("L0", metrics) == c_row("L0", metrics)
    metrics[17] = float("inf")
    assert b"     inf" in m.format_row_bytes("L0", metrics)
    assert m.format_row_bytes("L0", metrics) == c_row("L0", metrics)
    metrics[17] = float("-inf")
    assert b"    -inf" in m.format_row_bytes("L0", metrics)
    assert m.format_row_bytes("L0", metrics) == c_row("L0", metrics)


def test_row_truncation():
    metrics = sample_metrics()
    long_label = "L" + "9" * 3000
    row = m.format_row(long_label, metrics)
    assert len(row) == 1999
    assert row == m.format_row_bytes(long_label, metrics).decode("utf-8")
    assert row.encode("utf-8") == c_row(long_label, metrics)


def test_missing_key_raises():
    metrics = sample_metrics()
    for key in (1, 2, 3, 16, 17, 18, 21):
        bad = dict(metrics)
        del bad[key]
        try:
            m.format_row("L0", bad)
        except KeyError as e:
            assert "map::at" in str(e)
        else:
            raise AssertionError("key %d did not raise" % key)


def test_int_format():
    cases = [
        (0, "0"), (1, "1"), (-1, "-1"), (9999, "9999"),
        (-9999, "-9999"), (10000, "10K"), (999999, "999K"),
        (1000000, "1000K"), (9999999, "9999K"), (10000000, "10M"),
        (123456789, "123M"), (9999999999, "9999M"),
        (10000000000, "10G"), (123456789012, "123G"),
        (-10000, "-10K"), (-123456789, "-123M"),
        (2 ** 63 - 1, "9223372036G"),
        (-(2 ** 63), "-9223372036854775808"),
        (2 ** 62, "4611686018G"),
    ]
    for n, want in cases:
        assert m.int_format(n) == want, (n, m.int_format(n), want)


def test_int_format_division_matches_magic():
    # The binary divides by 1000/1e6/1e9 with magic multiplies (imuls
    # 0x20c49ba5e353f7cf>>7, 0x431bde82d7b634db>>18,
    # 0x112e0be826d694b3>>26, each minus the sign correction).  Replay
    # those exact sequences here and require them to equal the
    # model's truncating division on random values in each band.
    def s64(x):
        x &= (1 << 64) - 1
        return x - (1 << 64) if x >= (1 << 63) else x

    def magic_div(n, magic, shift):
        prod = s64(magic) * n
        hi = prod >> 64  # arithmetic shift of the signed 128-bit product
        return (hi >> shift) - (n >> 63)

    rng = random.Random(7)
    bands = [(0x20c49ba5e353f7cf, 7, 1000, 10000, 9999999),
             (0x431bde82d7b634db, 18, 1000000, 10000000, 9999999999),
             (0x112e0be826d694b3, 26, 1000000000, 10000000000, 2 ** 62)]
    for magic, shift, d, lo, hi in bands:
        for _ in range(20000):
            n = rng.randint(lo, hi) * rng.choice([1, -1])
            assert magic_div(n, magic, shift) == m.trunc_div(n, d), \
                (n, magic_div(n, magic, shift), m.trunc_div(n, d))


def test_human_size():
    cases = [
        (0, "0.00 KB"), (1, "0.00 KB"), (1023, "1.00 KB"),
        (1024, "1.00 KB"), (1536, "1.50 KB"), (1048575, "1024.00 KB"),
        (1048576, "1.00 MB"), (123456789, "117.74 MB"),
        (1073741824, "1.00 GB"), (1099511627776, "1.00 TB"),
        (2 ** 64 - 1, "16777216.00 TB"),
        (2 ** 63, "8388608.00 TB"),
    ]
    for u, want in cases:
        assert m.human_size(u) == want, (u, m.human_size(u), want)


def test_human_size_matches_c():
    # Independent check: scale in the test, format "%.2f %s" via C.
    rng = random.Random(11)
    for _ in range(300):
        u = rng.choice([rng.randint(0, 2 ** 64 - 1),
                        rng.randint(0, 2 ** 40),
                        rng.randint(0, 2 ** 20)])
        value = float(u)
        for unit in ("KB", "MB", "GB"):
            value *= 1.0 / 1024.0
            if value < 1024.0:
                break
        else:
            value *= 1.0 / 1024.0
            unit = "TB"
        buf = ctypes.create_string_buffer(64)
        LIBC.snprintf(buf, 64, b"%.2f %s", ctypes.c_double(value),
                      ctypes.c_char_p(unit.encode("utf-8")))
        want = buf.raw.split(b"\x00", 1)[0].decode("utf-8")
        assert m.human_size(u) == want, (u, m.human_size(u), want)


def test_u64_of_double():
    cases = [
        (0.0, 0), (1.0, 1), (123456789.0, 123456789),
        (2.0 ** 63 - 1024.0, 2 ** 63 - 1024),
        (2.0 ** 63, 2 ** 63), (2.0 ** 63 + 4096.0, 2 ** 63 + 4096),
        (2.0 ** 64 - 2048.0, 2 ** 64 - 2048),
        (2.0 ** 64, 0), (2.0 ** 65, 0), (-1.0, 2 ** 64 - 1),
        (-2.0 ** 63, 2 ** 63), (float("nan"), 2 ** 63),
        (float("inf"), 0), (float("-inf"), 2 ** 63),
        (123.9, 123), (-123.9, 2 ** 64 - 123),
    ]
    for v, want in cases:
        assert m.u64_of_double(v) == want, (v, m.u64_of_double(v), want)


def test_cvttsd2si32():
    cases = [
        (0.0, 0), (7.9, 7), (-7.9, -7), (2.0 ** 31 - 1, 2 ** 31 - 1),
        (2.0 ** 31, -(2 ** 31)), (-2.0 ** 31, -(2 ** 31)),
        (-2.0 ** 31 - 1.0, -(2 ** 31)), (1e15, -(2 ** 31)),
        (float("nan"), -(2 ** 31)), (float("inf"), -(2 ** 31)),
    ]
    for v, want in cases:
        assert m.cvttsd2si32(v) == want, (v, m.cvttsd2si32(v), want)


def test_column_metadata():
    assert m.COLUMN_KEYS == list(range(1, 22))
    assert len(m.FIRST) == 21 and len(m.SECOND) == 21
    assert m.FIRST[1] == "NumFiles" and m.FIRST[21] == "WblobGB"
    assert m.SECOND[1] == "Files" and m.SECOND[21] == "Wblob(GB)"
    assert m.ROW_FORMAT.count("%") == 22
    # A row with single-digit values is 192 chars including the newline.
    metrics = {k: 1.0 for k in range(1, 22)}
    metrics[3] = 1024.0
    row = m.format_row("L0", metrics)
    assert len(row) == 192, len(row)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - report and continue
            failed.append((name, e))
            print("FAIL %s: %r" % (name, e))
        else:
            print("PASS %s" % name)
    print("%d tests, %d failed" % (len(tests), len(failed)))
    sys.exit(1 if failed else 0)
