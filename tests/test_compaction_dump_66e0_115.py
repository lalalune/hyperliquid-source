#!/usr/bin/env python3
"""Tests for tools/compaction_dump_66e0_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_compaction_dump_66e0_115.py

The snprintf-shaped lines are cross-checked against the C library via
ctypes snprintf, so the model's formatting is verified against the
same function the binary calls (__snprintf_chk wraps snprintf).
"""

import ctypes
import ctypes.util
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import compaction_dump_66e0_115 as m

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "work" / "hl-node-115.bin"

LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def c_snprintf(fmt, *args):
    """Render fmt with the C library (snprintf) for the given args.

    args are (ctype, value) pairs; returns the rendered str."""
    buf = ctypes.create_string_buffer(4096)
    cfmt = ctypes.create_string_buffer(fmt.encode())
    cargs = [ctype(value) for ctype, value in args]
    LIBC.snprintf(buf, 4096, cfmt, *cargs)
    return buf.value.decode()


def check(name, got, want):
    assert got == want, "%s: got %r, want %r" % (name, got, want)
    print("ok %s" % name)


def make_struct(fields):
    """Build a 192-byte struct from a {offset: value} dict of i64 fields
    (+0x68 is the i32 scalar, packed as 4 bytes)."""
    buf = bytearray(192)
    for off, value in fields.items():
        if off == 0x68:
            buf[off:off + 4] = struct.pack("<i", value)
        else:
            buf[off:off + 8] = struct.pack("<q", value)
    return bytes(buf)


def test_digit_table():
    data = BIN.read_bytes()
    # The binary builds the table by storing the thirteen chunks at
    # these offsets into a 200-byte stack buffer (base rsp+0x3f0 in
    # the "L<i>" builder at 0x5ef6a14..0x5ef6aeb; the Sum-row builder
    # at 0x5ef6cbe..0x5ef6d8a repeats the same build).  The last
    # chunk is stored unaligned at offset 185: its first 7 bytes
    # overwrite the tail of the previous chunk with identical bytes,
    # and its next 8 bytes are the final "96979899".
    pairs = [(0x451750, 0), (0x453230, 16), (0x456910, 32),
             (0x453e00, 48), (0x451db0, 64), (0x452ba0, 80),
             (0x455590, 96), (0x456240, 112), (0x456920, 128),
             (0x4528d0, 144), (0x456250, 160), (0x453240, 176),
             (0x454870, 185)]
    buf = bytearray(200)
    for src, off in pairs:
        chunk = data[src:src + 16]
        buf[off:min(off + 16, 200)] = chunk[:max(0, 200 - off)]
    check("digit table", bytes(buf), m.DIGIT_TABLE)


def test_to_decimal():
    rng = random.Random(66)
    values = list(range(0, 200)) + [999, 1000, 9999, 10000, 99999,
                                    100000, 999999, 10 ** 12, 2 ** 63 - 1,
                                    2 ** 63, 2 ** 64 - 1]
    values += [rng.randrange(0, 2 ** 64) for _ in range(200)]
    for v in values:
        check("to_decimal %d" % v, m.to_decimal(v), str(v))
    print("ok to_decimal (%d values)" % len(values))


def test_labels():
    check("level_label 0", m.level_label(0), "L0")
    check("level_label 7", m.level_label(7), "L7")
    check("level_label 12", m.level_label(12), "L12")
    check("level_label 123", m.level_label(123), "L123")
    for i, name in enumerate(("Bottom", "Low", "High", "User")):
        check("priority_name %d" % i, m.priority_name(i), name)
    check("priority_name 4", m.priority_name(4), "Invalid")
    check("priority_name -1", m.priority_name(-1), "Invalid")
    check("priority_name 99", m.priority_name(99), "Invalid")
    check("priority_count", m.priority_count(0x1000, 0x1000 + 192 * 5), 5)
    check("priority_count empty", m.priority_count(0x1000, 0x1000), 0)


def test_filler_skip():
    check("filler_skip zero+0", m.filler_skip(True, 0), True)
    check("filler_skip zero+1", m.filler_skip(True, 1), False)
    check("filler_skip nonzero+0", m.filler_skip(False, 0), False)
    check("filler_skip nonzero+3", m.filler_skip(False, 3), False)


def test_accumulate_and_diff():
    a = make_struct({0x00: 5, 0x08: -3, 0x10: 100, 0x20: 7, 0x28: 9,
                       0x30: 11, 0x60: 1000, 0x68: 4})
    b = make_struct({0x00: 2, 0x08: 8, 0x10: -50, 0x20: -7, 0x28: 1,
                       0x30: -11, 0x60: -500, 0x68: -1})
    dst = bytearray(192)
    m.accumulate_192(dst, a)
    m.accumulate_192(dst, b)
    check("accumulate +0x00", m.struct_i64(dst, 0x00), 7)
    check("accumulate +0x08", m.struct_i64(dst, 0x08), 5)
    check("accumulate +0x10", m.struct_i64(dst, 0x10), 50)
    check("accumulate +0x20", m.struct_i64(dst, 0x20), 0)
    check("accumulate +0x28", m.struct_i64(dst, 0x28), 10)
    check("accumulate +0x30", m.struct_i64(dst, 0x30), 0)
    check("accumulate +0x60", m.struct_i64(dst, 0x60), 500)
    check("accumulate +0x68", struct.unpack_from("<i", dst, 0x68)[0], 3)
    # Bytes 0xbc..0xbf are not touched by the accumulation.
    c = bytearray(192)
    c[0xbc:0xc0] = b"\xde\xad\xbe\xef"
    d = bytearray(192)
    m.accumulate_192(d, bytes(c))
    check("accumulate untouched 0xbc", d[0xbc:0xc0], b"\x00\x00\x00\x00")
    # diff_192 is the inverse of accumulate_192.
    diff = m.diff_192(bytes(dst), bytes(bytearray(192)))
    check("diff identity", diff, bytes(dst))
    check("diff round trip",
          m.diff_192(bytes(dst), make_struct({0x00: 7, 0x08: 5})),
          make_struct({0x10: 50, 0x28: 10, 0x60: 500, 0x68: 3}))


def test_sum_s():
    check("sum_s empty", m.sum_s([]), 0)
    check("sum_s all null", m.sum_s([(True, 5), (True, 7)]), 0)
    check("sum_s mixed", m.sum_s([(False, 10), (True, 99), (False, -3)]), 7)
    check("sum_s negative wrap",
          m.sum_s([(False, -(2 ** 62)), (False, -(2 ** 62))]), -(2 ** 63))


def test_ratios():
    # The #3164 correction: level 0's ratio is NOT 0.0 when the owner
    # flush+addfile sum is nonzero.
    level = make_struct({0x28: 30, 0x30: 70, 0x10: 1000, 0x20: 2000})
    check("ratio level 0 corrected",
          m.ratio_for_level(level, 0, 400, 100), 100.0 / 500.0)
    check("ratio level 0 zero denom",
          m.ratio_for_level(level, 0, 0, 0), 0.0)
    check("ratio level 2",
          m.ratio_for_level(level, 2, 400, 100), 100.0 / 3000.0)
    check("ratio level 2 zero denom",
          m.ratio_for_level(make_struct({0x28: 5, 0x30: 5}), 2, 0, 0), 0.0)
    snap = make_struct({0x28: 30, 0x30: 70})
    check("sum_ratio", m.sum_ratio(snap, 400, 100), 100.0 / 500.0)
    check("sum_ratio zero denom", m.sum_ratio(snap, 0, 0), 0.0)
    agg = make_struct({0x28: 30, 0x30: 70})
    check("aggregate_ratio",
          m.aggregate_ratio(agg, 100, 200), 100.0 / 301.0)
    check("aggregate_ratio zero intervals",
          m.aggregate_ratio(agg, 0, 0), 100.0 / 1.0)
    # High-bit u64 numerator uses the fixup, not a signed conversion.
    big = make_struct({0x28: 0, 0x30: 0})
    big = bytearray(big)
    big[0x28:0x30] = struct.pack("<Q", 2 ** 63)
    check("ratio high-bit numerator",
          m.ratio_for_level(bytes(big), 0, 2 ** 63, 0), 1.0)


def test_blob_line():
    fmt = ("\nBlob file count: %zu, total size: %.1f GB, "
           "garbage size: %.1f GB, space amp: %.1f\n\n")
    want = c_snprintf(fmt, (ctypes.c_size_t, 7),
                      (ctypes.c_double, 3 * 2.0 ** 30 / 2.0 ** 30),
                      (ctypes.c_double, 1 * 2.0 ** 30 / 2.0 ** 30),
                      (ctypes.c_double, 3.0 / 2.0))
    check("blob_line", m.blob_line(7, 3 * 2 ** 30, 1 * 2 ** 30), want)
    # Garbage >= total forces space amp 0.0.
    check("blob_line garbage==total",
          m.blob_line(2, 5 * 2 ** 30, 5 * 2 ** 30),
          "\nBlob file count: 2, total size: 5.0 GB, "
          "garbage size: 5.0 GB, space amp: 0.0\n\n")
    check("blob_line empty",
          m.blob_line(0, 0, 0),
          "\nBlob file count: 0, total size: 0.0 GB, "
          "garbage size: 0.0 GB, space amp: 0.0\n\n")


def test_uptime_and_flush_lines():
    check("uptime_line",
          m.uptime_line(3_000_000, 1_000_000, 0.5),
          c_snprintf("Uptime(secs): %.1f total, %.1f interval\n",
                     (ctypes.c_double, 2.0), (ctypes.c_double, 1.5)))
    check("flush_line",
          m.flush_line(3 * 2 ** 30, 1 * 2 ** 30),
          c_snprintf("Flush(GB): cumulative %.3f, interval %.3f\n",
                     (ctypes.c_double, 3.0), (ctypes.c_double, 2.0)))
    check("addfile_gb_line",
          m.addfile_gb_line(5 * 2 ** 30, 2 * 2 ** 30),
          c_snprintf("AddFile(GB): cumulative %.3f, interval %.3f\n",
                     (ctypes.c_double, 5.0), (ctypes.c_double, 3.0)))
    check("addfile_count_line",
          m.addfile_count_line("Total Files", 100, 40),
          c_snprintf("AddFile(Total Files): cumulative %lu, interval %lu\n",
                     (ctypes.c_ulong, 100), (ctypes.c_ulong, 60)))
    # The interval is a u64 subtraction: cum < prev wraps.
    check("addfile_count_line wrap",
          m.addfile_count_line("Keys", 5, 10),
          "AddFile(Keys): cumulative 5, interval %d\n" % (2 ** 64 - 5))


def test_compaction_lines():
    fmt = ("Cumulative compaction: %.2f GB write, %.2f MB/s write, "
           "%.2f GB read, %.2f MB/s read, %.1f seconds\n")
    want = c_snprintf(fmt,
                      (ctypes.c_double, 2.0), (ctypes.c_double, 1024.0),
                      (ctypes.c_double, 4.0), (ctypes.c_double, 2048.0),
                      (ctypes.c_double, 10.0))
    cum, interval = m.compaction_lines(2 * 2 ** 30, 4 * 2 ** 30, 10_000_000,
                                       2.0, 0, 0, 0, 2.0)
    check("compaction cumulative", cum, want)
    check("compaction interval", interval, want.replace(
        "Cumulative compaction", "Interval compaction"))
    # The 0.001 floor: uptime 0.0005 divides the MB/s by 0.001.
    cum2, _ = m.compaction_lines(2 ** 20, 0, 0, 0.0005, 0, 0, 0, 0.0005)
    check("compaction 0.001 floor",
          cum2, c_snprintf(fmt, (ctypes.c_double, 2.0 ** -10),
                           (ctypes.c_double, 1.0 / 0.001),
                           (ctypes.c_double, 0.0),
                           (ctypes.c_double, 0.0),
                           (ctypes.c_double, 0.0)))


def test_parse_u64_and_stall():
    check("parse_u64 plain", m.parse_u64("123"), 123)
    check("parse_u64 spaces", m.parse_u64("   42"), 42)
    check("parse_u64 plus", m.parse_u64("+7"), 7)
    check("parse_u64 minus", m.parse_u64("-1"), 2 ** 64 - 1)
    check("parse_u64 empty", m.parse_u64(""), 0)
    check("parse_u64 no digits", m.parse_u64("abc"), 0)
    check("parse_u64 trailing junk", m.parse_u64("12x"), 12)
    check("parse_u64 overflow", m.parse_u64("9" * 25), 2 ** 64 - 1)
    check("stall_sum", m.stall_sum("10", "32"), 42)
    check("stall_interval_line zero", m.stall_interval_line(0, 0), "")
    check("stall_interval_line",
          m.stall_interval_line(42, 10), "interval: 32 total count\n")
    check("stall_interval_line wrap",
          m.stall_interval_line(5, 10), "interval: %d total count\n" % (2 ** 64 - 5))


def main():
    test_digit_table()
    test_to_decimal()
    test_labels()
    test_filler_skip()
    test_accumulate_and_diff()
    test_sum_s()
    test_ratios()
    test_blob_line()
    test_uptime_and_flush_lines()
    test_compaction_lines()
    test_parse_u64_and_stall()
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
