#!/usr/bin/env python3
"""Tests for tools/serializer_115.py (RE-001, node #115).

Run from the repository root:
    python3 tests/test_serializer_115.py

Every expectation is target-grounded: decimal strings follow the
binary's two-digit-table loop, escapes follow escape_predicate /
escape_letter, hex follows hexchar, doubles follow C "%f", and the
enum kinds follow the head-list walk over harness-injected maps.
"""

import math
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import serializer_115 as m

CHECKS = []


def check(name, got, want):
    CHECKS.append((name, got == want, got, want))


def main():
    # --- decimal via the two-digit table -------------------------------
    for v in [0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 12345,
              999999999, 10 ** 18, 10 ** 19, 2 ** 64 - 1, 1000000007]:
        check("u64 %d" % v, m._decimal_u64(v), str(v))
    for v in [0, 1, 9, 10, 99, 100, 12345, 2 ** 32 - 1, 1000000000]:
        check("u32 %d" % v, m._decimal_u32(v), str(v))
    for v in [0, 1, -1, 9, -9, 10, -10, 99, -99, 100, -100,
              2 ** 63 - 1, -(2 ** 63), 10 ** 18, -(10 ** 18)]:
        check("i64 %d" % v, m._decimal_i64(v), str(v))
    for v in [0, 1, -1, 9, 10, 99, 100, 123456789, -987654321,
              2 ** 31 - 1, -(2 ** 31)]:
        check("i32 %d" % v, m.int_to_string(v), str(v))

    # --- escape predicate / letter --------------------------------------
    for byte, want in [(0x00, False), (0x09, False), (0x0A, True),
                       (0x0D, True), (0x20, False), (0x22, False),
                       (0x23, True), (0x3A, True), (0x5C, True),
                       (0x5D, False), (0x7F, False), (0x80, False),
                       (0xFF, False), (ord("a"), False),
                       (ord("T"), False), (ord("~"), False)]:
        check("needs_escape %#x" % byte, m.escape_predicate(byte), want)
    check("letter 0x0a", m.escape_letter(0x0A), ord("n"))
    check("letter 0x0d", m.escape_letter(0x0D), ord("r"))
    check("letter 'a'", m.escape_letter(ord("a")), ord("a"))
    check("letter backslash", m.escape_letter(0x5C), 0x5C)
    check("letter '#'", m.escape_letter(0x23), 0x23)

    # --- escape_copy ------------------------------------------------------
    for data, want in [
            (b"", b""),
            (b"abc", b"abc"),
            (b"a#b", b"a\\#b"),
            (b"a:b", b"a\\:b"),
            (b"a\\b", b"a\\\\b"),
            (b"a\nb", b"a\\nb"),
            (b"a\rb", b"a\\rb"),
            (b"~}", b"~}"),
            (b"\x00\x01\x02", b"\x00\x01\x02"),
            (b"\x80\xff", b"\x80\xff"),
            (b"a#b:c\\d\ne\rf", b"a\\#b\\:c\\\\d\\ne\\rf"),
            (b"#:\\\n\r", b"\\#\\:\\\\\\n\\r")]:
        check("escape_copy %r" % data, m.escape_copy(data), want)

    # --- hex ---------------------------------------------------------------
    for n, want in [(0, "0"), (9, "9"), (10, "A"), (15, "F")]:
        check("hexchar %d" % n, chr(m.hexchar(n)), want)
    for data, want in [(b"", b""), (b"\x00", b"00"), (b"\xff", b"FF"),
                       (b"\x00\xff\xab", b"00FFAB"),
                       (b"Hi", b"4869"),
                       (b"\xde\xad\xbe\xef", b"DEADBEEF")]:
        check("hex_encode %r" % data, m.hex_encode(data, 1), want)
    check("hex_encode flag 0", m.hex_encode(b"\x00\xff", 0), b"\x00\xff")

    # --- double "%f" ---------------------------------------------------------
    for v, want in [(0.0, "0.000000"), (1.5, "1.500000"),
                    (-2.25, "-2.250000"), (1e20, "100000000000000000000.000000"),
                    (123456.789, "123456.789000"),
                    (float("inf"), "inf"), (float("-inf"), "-inf"),
                    (float("nan"), "nan")]:
        check("double %r" % v, m.format_double(v), want)

    # --- serialize: scalar kinds ----------------------------------------------
    for v, want in [(0, "false"), (1, "true"), (2, "true"),
                    (255, "true")]:
        check("kind 0 %d" % v, m.serialize(0, v), (True, want))
    for v in [42, -42, 0, -(2 ** 31), 2 ** 31 - 1]:
        check("kind 1 %d" % v, m.serialize(1, v), (True, str(v)))
        check("kind 2 %d" % v, m.serialize(2, v), (True, str(v)))
    for v in [0, -1, 2 ** 63 - 1, -(2 ** 63), 10 ** 18, -(10 ** 18)]:
        check("kind 3 %d" % v, m.serialize(3, v), (True, str(v)))
    for v in [0, 2 ** 32 - 1, 1000000000]:
        check("kind 4 %d" % v, m.serialize(4, v), (True, str(v)))
        check("kind 6 %d" % v, m.serialize(6, v), (True, str(v)))
    for v, want in [(0, "0"), (255, "255"), (128, "128")]:
        check("kind 5 %d" % v, m.serialize(5, v), (True, want))
    for v in [0, 2 ** 64 - 1, 10 ** 19]:
        check("kind 7 %d" % v, m.serialize(7, v), (True, str(v)))
        check("kind 8 %d" % v, m.serialize(8, v), (True, str(v)))
    for data, want in [(b"", ""), (b"a#b", "a\\#b"),
                       (b"a\nb", "a\\nb")]:
        check("kind 9 %r" % data, m.serialize(9, data), (True, want))
    for v, want in [(0.0, "0.000000"), (1.5, "1.500000")]:
        check("kind 10 %r" % v, m.serialize(10, v), (True, want))
    for data, want in [(b"", ""), (b"\x00\xff\xab", "00FFAB")]:
        check("kind 23 %r" % data, m.serialize(23, data), (True, want))

    # --- serialize: enum kinds ----------------------------------------------
    maps = {
        0x65070A0: m.EnumMap({1: "one", 2: "two"}),
        0x6507060: m.EnumMap({0: "zero"}),
        0x6507120: m.EnumMap({7: "seven"}),
        0x6507020: m.EnumMap({0xDEADBEEF: "big"}),
        0x6507160: m.EnumMap({255: "max"}),
        0x65070E0: m.EnumMap({3: "three"}),
        0x6506FE0: m.EnumMap({9: "nine"}),
    }
    for kind, key, want in [(11, 1, "one"), (11, 2, "two"),
                            (12, 0, "zero"), (13, 7, "seven"),
                            (14, 0xDEADBEEF, "big"), (15, 255, "max"),
                            (16, 3, "three"), (24, 9, "nine")]:
        check("kind %d key %d" % (kind, key),
              m.serialize(kind, key, maps), (True, want))
    check("enum miss", m.serialize(11, 99, maps), (False, None))
    check("enum u32 miss", m.serialize(14, 1, maps), (False, None))
    check("enum no map", m.serialize(11, 1, {}), (False, None))

    # --- serialize: unhandled kinds -------------------------------------------
    for kind in list(range(0x11, 0x17)) + [0x19, 0x100]:
        check("kind %#x unhandled" % kind,
              m.serialize(kind, 0), (False, None))

    # --- jump-table shape -------------------------------------------------------
    check("kind count", m.KIND_COUNT, 25)
    check("kind targets", len(m.KIND_TARGETS), 25)
    check("unsupported kinds", sorted(m.UNSUPPORTED_KINDS),
          [0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
    check("digits table", m.DIGITS_TABLE,
          "".join("%02d" % i for i in range(100)))

    bad = [(n, g, w) for n, ok, g, w in CHECKS if not ok]
    for n, g, w in bad:
        print("FAIL %s: got %r want %r" % (n, g, w))
    print("all %d tests passed" % len(CHECKS) if not bad else
          "%d/%d tests failed" % (len(bad), len(CHECKS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
