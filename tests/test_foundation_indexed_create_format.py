#!/usr/bin/env python3
"""Tests for tools/foundation_indexed_create_format.py (node #94 0x514eb90).

The window is exercised end to end through injected lookup and
formatter callables: parser gates, the signed low-32 index gate, the
create-vs-found dispatch, the move-assign, and failure preservation
of the destination. Packet verification lives in the work item's
verify.py; these tests pin the modelled behaviour.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from foundation_indexed_create_format import (
    Destination,
    indexed_create_format,
    parse_decimal,
    to_signed32,
)


def created_lookup(record):
    def lookup(field):
        assert field == 0xDEADBEEF
        return (0, record)
    return lookup


def found_lookup(tag=0x41):
    def lookup(field):
        return (tag, None)
    return lookup


def stub_formatter(record, separator, equals):
    assert separator == "; "
    assert equals == "="
    return "record=%r" % (record,)


class ParserTests(unittest.TestCase):
    def test_plain_index(self):
        self.assertEqual(parse_decimal(b"7"), (True, 7, 0))

    def test_zero(self):
        self.assertEqual(parse_decimal(b"0"), (True, 0, 0))

    def test_leading_zeroes(self):
        self.assertEqual(parse_decimal(b"007"), (True, 7, 0))

    def test_empty_fails(self):
        self.assertEqual(parse_decimal(b"")[0], False)

    def test_nondigit_first_fails(self):
        self.assertEqual(parse_decimal(b"x12")[0], False)

    def test_trailing_tail_reported(self):
        self.assertEqual(parse_decimal(b"12x"), (True, 12, 1))

    def test_uint64_max_ok(self):
        self.assertEqual(parse_decimal(b"18446744073709551615"),
                         (True, 18446744073709551615, 0))

    def test_uint64_overflow_fails(self):
        self.assertEqual(parse_decimal(b"18446744073709551616")[0], False)

    def test_overflow_threshold_boundary(self):
        # 0x1999999999999999 == 1844674407370955161, and
        # 0x1999999999999999 * 10 + 5 == UINT64_MAX, so a 20th digit
        # above 5 overflows while 5 itself is exactly UINT64_MAX.
        self.assertEqual(parse_decimal(b"18446744073709551615"),
                         (True, 18446744073709551615, 0))
        self.assertEqual(parse_decimal(b"18446744073709551616")[0], False)


class GateTests(unittest.TestCase):
    def test_success_sets_destination(self):
        dest = Destination("old")
        trace = []
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"3",
                                   created_lookup("rec"), stub_formatter,
                                   trace)
        self.assertEqual(rc, 1)
        self.assertEqual(dest.value, "record='rec'")
        self.assertEqual(trace, ["parse", "lookup", "format", "move-assign",
                                 "dispose-temp", "dispose-separator",
                                 "dispose-equals", "cleanup"])

    def test_parser_failure_preserves(self):
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"abc",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 0)
        self.assertEqual(dest.value, "old")

    def test_trailing_characters_preserve(self):
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"3x",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 0)
        self.assertEqual(dest.value, "old")

    def test_index_equal_to_count_fails(self):
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"10",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 0)
        self.assertEqual(dest.value, "old")

    def test_index_above_count_fails(self):
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"11",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 0)

    def test_found_entry_returns_zero_and_preserves(self):
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"3",
                                   found_lookup(), stub_formatter)
        self.assertEqual(rc, 0)
        self.assertEqual(dest.value, "old")

    def test_found_entry_with_any_nonzero_tag(self):
        dest = Destination("old")
        for tag in (1, 0xFF, 0x2A):
            rc = indexed_create_format(10, 0xDEADBEEF, dest, b"3",
                                       found_lookup(tag), stub_formatter)
            self.assertEqual(rc, 0)
        self.assertEqual(dest.value, "old")

    def test_low32_gate_quirk(self):
        # The gate reads only the low 32 bits, signed: 2**32 + 3 passes
        # a count of 10, because its low half is 3. This pins the
        # observed instruction (a 32-bit cmp), not an intended rule.
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"4294967299",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 1)
        self.assertEqual(dest.value, "record='rec'")

    def test_signed32_negative_low_half_passes(self):
        # Low half 0xFFFFFFFF is -1 signed, below any non-negative count.
        dest = Destination("old")
        rc = indexed_create_format(10, 0xDEADBEEF, dest, b"4294967295",
                                   created_lookup("rec"), stub_formatter)
        self.assertEqual(rc, 1)

    def test_formatter_receives_record_and_separators(self):
        seen = {}

        def fmt(record, sep, eq):
            seen.update(record=record, sep=sep, eq=eq)
            return "out"
        dest = Destination()
        rc = indexed_create_format(5, 0xDEADBEEF, dest, b"0",
                                   created_lookup(object()), fmt)
        self.assertEqual(rc, 1)
        self.assertEqual(seen["sep"], "; ")
        self.assertEqual(seen["eq"], "=")
        self.assertEqual(dest.value, "out")

    def test_index_is_gate_only(self):
        # The parsed index is never passed to the lookup or formatter:
        # two different in-range indices give the same result.
        for view in (b"0", b"9"):
            dest = Destination()
            rc = indexed_create_format(10, 0xDEADBEEF, dest, view,
                                       created_lookup("same"),
                                       stub_formatter)
            self.assertEqual(rc, 1)
            self.assertEqual(dest.value, "record='same'")


class Signed32Tests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(to_signed32(0x7FFFFFFF), 0x7FFFFFFF)
        self.assertEqual(to_signed32(0x80000000), -0x80000000)
        self.assertEqual(to_signed32(0xFFFFFFFF), -1)
        self.assertEqual(to_signed32(0x100000000), 0)


if __name__ == "__main__":
    unittest.main()
