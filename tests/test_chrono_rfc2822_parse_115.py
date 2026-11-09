import itertools
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chrono_rfc2822_parse_115 as tool  # noqa: E402

cpu = tool.cpu
STR = tool.STR


class Fixture(unittest.TestCase):
    image = None

    @classmethod
    def setUpClass(cls):
        cls.image = cpu.load_image(tool.BINARY, tool.SHA256)
        cls.harness = tool.Harness(cls.image)
        cls.spec = tool.Spec()

    def parse(self, data, pre=()):
        return self.harness.run(tool.Case(tool.P2822, data, pre=pre))

    def field(self, parsed, offset):
        return struct.unpack_from("<II", parsed, offset)

    @staticmethod
    def kind(got):
        blob = got[1]
        return blob[8] if blob[0:8] == bytes(8) else None


class ParseRfc2822Bytes(Fixture):
    def test_a_full_date_fills_every_field(self):
        got = self.parse(b"Tue, 02 Jan 2024 03:04:05 +0100")
        self.assertEqual(struct.unpack_from("<QQ", got[1], 0), (STR + 31, 0))
        parsed = got[2]
        self.assertEqual(parsed[tool.F_WEEKDAY], 1)
        self.assertEqual(self.field(parsed, tool.F_DAY), (1, 2))
        self.assertEqual(self.field(parsed, tool.F_MONTH), (1, 1))
        self.assertEqual(self.field(parsed, tool.F_YEAR), (1, 2024))
        self.assertEqual(self.field(parsed, tool.F_HOUR12), (1, 0))
        self.assertEqual(self.field(parsed, tool.F_HOURMOD), (1, 3))
        self.assertEqual(self.field(parsed, tool.F_MINUTE), (1, 4))
        self.assertEqual(self.field(parsed, tool.F_SECOND), (1, 5))
        self.assertEqual(self.field(parsed, tool.F_OFFSET), (1, 3600))

    def test_the_weekday_and_seconds_are_optional(self):
        got = self.parse(b"2 Jan 24 03:04 GMT")
        self.assertEqual(struct.unpack_from("<QQ", got[1], 0), (STR + 18, 0))
        self.assertEqual(got[2][tool.F_WEEKDAY], 7)
        self.assertNotEqual(self.field(got[2], tool.F_SECOND)[0], 1)
        self.assertEqual(self.field(got[2], tool.F_YEAR), (1, 2024))

    def test_two_digit_years_use_the_fifty_year_window(self):
        for text, year in ((b"49", 2049), (b"50", 1950), (b"99", 1999), (b"00", 2000), (b"100", 2000), (b"999", 2899), (b"1900", 1900), (b"0000", 0)):
            got = self.parse(b"1 Jan " + text + b" 00:00 Z")
            self.assertEqual(self.field(got[2], tool.F_YEAR), (1, year), text)

    def test_the_year_must_fit_a_signed_word(self):
        self.assertEqual(self.field(self.parse(b"1 Jan 2147483647 00:00 Z")[2], tool.F_YEAR), (1, 2147483647))
        self.assertEqual(self.kind(self.parse(b"1 Jan 2147483648 00:00 Z")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse(b"1 Jan 9223372036854775808 00:00 Z")), tool.OUT_OF_RANGE)

    def test_range_errors_by_field(self):
        self.assertEqual(self.kind(self.parse(b"32 Jan 2020 12:00 Z")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse(b"0 Jan 2020 12:00 Z")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse(b"1 Jan 2020 24:00 Z")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse(b"1 Jan 2020 12:60 Z")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse(b"1 Jan 2020 12:00:61 Z")), tool.OUT_OF_RANGE)
        self.assertIsNone(self.kind(self.parse(b"1 Jan 2020 12:00:60 Z")))
        self.assertEqual(self.kind(self.parse(b"1 Jan 2020 12:00 +0560")), tool.OUT_OF_RANGE)

    def test_state_written_before_a_failure_stays(self):
        got = self.parse(b"1 Jan 2020 12:00 +0560")
        self.assertEqual(self.field(got[2], tool.F_YEAR), (1, 2020))
        self.assertEqual(self.field(got[2], tool.F_MINUTE), (1, 0))
        self.assertNotEqual(self.field(got[2], tool.F_OFFSET)[0], 1)

    def test_present_fields_must_agree(self):
        text = b"Tue, 02 Jan 2024 03:04:05 +0100"
        self.assertIsNone(self.kind(self.parse(text, pre=((tool.F_WEEKDAY, bytes((1,))),))))
        self.assertEqual(self.kind(self.parse(text, pre=((tool.F_WEEKDAY, bytes((2,))),))), tool.IMPOSSIBLE)
        self.assertEqual(self.kind(self.parse(text, pre=((tool.F_DAY, tool.word(1, 3)),))), tool.IMPOSSIBLE)
        self.assertIsNone(self.kind(self.parse(text, pre=((tool.F_DAY, tool.word(1, 2)),))))
        self.assertIsNone(self.kind(self.parse(text, pre=((tool.F_DAY, tool.word(2, 9)),))))
        self.assertEqual(self.kind(self.parse(text, pre=((tool.F_OFFSET, tool.word(1, 1)),))), tool.IMPOSSIBLE)
        self.assertEqual(self.kind(self.parse(text, pre=((tool.F_HOUR12, tool.word(1, 1)),))), tool.IMPOSSIBLE)

    def test_the_gap_after_each_field_is_required(self):
        for text in (b"1 Jan2020 12:00 Z", b"1Jan 2020 12:00 Z", b"1 Jan 2020 12:00Z"):
            self.assertEqual(self.kind(self.parse(text)), tool.INVALID, text)
        self.assertEqual(self.kind(self.parse(b"1")), tool.TOO_SHORT)
        self.assertEqual(self.kind(self.parse(b"1 Jan")), tool.TOO_SHORT)
        self.assertEqual(self.kind(self.parse(b"")), tool.TOO_SHORT)

    def test_comments_after_the_zone_are_consumed_until_one_fails(self):
        base = b"1 Jan 2020 12:00 +0100"
        for tail, left in ((b" (c) (d)", 0), (b" (c) x", 2), (b" (a (b) c)", 0), (b" (unterminated", 14), (b" (a\\)b)", 0), (b"(c)", 0), (b"(c)x", 1)):
            got = self.parse(base + tail)
            self.assertEqual(struct.unpack_from("<Q", got[1], 8)[0], left, tail)

    def test_a_stray_continuation_byte_is_a_slice_panic(self):
        self.assertEqual(self.parse(b"1\x80"), ("panic", "slice", 1, 2))
        self.assertEqual(self.parse(b"12\x80"), ("panic", "slice", 2, 3))
        self.assertEqual(self.parse(b"Mon\x80, 1"), ("panic", "slice", 3, 7))
        self.assertEqual(self.parse(b"Mon,\x80"), ("panic", "slice", 1, 2))

    def test_the_rule_list_agrees_on_every_named_case(self):
        for case in tool.named_cases():
            self.assertEqual(self.harness.run(case), self.spec.run(case), case.label())


class ScannerBytes(Fixture):
    def run_kind(self, kind, data, arg=()):
        return self.harness.run(tool.Case(kind, data, arg))

    def test_number_counts_digits_and_stops_at_the_first_other_byte(self):
        got = self.run_kind(tool.NUM, b"123x", (2, 3))
        self.assertEqual(struct.unpack_from("<QQQ", got[1], 0), (STR + 3, 1, 123))
        got = self.run_kind(tool.NUM, b"1234", (2, 3))
        self.assertEqual(struct.unpack_from("<QQQ", got[1], 0), (STR + 3, 1, 123))
        self.assertEqual(self.kind(self.run_kind(tool.NUM, b"1x", (2, 3))), tool.INVALID)
        self.assertEqual(self.kind(self.run_kind(tool.NUM, b"1", (2, 3))), tool.TOO_SHORT)

    def test_number_overflow_is_out_of_range_at_two_to_the_63(self):
        self.assertEqual(struct.unpack_from("<Q", self.run_kind(tool.NUM, b"9223372036854775807", (1, tool.U64))[1], 0x10)[0], (1 << 63) - 1)
        self.assertEqual(self.kind(self.run_kind(tool.NUM, b"9223372036854775808", (1, tool.U64))), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.run_kind(tool.NUM, b"99999999999999999999", (1, tool.U64))), tool.OUT_OF_RANGE)

    def test_number_with_a_larger_minimum_than_maximum_is_the_assert_panic(self):
        self.assertEqual(self.run_kind(tool.NUM, b"12", (3, 2)), ("panic", "assert", 28, 0))

    def test_number_with_a_zero_maximum_still_reads_every_digit_but_returns_the_start(self):
        got = self.run_kind(tool.NUM, b"123", (0, 0))
        self.assertEqual(struct.unpack_from("<QQQ", got[1], 0), (STR, 3, 123))

    def test_set_hour_splits_into_half_day_and_hour_of_half_day(self):
        for value, want in ((0, (0, 0)), (11, (0, 11)), (12, (1, 0)), (23, (1, 11))):
            got = self.run_kind(tool.HOUR, b"", (value,))
            self.assertEqual(got[1], 8)
            self.assertEqual((self.field(got[2], tool.F_HOUR12)[1], self.field(got[2], tool.F_HOURMOD)[1]), want)
        self.assertEqual(self.run_kind(tool.HOUR, b"", (24,))[1], 0)
        self.assertEqual(self.run_kind(tool.HOUR, b"", (tool.U64,))[1], 0)

    def test_set_hour_checks_the_half_day_before_it_writes_the_hour(self):
        case = tool.Case(tool.HOUR, arg=(13,), pre=((tool.F_HOUR12, tool.word(1, 0)),))
        got = self.harness.run(case)
        self.assertEqual(got[1], 1)
        self.assertNotEqual(self.field(got[2], tool.F_HOURMOD)[0], 1)
        agree = tool.Case(tool.HOUR, arg=(13,), pre=((tool.F_HOUR12, tool.word(1, 1)), (tool.F_HOURMOD, tool.word(1, 2))))
        self.assertEqual(self.harness.run(agree)[1], 1)
        agree = tool.Case(tool.HOUR, arg=(13,), pre=((tool.F_HOUR12, tool.word(1, 1)), (tool.F_HOURMOD, tool.word(1, 1))))
        self.assertEqual(self.harness.run(agree)[1], 8)

    def test_names_are_three_letters_in_any_case(self):
        for name, index in tool.WEEKDAYS.items():
            for text in (name, name.upper(), name.capitalize()):
                got = self.run_kind(tool.WEEK, text + b"x")
                self.assertEqual((got[1][0:8], got[1][8:16], got[1][16]), (struct.pack("<Q", STR + 3), struct.pack("<Q", 1), index))
        for name, index in tool.MONTHS.items():
            self.assertEqual(self.run_kind(tool.MONTH, name.upper() + b" ")[1][16], index)
        self.assertEqual(self.run_kind(tool.MONTH, b"Sept")[1][0:8], struct.pack("<Q", STR + 3))
        self.assertEqual(self.run_kind(tool.MONTH, b"ja")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.run_kind(tool.MONTH, b"xyz")[1][8], tool.INVALID)

    def test_the_weekday_error_writes_a_tag_byte_and_the_none_marker(self):
        blob = self.run_kind(tool.WEEK, b"xyz")[1]
        self.assertEqual((blob[0], blob[0x10]), (tool.INVALID, 7))
        self.assertEqual(blob[1:0x10], tool.FILL[1:0x10])

    def test_comments_nest_and_escape(self):
        self.assertEqual(struct.unpack_from("<Q", self.run_kind(tool.COMMENT, b"(a(b)c)d")[1], 8)[0], 1)
        self.assertEqual(struct.unpack_from("<Q", self.run_kind(tool.COMMENT, b"(a\\)b)d")[1], 8)[0], 1)
        self.assertEqual(self.run_kind(tool.COMMENT, b"(a(b)")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.run_kind(tool.COMMENT, b"a")[1][8], tool.INVALID)
        self.assertEqual(self.run_kind(tool.COMMENT, b"  ")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.run_kind(tool.COMMENT, b"()\x80"), ("panic", "slice", 2, 3))

    def test_char_matches_one_byte(self):
        self.assertEqual(struct.unpack_from("<QQ", self.run_kind(tool.CHAR, b":x", (0x3A,))[1], 0), (STR + 1, 1))
        self.assertEqual(self.run_kind(tool.CHAR, b"x", (0x3A,))[1][8], tool.INVALID)
        self.assertEqual(self.run_kind(tool.CHAR, b"", (0x3A,))[1][8], tool.TOO_SHORT)
        self.assertEqual(self.run_kind(tool.CHAR, b":\x80", (0x3A,)), ("panic", "slice", 1, 2))


class Controls(Fixture):
    def sample(self, count=3000):
        cases = list(itertools.islice(tool.all_cases(), 0, None, 14))[:count]
        return list(tool.named_cases()) + cases

    def test_every_wrong_rule_is_contradicted(self):
        cases = self.sample()
        for name in tool.SPEC_MUTANTS + tool.WRONG_MUTANTS:
            wrong = tool.Wrong(frozenset((name,)))
            self.assertTrue(any(self.harness.run(case) != wrong.run(case) for case in cases), name)

    def test_condition_edits_in_the_main_body_are_noticed(self):
        rows = tool.cpu.decode_range(self.image, *self.image.exact_fde(tool.P2822))
        cases = [case for case in self.sample() if case.kind == tool.P2822]
        harness = tool.Harness(self.image)
        for case in cases:
            harness.run(case)
        seen = set(harness.machine.seen)
        edits = [edit for edit in cpu.edits_for(self.image, rows, seen) if edit[1] == "condition"]
        self.assertGreater(len(edits), 40)
        killed = 0
        for _, _, patch in edits[:16]:
            edited = tool.Harness(self.image, patch)
            edited.machine.step_limit = 6000
            if tool.first_failure(edited, cases, self.spec) is not None:
                killed += 1
        self.assertGreaterEqual(killed, 14)

    def test_a_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            cpu.load_image(tool.BINARY, "0" * 64)

    def test_addresses_that_are_not_function_starts_are_refused(self):
        for va in (tool.P2822 + 1, tool.NUM - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_a_string_beyond_evaluator_memory_is_refused(self):
        with self.assertRaises(tool.Halt):
            tool.Harness(self.image).run(tool.Case(tool.P2822, b"1" * 140000))

    def test_the_filter_keeps_str_inputs_and_boundary_probes_only(self):
        self.assertTrue(tool.admissible(tool.Case(tool.P2822, b"1 Jan 2020 12:00 Z")))
        self.assertTrue(tool.admissible(tool.Case(tool.P2822, b"1\x80")))
        self.assertFalse(tool.admissible(tool.Case(tool.P2822, b"1 \x80")))
        self.assertFalse(tool.admissible(tool.Case(tool.P2822, b"\x80")))

    def test_a_corrupted_comparison_byte_changes_the_outcome(self):
        # the jne after the weekday call (0x161fa59, cmp al,7 -> 0x161faec) turned into je: opcode byte 0x85 becomes 0x84
        patch = {0x161FA5A: 0x84}
        edited = tool.Harness(self.image, patch)
        case = tool.Case(tool.P2822, b"Tue, 02 Jan 2024 03:04:05 +0100")
        self.assertNotEqual(edited.run(case), self.spec.run(case))

    def test_call_sites_and_slots_are_read_from_bytes(self):
        rows = tool.caller_rows(self.image)
        self.assertIn(("parse_rfc2822", "0x161fa20", "slot-call", "0x1620ff0", "0x1620be0"), rows)
        self.assertIn(("scan_weekday", "0x1625100", "slot-call", "0x161fa4c", "0x161fa20"), rows)
        self.assertIn(("scan_number", "0x161f900", "call", "0x161fc58", "0x161fa20"), rows)
        self.assertEqual(tool.slot_rows(self.image), [("0x64e1b00", "0x161fa20", "parse_rfc2822"), ("0x64e1b08", "0x1625100", "scan_weekday"),
                                                     ("0x64e1b10", "0x1624fb0", "scan_month")])

    def test_record_layout_is_read_from_the_displacements(self):
        rows = tool.layout_rows(self.image, tool.edit_rows(self.image), set())
        offsets = {row[0] for row in rows}
        for offset in (0x10, 0x40, 0x68, 0x80, 0x88, 0x98, 0xA0):
            self.assertIn("%#x" % offset, offsets)

    def test_generated_evidence_is_reproducible_for_the_cheap_tables(self):
        first = tool.render_functions(self.image, tool.edit_rows(self.image))
        second = tool.render_functions(self.image, tool.edit_rows(self.image))
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "one.tsv"
            tool.write_lines(path, first)
            self.assertEqual(path.read_text().count("\n"), len(first))


if __name__ == "__main__":
    unittest.main()
