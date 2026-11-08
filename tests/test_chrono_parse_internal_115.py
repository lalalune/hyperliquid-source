import itertools
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chrono_parse_internal_115 as tool  # noqa: E402

cpu = tool.cpu
STR = tool.STR
Item, Case = tool.Item, tool.Case


def numeric(name, junk=0):
    return Item(tool.NUMERIC, [row[0] for row in tool.NUMERIC_KINDS].index(name), b"", junk)


def fixed(name):
    return Item(tool.FIXED, [key for key, value in tool.FIXED_KINDS.items() if value == name][0])


def literal(text, tag=tool.LITERAL):
    return Item(tag, 0, text)


class Fixture(unittest.TestCase):
    image = None

    @classmethod
    def setUpClass(cls):
        cls.image = cpu.load_image(tool.BINARY, tool.SHA256)
        cls.harness = tool.Harness(cls.image)
        cls.spec = tool.Spec()

    def parse(self, items, data, pre=()):
        return self.harness.run(Case(items, data, pre))

    @staticmethod
    def field(got, offset):
        return struct.unpack_from("<II", got[2], offset)

    @staticmethod
    def kind(got):
        blob = got[1]
        return blob[8] if blob[0:8] == bytes(8) else None

    @staticmethod
    def rest(got):
        return struct.unpack_from("<QQ", got[1], 0)


class InterpreterBytes(Fixture):
    def test_an_iso_date_time_fills_the_record(self):
        items = (numeric("Year"), literal(b"-"), numeric("Month"), literal(b"-"), numeric("Day"), literal(b"T"), numeric("Hour"), literal(b":"), numeric("Minute"),
                 literal(b":"), numeric("Second"))
        got = self.parse(items, b"2024-01-02T13:04:05!")
        self.assertEqual(self.rest(got), (STR + 19, 1))
        for name, offset, value in (("year", 0x10, 2024), ("month", 0x40, 1), ("day", 0x68, 2), ("hour_div_12", 0x70, 1), ("hour_mod_12", 0x78, 1), ("minute", 0x80, 4),
                                    ("second", 0x88, 5)):
            self.assertEqual(self.field(got, offset), (1, value), name)

    def test_no_items_return_the_whole_input_and_touch_nothing(self):
        got = self.parse((), b"abc")
        self.assertEqual(self.rest(got), (STR, 3))
        self.assertEqual(got[2], bytes(tool.INITIAL))

    def test_year_and_isoyear_take_a_sign_and_then_any_number_of_digits(self):
        self.assertEqual(self.field(self.parse((numeric("Year"),), b"123456"), 0x10), (1, 1234))
        self.assertEqual(self.rest(self.parse((numeric("Year"),), b"123456")), (STR + 4, 2))
        self.assertEqual(self.field(self.parse((numeric("Year"),), b"+123456"), 0x10), (1, 123456))
        self.assertEqual(self.field(self.parse((numeric("IsoYear"),), b"-0042"), 0x28), (1, (-42) & 0xFFFFFFFF))
        self.assertEqual(self.kind(self.parse((numeric("Year"),), b"+2147483648")), tool.OUT_OF_RANGE)
        self.assertEqual(self.field(self.parse((numeric("Year"),), b"-2147483648"), 0x10), (1, 0x80000000))
        self.assertEqual(self.kind(self.parse((numeric("Year"),), b"+9223372036854775808")), tool.OUT_OF_RANGE)
        self.assertEqual(self.kind(self.parse((numeric("Year"),), b"+")), tool.TOO_SHORT)
        self.assertEqual(self.kind(self.parse((numeric("Year"),), b"-a")), tool.INVALID)

    def test_the_timestamp_is_unsigned_in_this_build(self):
        got = self.parse((numeric("Timestamp"),), b"1700000000x")
        self.assertEqual(struct.unpack_from("<QQ", got[2], 0), (1, 1700000000))
        self.assertEqual(self.kind(self.parse((numeric("Timestamp"),), b"-1")), tool.INVALID)
        self.assertEqual(self.kind(self.parse((numeric("Timestamp"),), b"9223372036854775808")), tool.OUT_OF_RANGE)

    def test_each_numeric_kind_checks_its_own_range(self):
        for name, text, bad in (("Month", b"12", b"13"), ("Day", b"31", b"32"), ("Ordinal", b"366", b"367"), ("Minute", b"59", b"60"), ("Second", b"60", b"61"),
                                ("Hour", b"23", b"24"), ("Hour12", b"12", b"00"), ("WeekFromSun", b"53", b"54"), ("IsoWeek", b"53", b"00"),
                                ("NumDaysFromSun", b"6", b"7"), ("WeekdayFromMon", b"7", b"0")):
            good = self.parse((numeric(name),), text)
            self.assertIsNone(self.kind(good), name)
            self.assertEqual(self.kind(self.parse((numeric(name),), bad)), tool.OUT_OF_RANGE, name)

    def test_numeric_width_per_kind_leaves_the_rest_of_the_digits(self):
        for name, width in (("Month", 2), ("Ordinal", 3), ("Year", 4), ("NumDaysFromSun", 1)):
            got = self.parse((numeric(name),), b"1111111")
            self.assertEqual(self.rest(got)[1], 7 - width, name)

    def test_the_pad_bytes_of_a_numeric_item_are_never_read(self):
        for junk in range(7):
            got = self.parse((numeric("Month", junk),), b"  07")
            self.assertEqual(self.field(got, 0x40), (1, 7))

    def test_a_set_once_field_must_agree(self):
        self.assertIsNone(self.kind(self.parse((numeric("Month"),), b"3", ((0x40, tool.word(1, 3)),))))
        self.assertEqual(self.kind(self.parse((numeric("Month"),), b"3", ((0x40, tool.word(1, 4)),))), tool.IMPOSSIBLE)
        self.assertEqual(self.kind(self.parse((numeric("NumDaysFromSun"),), b"0", ((0xA0, bytes((5,))),))), tool.IMPOSSIBLE)
        self.assertIsNone(self.kind(self.parse((numeric("NumDaysFromSun"),), b"0", ((0xA0, bytes((6,))),))))

    def test_weekday_numbers_map_to_monday_zero(self):
        for text, want in ((b"0", 6), (b"1", 0), (b"6", 5)):
            self.assertEqual(self.parse((numeric("NumDaysFromSun"),), text)[2][0xA0], want)
        for text, want in ((b"1", 0), (b"7", 6)):
            self.assertEqual(self.parse((numeric("WeekdayFromMon"),), text)[2][0xA0], want)

    def test_hour12_and_am_pm_combine(self):
        got = self.parse((numeric("Hour12"), fixed("UpperAmPm")), b"12PM")
        self.assertEqual((self.field(got, 0x78), self.field(got, 0x70)), ((1, 0), (1, 1)))
        got = self.parse((numeric("Hour"), fixed("LowerAmPm")), b"13am")
        self.assertEqual(self.kind(got), tool.IMPOSSIBLE)

    def test_literals_are_checked_for_length_first_then_content(self):
        self.assertEqual(self.kind(self.parse((literal(b"ab"),), b"a")), tool.TOO_SHORT)
        self.assertEqual(self.kind(self.parse((literal(b"ab"),), b"ax")), tool.INVALID)
        self.assertEqual(self.rest(self.parse((literal(b"ab", tool.OWNED_LITERAL),), b"abc")), (STR + 2, 1))
        self.assertEqual(self.rest(self.parse((literal("é".encode()),), "é!".encode())), (STR + 2, 1))
        self.assertEqual(self.rest(self.parse((literal(b""),), b"")), (STR, 0))

    def test_space_skips_unicode_white_space_only_at_the_front(self):
        for text, left in (("  x", 1), ("　 x", 1), ("​x", 4), ("x ", 2), ("", 0), ("\u0085 q", 1)):
            for tag in (tool.SPACE, tool.OWNED_SPACE):
                got = self.parse((Item(tag, 0, b" "),), text.encode())
                self.assertEqual(self.rest(got)[1], left, repr(text))

    def test_the_error_item_stops_the_walk_with_the_bad_format_kind(self):
        got = self.parse((numeric("Month"), Item(tool.ERROR), numeric("Day")), b"1 2")
        self.assertEqual(self.kind(got), tool.BAD_FORMAT)
        self.assertEqual(self.field(got, 0x40), (1, 1))
        self.assertNotEqual(self.field(got, 0x68)[0], 1)

    def test_names_fraction_and_zone_name_items(self):
        got = self.parse((fixed("LongWeekdayName"), Item(tool.SPACE), fixed("LongMonthName"), Item(tool.SPACE), numeric("Day")), b"Tuesday January 2")
        self.assertEqual((got[2][0xA0], self.field(got, 0x40), self.field(got, 0x68)), (1, (1, 1), (1, 2)))
        self.assertEqual(self.rest(self.parse((fixed("LongMonthName"),), b"Sept")), (STR + 3, 1))
        self.assertEqual(self.rest(self.parse((fixed("LongMonthName"),), b"SEPTEMBERx")), (STR + 9, 1))
        self.assertEqual(self.field(self.parse((fixed("Nanosecond"),), b".5x"), 0x90), (1, 500000000))
        self.assertEqual(self.field(self.parse((fixed("Nanosecond"),), b".12345678901x"), 0x90), (1, 123456789))
        self.assertEqual(self.rest(self.parse((fixed("Nanosecond"),), b"x")), (STR, 1))
        self.assertEqual(self.field(self.parse((fixed("Nanosecond3NoDot"),), b"123"), 0x90), (1, 123000000))
        self.assertEqual(self.kind(self.parse((fixed("Nanosecond6NoDot"),), b"12345")), tool.TOO_SHORT)
        self.assertEqual(self.rest(self.parse((fixed("TimezoneName"),), b"UTC+9 x")), (STR + 5, 2))

    def test_a_stray_continuation_byte_is_outside_the_modelled_domain(self):
        self.assertFalse(tool.admissible(Case((numeric("Month"),), b"1\x80")))
        self.assertFalse(tool.admissible(Case((literal(b"\x80"),), b"x")))

    def test_the_rule_list_agrees_on_every_named_case(self):
        for case in tool.named_cases():
            self.assertEqual(self.harness.run(case), self.spec.run(case), case.label())


class Controls(Fixture):
    def sample(self, count=1500):
        cases = list(itertools.islice(tool.all_cases(), 0, None, 9))[:count]
        return list(tool.named_cases()) + cases

    def test_every_wrong_rule_is_contradicted(self):
        cases = self.sample()
        for name in tool.SPEC_MUTANTS:
            wrong = tool.Spec(frozenset((name,)))
            self.assertTrue(any(self.harness.run(case) != wrong.run(case) for case in cases), name)

    def test_condition_edits_in_the_interpreter_are_noticed(self):
        rows = cpu.decode_range(self.image, *self.image.exact_fde(tool.INTERNAL))
        cases = self.sample()
        harness = tool.Harness(self.image)
        for case in cases:
            harness.run(case)
        seen = set(harness.machine.seen)
        edits = [edit for edit in cpu.edits_for(self.image, rows, seen) if edit[1] == "condition"]
        self.assertGreater(len(edits), 40)
        killed = 0
        for _, _, patch in edits[:16]:
            edited = tool.Harness(self.image, patch)
            edited.machine.step_limit = 9000
            if tool.first_failure(edited, cases, self.spec) is not None:
                killed += 1
        self.assertGreaterEqual(killed, 13)

    def test_a_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            cpu.load_image(tool.BINARY, "0" * 64)

    def test_addresses_that_are_not_function_starts_are_refused(self):
        for va in (tool.INTERNAL + 1, tool.TRIM - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_a_string_beyond_evaluator_memory_is_refused(self):
        with self.assertRaises(tool.Halt):
            tool.Harness(self.image).run(Case((literal(b"a"),), b"x" * 140000))

    def test_an_item_outside_the_modelled_domain_is_refused_by_the_rule_list(self):
        with self.assertRaises(tool.EvidenceError):
            self.spec.run(Case((Item(tool.FIXED, 0),), b"+01:00"))
        with self.assertRaises(tool.EvidenceError):
            self.spec.run(Case((Item(tool.FIXED, 17),), b"x"))

    def test_a_corrupted_comparison_byte_changes_the_outcome(self):
        # the literal compare result test at 0x1620ca8 (`test eax,eax; jne`): the jne opcode byte 0x85 becomes 0x84
        patch = {0x1620CAB: 0x84}
        edited = tool.Harness(self.image, patch)
        case = Case((literal(b"ab"),), b"ab")
        self.assertNotEqual(edited.run(case), self.spec.run(case))

    def test_dispatch_and_setter_tables_are_read_from_bytes(self):
        rows = tool.dispatch_rows(self.image)
        tags = [row for row in rows if row[0] == "tag"]
        self.assertEqual(len(tags), 7)
        self.assertEqual(tags[2][3], tags[3][3])
        self.assertEqual(len([row for row in rows if row[0] == "numeric-kind"]), 20)
        setters = {row[0]: row for row in tool.setter_rows(self.image)}
        self.assertEqual(setters["set_month"][3:], ("0x40", "month"))
        self.assertEqual(setters["set_timestamp"][3], "0x0")
        self.assertEqual(setters["set_hour12"][3], "0x78")

    def test_call_sites_and_slots_are_read_from_bytes(self):
        rows = tool.caller_rows(self.image)
        self.assertIn(("trim_start", "0x16288c0", "call", "0x1620c4d", "0x1620be0"), rows)
        self.assertIn(("scan_weekday", "0x1625100", "slot-call", "0x1621118", "0x1620be0"), rows)
        slots = {row[0]: row for row in tool.slot_rows(self.image)}
        self.assertEqual(slots["0x64e1b08"][1], "0x1625100")
        self.assertEqual(slots["0x64e1b38"][1], "0x1625680")

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
