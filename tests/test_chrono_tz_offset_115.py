import itertools
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chrono_tz_offset_115 as tool  # noqa: E402

cpu = tool.cpu
STR = tool.STR


class Fixture(unittest.TestCase):
    image = None

    @classmethod
    def setUpClass(cls):
        cls.image = cpu.load_image(tool.BINARY, tool.SHA256)
        cls.harness = tool.Harness(cls.image)
        cls.spec = tool.Spec()

    def tz(self, data, zulu=0, missing=0, minus=0):
        return self.harness.run(tool.Case(tool.TZ, data, zulu, missing, minus))

    def tail(self, data, date=("ok", 10), time=("ok", 8), pset=0, pval=0):
        return self.harness.run(tool.Case(tool.WRAP, data, date=date, time=time, pset=pset, pval=pval))

    @staticmethod
    def words(blob):
        return struct.unpack_from("<QQi", blob, 0)


class TimezoneOffsetBytes(Fixture):
    def test_numeric_offsets_come_out_in_seconds(self):
        self.assertEqual(self.words(self.tz(b"+05:30")[1]), (STR + 6, 0, 19800))
        self.assertEqual(self.words(self.tz(b"-08:00")[1]), (STR + 6, 0, -28800))
        self.assertEqual(self.words(self.tz(b"+99:59x")[1]), (STR + 6, 1, 99 * 3600 + 59 * 60))

    def test_the_unicode_minus_needs_its_flag(self):
        minus = "−05:30".encode()
        self.assertEqual(self.words(self.tz(minus, 0, 0, 1)[1]), (STR + 8, 0, -19800))
        refused = self.tz(minus, 0, 0, 0)[1]
        self.assertEqual((refused[0:8], refused[8]), (bytes(8), tool.INVALID))

    def test_zulu_is_a_flag_and_case_blind(self):
        for letter in (b"Z", b"z"):
            self.assertEqual(self.words(self.tz(letter + b"x", 1)[1]), (STR + 1, 1, 0))
            self.assertEqual(self.tz(letter, 0)[1][8], tool.INVALID)

    def test_error_tags(self):
        self.assertEqual(self.tz(b"")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.tz(b"+0")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.tz(b"+05:60")[1][8], tool.OUT_OF_RANGE)
        self.assertEqual(self.tz(b"+05:6x")[1][8], tool.INVALID)
        self.assertEqual(self.tz(b"+05")[1][8], tool.TOO_SHORT)
        self.assertEqual(self.words(self.tz(b"+05", 0, 1)[1]), (STR + 3, 0, 18000))
        self.assertEqual(self.tz(b"+05:3", 0, 1)[1][8], tool.TOO_SHORT)

    def test_the_error_result_writes_one_tag_byte_only(self):
        blob = self.tz(b"+0x")[1]
        self.assertEqual(blob[0:8], bytes(8))
        self.assertEqual(blob[9:], tool.FILL[9:])

    def test_a_stray_continuation_byte_is_a_slice_panic(self):
        self.assertEqual(self.tz(b"+\x80"), ("panic", "slice", 1, 2))
        self.assertEqual(self.tz(b"+05\x80", 0, 0, 0), ("panic", "slice", 2, 3))
        self.assertEqual(self.tz(b"Z\x80", 1), ("panic", "slice", 1, 2))
        self.assertEqual(self.tz(b"+05:30\x80"), ("panic", "slice", 2, 3))

    def test_colon_trim_is_inside_the_body(self):
        for gap in (b":", b" ", b" : ", b"\t", "　".encode(), b"::"):
            self.assertEqual(self.words(self.tz(b"+05" + gap + b"30")[1])[2], 19800)

    def test_the_rule_list_agrees_on_every_named_case(self):
        for case in tool.named_cases():
            self.assertEqual(self.harness.run(case), self.spec.run(case), case.label())


class DatetimeTailBytes(Fixture):
    def test_numeric_offset_sets_the_parsed_state(self):
        got = self.tail(b"2020-01-02T03:04:05+05:30")
        self.assertEqual(got[1][0:16], struct.pack("<QQ", STR + 25, 0))
        self.assertEqual(got[2], struct.pack("<Ii", 1, 19800))

    def test_utc_word_means_zero_offset_in_any_case(self):
        for word in (b"UTC", b"utc", b"uTc", b" Utc"):
            got = self.tail(b"2020-01-02T03:04:05" + word, pset=0)
            self.assertEqual(got[2], struct.pack("<Ii", 1, 0))

    def test_a_conflicting_offset_is_the_impossible_tag(self):
        got = self.tail(b"2020-01-02T03:04:05utc", pset=1, pval=5)
        self.assertEqual((got[1][0:8], got[1][8]), (bytes(8), tool.IMPOSSIBLE))
        self.assertEqual(got[2], struct.pack("<Ii", 1, 5))

    def test_an_equal_offset_is_accepted_and_state_is_kept(self):
        got = self.tail(b"2020-01-02T03:04:05+05:30", pset=1, pval=19800)
        self.assertEqual(got[1][0:8], struct.pack("<Q", STR + 25))

    def test_separator_set(self):
        for sep in (b"T", b"t", b" "):
            self.assertEqual(self.tail(b"2020-01-02" + sep + b"03:04:05Z")[1][0:8], struct.pack("<Q", STR + 20))
        refused = self.tail(b"2020-01-02x03:04:05Z")[1]
        self.assertEqual((refused[0:8], refused[8]), (bytes(8), tool.INVALID))

    def test_nothing_after_the_date_is_too_short(self):
        refused = self.tail(b"2020-01-02")[1]
        self.assertEqual((refused[0:8], refused[8]), (bytes(8), tool.TOO_SHORT))

    def test_stub_errors_are_passed_through_unchanged(self):
        for tag in range(7):
            self.assertEqual(self.tail(b"2020-01-02T03:04:05Z", date=("err", tag))[1][8], tag)
            self.assertEqual(self.tail(b"2020-01-02T03:04:05Z", time=("err", tag))[1][8], tag)

    def test_the_stub_sees_the_item_lists_and_windows(self):
        got = self.tail(b"2020-01-02T03:04:05Z")
        self.assertEqual(got[3][0], ("date", tool.PARSED, 0, 20, tool.DATE_ITEMS))
        self.assertEqual(got[3][1], ("time", tool.PARSED, 11, 9, tool.TIME_ITEMS))

    def test_the_first_error_skips_the_time_stub(self):
        got = self.tail(b"2020-01-02T03:04:05Z", date=("err", 3))
        self.assertEqual(len(got[3]), 1)

    def test_nothing_else_in_memory_changes(self):
        self.tail(b"2020-01-02T03:04:05+05:30")


class ZoneBytes(Fixture):
    def zone(self, data):
        return self.harness.run(tool.Case(tool.ZONE, data))

    def test_named_zones_map_to_whole_hours(self):
        want = {b'gmt': 0, b'EST': -5, b'edt': -4, b'cst': -6, b'CDT': -5, b'mst': -7, b'Mdt': -6, b'pst': -8, b'PDT': -7}
        for name, hours in want.items():
            self.assertEqual(self.words(self.zone(name + b' x')[1]), (STR + 3, 2, hours * 3600), name)

    def test_one_and_two_letter_words(self):
        self.assertEqual(self.words(self.zone(b'UT1')[1]), (STR + 2, 1, 0))
        for letter in b'ZzAaIiKkYy':
            self.assertEqual(self.words(self.zone(bytes([letter]))[1]), (STR + 1, 0, 0))
        for letter in b'Jj':
            self.assertEqual(self.zone(bytes([letter]))[1][8], tool.INVALID)

    def test_unknown_words_are_invalid(self):
        for word in (b'utc', b'abcd', b'gmtx', b'ab', b'xyz'):
            self.assertEqual(self.zone(word)[1][8], tool.INVALID, word)

    def test_numeric_form_has_no_colon_and_a_minute_range(self):
        self.assertEqual(self.words(self.zone(b'+0530')[1]), (STR + 5, 0, 19800))
        self.assertEqual(self.words(self.zone(b'-0800x')[1]), (STR + 5, 1, -28800))
        self.assertEqual(self.zone(b'+0560')[1][8], tool.OUT_OF_RANGE)
        self.assertEqual(self.zone(b'+05:30')[1][8], tool.INVALID)
        self.assertEqual(self.zone(b'+053')[1][8], tool.TOO_SHORT)
        self.assertEqual(self.zone(b'+')[1][8], tool.TOO_SHORT)
        self.assertEqual(self.zone(b'')[1][8], tool.TOO_SHORT)
        self.assertEqual(self.zone('\u22120530'.encode())[1][8], tool.INVALID)

    def test_boundary_panics(self):
        self.assertEqual(self.zone(b'gmt\x80'), ('panic', 'slice', 3, 4))
        self.assertEqual(self.zone(b'+\x80'), ('panic', 'slice', 1, 2))
        self.assertEqual(self.zone(b'+0530\x80'), ('panic', 'slice', 2, 3))

    def test_every_three_letter_word_matches_the_table(self):
        names = set(tool.ZONE_NAMES)
        for a in 'abcdefghijklmnopqrstuvwxyz':
            for b in 'cdemstuxyz':
                word = (a + b + 't').encode()
                got = self.zone(word)[1]
                self.assertEqual(got[0:8] != bytes(8), word.decode() in names, word)

    def test_zone_wrong_rules_are_contradicted(self):
        cases = [case for case in tool.named_cases() if case.kind == tool.ZONE] + [tool.Case(tool.ZONE, b'gmtx')] + list(itertools.islice(tool.zone_cases(tool.lcg(1)), 0, None, 7))
        for name in tool.ZONE_MUTANTS:
            wrong = tool.Wrong(frozenset((name,)))
            self.assertTrue(any(self.harness.run(case) != wrong.run(case) for case in cases), name)


class Controls(Fixture):
    def sample(self, count=2500):
        cases = list(itertools.islice(tool.all_cases(), 0, None, 20))[:count]
        return list(tool.named_cases()) + cases

    def test_every_wrong_rule_is_contradicted(self):
        cases = self.sample()
        for name in tool.SPEC_MUTANTS + tool.WRONG_MUTANTS:
            wrong = tool.Wrong(frozenset((name,)))
            self.assertTrue(any(self.harness.run(case) != wrong.run(case) for case in cases), name)

    def test_condition_edits_in_the_body_are_noticed(self):
        rows = tool.cpu.decode_range(self.image, *self.image.exact_fde(tool.TZ))
        cases = self.sample()
        harness = tool.Harness(self.image)
        harness.machine.step_limit = 4000
        seen = set()
        for case in cases:
            harness.run(case)
        seen = set(harness.machine.seen)
        killed = 0
        edits = [edit for edit in cpu.edits_for(self.image, rows, seen) if edit[1] == "condition"]
        self.assertGreater(len(edits), 20)
        for _, _, patch in edits[:12]:
            edited = tool.Harness(self.image, patch)
            edited.machine.step_limit = 4000
            if tool.first_failure(edited, cases, self.spec) is not None:
                killed += 1
        self.assertGreaterEqual(killed, 11)

    def test_a_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            cpu.load_image(tool.BINARY, "0" * 64)

    def test_addresses_that_are_not_function_starts_are_refused(self):
        for va in (tool.TZ + 1, tool.WRAP - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_a_string_beyond_evaluator_memory_is_refused(self):
        with self.assertRaises(tool.Halt):
            tool.Harness(self.image).run(tool.Case(tool.TZ, b"1" * 140000, 1, 1, 1))

    def test_a_flipped_stub_argument_is_noticed(self):
        case = tool.Case(tool.WRAP, b"2020-01-02T03:04:05Z", date=("ok", 10), time=("ok", 8))
        got = self.harness.run(case)
        wrong = self.spec.run(case)
        self.assertEqual(got, wrong)
        swapped = list(wrong[3])
        swapped[0], swapped[1] = swapped[1], swapped[0]
        self.assertNotEqual(got[3], tuple(swapped))

    def test_the_filter_keeps_str_inputs_and_boundary_probes_only(self):
        self.assertTrue(tool.admissible(tool.Case(tool.TZ, b"+05:30", 0, 0, 0)))
        self.assertTrue(tool.admissible(tool.Case(tool.TZ, b"+\x80", 0, 0, 0)))
        self.assertFalse(tool.admissible(tool.Case(tool.TZ, b"+0\x80", 0, 0, 0)))
        self.assertFalse(tool.admissible(tool.Case(tool.TZ, b"\x80+05", 0, 0, 0)))

    def test_call_sites_are_read_from_bytes(self):
        sites = {site for site, target, call in tool.text_calls(self.image) if target == tool.TZ and call}
        self.assertEqual(sites, {0x162026B, 0x16202CA, 0x1620748, 0x1620E0E, 0x1621865})
        rows = tool.flag_rows(self.image, {})
        self.assertIn(("0x1621730", "0x1621865", "1", "0", "1"), rows)
        self.assertIn(("0x161ffc0", "0x1620748", "1", "1", "1"), rows)

    def test_item_lists_match_the_shape_of_a_date_and_a_time(self):
        rows = tool.item_rows(self.image)
        date = [row[3] for row in rows if row[0] == "DATE"]
        time = [row[3] for row in rows if row[0] == "TIME"]
        self.assertEqual(date, ["Numeric", "Space", "Literal", "Numeric", "Space", "Literal", "Numeric"])
        self.assertEqual(time, ["Numeric", "Space", "Literal", "Numeric", "Space", "Literal", "Numeric", "Fixed", "Space"])

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
