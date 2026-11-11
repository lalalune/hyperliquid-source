import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import oi_price_gate_115 as gate  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-open-interest-gate-115"


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = gate.load_image()
        cls.harness = gate.Harness(cls.image)

    def run_case(self, case):
        return gate.compare_run(self.harness, case)


class BinaryTests(Fixture):
    def test_digest_is_checked_first(self):
        with self.assertRaises(gate.EvidenceError):
            gate.load_image(gate.BINARY, "0" * 64)

    def test_functions_are_whole_fdes(self):
        for start, _ in gate.GROUPS:
            begin, end = self.image.exact_fde(start)
            self.assertEqual(begin, start)
            self.assertGreater(end, begin)
        with self.assertRaises(gate.EvidenceError):
            self.image.exact_fde(gate.CHECK + 1)

    def test_text_templates(self):
        self.assertEqual(gate.template(self.image, gate.TEXT_ASSET), "Asset open interest exceeded cap asset={} kind={}, oi={}")
        self.assertEqual(gate.template(self.image, gate.TEXT_MISSING), "Missing price, keeping old {} price asset={} oracle_kind={}")
        self.assertTrue(gate.template(self.image, gate.TEXT_TOTAL).startswith("Total open interest exceeded 10x of total open interest cap"))

    def test_field_reads_and_floats(self):
        self.assertEqual(len(gate.read_fields(self.image)), len(gate.HOST_FIELDS))
        self.assertEqual(len(gate.read_floats(self.image)), len(gate.FLOAT_BYTES))

    def test_wrong_field_expectation_is_refused(self):
        original = gate.HOST_FIELDS
        try:
            gate.HOST_FIELDS = ((0x447ABAB, 0x37C, "wrong"),)
            with self.assertRaises(gate.EvidenceError):
                gate.read_fields(self.image)
        finally:
            gate.HOST_FIELDS = original

    def test_wrong_float_expectation_is_refused(self):
        original = gate.FLOAT_BYTES
        try:
            gate.FLOAT_BYTES = ((0x4593E0, 0.5, "wrong"),)
            with self.assertRaises(gate.EvidenceError):
                gate.read_floats(self.image)
        finally:
            gate.FLOAT_BYTES = original


class CheckTests(Fixture):
    def test_limit_edge(self):
        passing = gate.Case("pass", "check", gate.world(price=1, stored=gate.LIMIT_HIGH - 1, book=0))
        failing = gate.Case("fail", "check", gate.world(price=1, stored=gate.LIMIT_HIGH, book=0))
        self.assertIsNone(self.harness.run(passing)["out"])
        self.assertIsNotNone(self.harness.run(failing)["out"])
        self.assertEqual(self.run_case(passing), "")
        self.assertEqual(self.run_case(failing), "")

    def test_book_total_is_added(self):
        split = gate.Case("split", "check", gate.world(price=1, stored=gate.LIMIT_HIGH - 5, book=5))
        self.assertIsNotNone(self.harness.run(split)["out"])

    def test_negative_book_panics(self):
        answer = self.harness.run(gate.Case("neg", "check", gate.world(book=1 << 63)))
        self.assertEqual(answer["stop"][0], "unwrap")
        self.assertEqual(answer["stop"][1], gate.LOC_CHECK_UNWRAP)

    def test_second_record_needs_the_none_word(self):
        quiet = self.harness.run(gate.Case("q", "check", gate.world(price=1, stored=gate.LIMIT_LOW, book=0)))
        loud = self.harness.run(gate.Case("l", "check", gate.world(mode_min=True, price=1, stored=gate.LIMIT_LOW, book=0)))
        self.assertEqual([event for event in quiet["events"] if event[0] == "record"], [])
        self.assertEqual([event[:2] for event in loud["events"] if event[0] == "record"], [("record", 1)])


class RowTests(Fixture):
    def test_ring_and_tree_agree(self):
        sizes = gate.spread(12)
        for form in ("tree", "ring"):
            for key in sizes:
                case = gate.Case("k", "row", gate.world(asset=key, sizes=sizes, form=form, ring_extra=2, ring_head=5, books=None, price=1))
                self.assertEqual(self.run_case(case), "")

    def test_book_bound_panics_with_the_location(self):
        answer = self.harness.run(gate.Case("b", "row", gate.world(asset=4, books=[0, 0, 0, 0], price=1)))
        self.assertEqual(answer["stop"], ("bounds", 4, 4, gate.LOC_BOOK))

    def test_failing_row_pushes_two_texts(self):
        answer = self.harness.run(gate.Case("f", "row", gate.world(asset=2, sizes={2: gate.LIMIT_HIGH}, price=1)))
        self.assertFalse(answer["out"])
        self.assertEqual(len(answer["errors"]), 2)


class CorpusTests(Fixture):
    def test_curated_cases_match(self):
        bad = [line for line in (self.run_case(case) for case in gate.curated_cases()) if line]
        self.assertEqual(bad, [])

    def test_random_slice_matches(self):
        bad = [line for line in (self.run_case(case) for case in gate.random_cases(1500)) if line]
        self.assertEqual(bad, [])

    def test_random_cases_are_deterministic(self):
        first = [(case.label, sorted(case.world["sizes"].items())) for case in gate.random_cases(50)]
        second = [(case.label, sorted(case.world["sizes"].items())) for case in gate.random_cases(50)]
        self.assertEqual(first, second)


class NegativeControlTests(Fixture):
    def test_every_planted_wrong_rule_is_caught(self):
        cases = gate.curated_cases() + gate.random_cases(600)
        answers = [self.harness.run(case) for case in cases]
        rows = gate.spec_controls(cases, answers)
        self.assertEqual(len(rows), len(gate.SPEC_BUGS))
        self.assertEqual([row["control"] for row in rows if not row["detected"]], [])

    def test_damaged_bytes_change_the_result(self):
        cases = gate.curated_cases()
        for va, kind in ((0x447C6CB + 2, "immediate"), (0x447ABAB, "offset"), (0x3D98949, "immediate")):
            rows = gate.decode_range(self.image, *self.image.fde(va))
            row = [item for item in rows if item.va <= va < item.next][0]
            at = va - row.va
            self.harness.machine.patches = {row.va + at: self.image.blob[self.image.offset(row.va) + at] ^ 1}
            self.harness.machine.cache.clear()
            try:
                caught = any(self.run_case(case) for case in cases)
            finally:
                self.harness.machine.patches = {}
                self.harness.machine.cache.clear()
            self.assertTrue(caught, hex(va))

    def test_out_of_range_input_is_refused(self):
        rows = gate.range_controls(self.image)
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual([row["control"] for row in rows if not row["detected"]], [])

    def test_a_wrong_spec_would_fail_the_corpus(self):
        case = gate.Case("w", "check", gate.world(price=1, stored=gate.LIMIT_HIGH, book=0))
        found = self.harness.run(case)
        self.assertNotEqual(gate.compare_answers(case, found, gate.spec_run(case, "limit_inclusive")), "")


class EvidenceTests(Fixture):
    def test_committed_files_match_a_fresh_run(self):
        files = gate.render(gate.analyse(self.image))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        measure = json.loads(files["measure.json"])
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])


if __name__ == "__main__":
    unittest.main()
