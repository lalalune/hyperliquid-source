import itertools
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import funding_rate115 as fr  # noqa: E402


def bits(value):
    return fr.to_bits(value)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = fr.load_image()
        cls.k = fr.constant_bits(cls.image)
        cls.harness = fr.Harness(cls.image)
        cls.cases = fr.named_cases() + fr.random_cases(1500, seed=0xBEEF)
        cls.reached = fr.collections.Counter()
        cls.stats, cls.caught, cls.sample = fr.check_stream(cls.harness, cls.cases, cls.k, fr.VARIANTS, keep=50, hits=cls.reached)


class TestImage(unittest.TestCase):
    def test_digest_is_pinned(self):
        self.assertEqual(fr.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(fr.EvidenceError):
            fr.load_image(fr.BINARY, "0" * 64)

    def test_subject_is_one_fde(self):
        image = fr.load_image()
        start, end = image.exact_fde(fr.RATE)
        self.assertEqual((start, end - start), (0x44D8590, 0x47F))
        self.assertEqual(image.exact_fde(fr.BSEARCH)[1] - fr.BSEARCH, 0x121)
        with self.assertRaises(fr.EvidenceError):
            image.exact_fde(fr.RATE + 1)

    def test_constants_come_from_the_bytes(self):
        k = fr.constant_bits(fr.load_image())
        self.assertEqual(k["default_interest"], 0x3F1A36E2EB1C432D)
        self.assertEqual(k["default_multiplier"], bits(1.0))
        self.assertEqual(k["sum_start"], 1 << 63)
        self.assertEqual(fr.to_float(k["rate_ceiling"]), -fr.to_float(k["rate_floor"]))
        self.assertEqual(fr.to_float(k["output_scale"]), 0.125)


class TestRuleList(unittest.TestCase):
    def test_hand_value(self):
        k = fr.constant_bits(fr.load_image())
        case = fr.named_cases()[0]
        self.assertEqual(case.name, "deque single sample")
        expected, log = fr.spec_rate(case, k)
        self.assertEqual(log, [])
        # average 1e-4, interest 1.25e-5, difference inside the clamp, multiplier 1, scale 0.125
        self.assertEqual(expected[0], "some")
        self.assertAlmostEqual(fr.to_float(expected[1]), 1e-4 * 0.125, places=15)

    def test_hand_value_with_the_pull_limited_by_the_clamp(self):
        k = fr.constant_bits(fr.load_image())
        empty = {name: [] for name, _ in fr.MAPS}
        # average 0.05, default interest 1e-4, clamp 0.01: the pull is limited to -0.01, so 0.04 is scaled to 0.005
        case = fr.Case("hand", "deque", [(1, [bits(0.05)])], 1, empty, bits(0.01), cap=2, head=0)
        expected, _ = fr.spec_rate(case, k)
        self.assertAlmostEqual(fr.to_float(expected[1]), 0.005, places=12)
        self.assertEqual(fr.run_case(fr.Harness(fr.load_image()), case)[0], expected)

    def test_arith_agrees_between_rule_list_and_evaluator(self):
        specials = [0, 1 << 63, bits(1.0), bits(-2.5), 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000001, 0xFFF8000000000000,
                    0x7FF4000000000007, 0x7FEFFFFFFFFFFFFF, 1, bits(3.0)]
        for op in ("add", "sub", "mul", "div"):
            for a, b in itertools.product(specials, repeat=2):
                self.assertEqual(fr.arith(op, a, b), fr.sse_arith(op, a, b), (op, hex(a), hex(b)))

    def test_nan_rules(self):
        first, second = 0x7FF8000000000001, 0xFFF8000000000002
        self.assertEqual(fr.arith("add", first, second), first)
        self.assertEqual(fr.arith("add", bits(1.0), second), second)
        self.assertEqual(fr.arith("add", 0x7FF4000000000007, bits(1.0)), 0x7FFC000000000007)
        self.assertEqual(fr.arith("sub", 0x7FF0000000000000, 0x7FF0000000000000), fr.INDEFINITE)
        self.assertEqual(fr.arith("div", 0, 0), fr.INDEFINITE)
        self.assertEqual(fr.arith("div", bits(1.0), 1 << 63), 0xFFF0000000000000)

    def test_min_max_pick_the_second_operand_on_ties_and_nan(self):
        plus, minus, nan = 0, 1 << 63, 0x7FF8000000000000
        self.assertEqual(fr.smin(plus, minus), minus)
        self.assertEqual(fr.smin(minus, plus), plus)
        self.assertEqual(fr.smax(plus, minus), minus)
        self.assertEqual(fr.smin(nan, bits(1.0)), bits(1.0))
        self.assertEqual(fr.smin(bits(1.0), nan), nan)

    def test_tree_shape_keeps_every_key(self):
        items = [(k, [k]) for k in range(1, 20)]

        def flatten(shape):
            keys, children = shape
            if children is None:
                return list(keys)
            out = []
            for index, child in enumerate(children):
                out += flatten(child)
                if index < len(keys):
                    out.append(keys[index])
            return out

        for height, plan in ((1, [3]), (2, [3, 3, 3, 3]), (2, [2, 4, 2, 2, 2])):
            self.assertEqual(flatten(fr.split_tree(items, height, list(plan))), items)


class TestBytes(Fixture):
    def test_every_case_matches(self):
        self.assertEqual(self.stats["cases"], len(self.cases))
        self.assertGreater(self.stats["cases"], 1500)
        self.assertEqual(self.stats["mismatches"], 0, self.stats["first_mismatch"])

    def test_both_stores_and_all_outcomes_occur(self):
        kinds = set(self.stats["kinds"])
        for store in ("deque", "btree"):
            for outcome in ("some", "none"):
                self.assertIn((store, outcome), kinds)
        self.assertIn(("btree", "panic"), kinds)

    def test_every_deviation_is_refused(self):
        for name in fr.VARIANTS:
            self.assertGreater(self.caught[name][0], 0, name)

    def test_most_instructions_are_reached(self):
        for entry in (fr.RATE, fr.BSEARCH):
            rows = fr.decode_range(self.image, *self.image.exact_fde(entry))
            reached = sum(1 for row in rows if self.reached[row.va])
            self.assertGreater(reached / len(rows), 0.9, hex(entry))

    def test_structural_controls_are_all_detected(self):
        controls = fr.structural_controls(self.image, self.harness, self.k, self.cases)
        self.assertGreaterEqual(len(controls), 10)
        for name, detected, _ in controls:
            self.assertTrue(detected, name)

    def test_condition_edits_are_caught_except_the_proved_equivalent(self):
        mutants = [m for m in fr.mutants_of(self.image, self.reached) if m[1] == "condition"]
        self.assertGreater(len(mutants), 20)
        picked = self.cases[:40] + self.cases[40::25]
        rows = fr.run_mutants(self.image, mutants, picked, self.k)
        equivalent = {0x4556372}      # equal keys: the carry is clear, so the skipped adc adds nothing
        for va, kind, at, old, new, killed, first in rows:
            if va not in equivalent:
                self.assertTrue(killed, hex(va))

    def test_unreached_index_guard_is_exercised_by_a_faulty_probe(self):
        faulty = [case for case in self.cases if case.bad_index]
        self.assertGreater(len(faulty), 5)
        panics = 0
        for case in faulty:
            got, log = fr.run_case(self.harness, case)
            expected = fr.spec_rate(case, self.k)
            self.assertEqual((got, log), expected)
            panics += got == ("panic", "bounds")
        self.assertGreater(panics, 3)


class TestRender(Fixture):
    def test_render_is_deterministic_and_complete(self):
        result = {"image": self.image, "k": self.k, "stats": self.stats, "caught": self.caught, "sample": self.sample,
                  "reached": self.reached, "cases": len(self.cases), "structural": [("x", True, "y")], "mutants": []}
        one, two = fr.render(result), fr.render(result)
        self.assertEqual(one, two)
        self.assertEqual(set(one), {"constants.tsv", "owner-fields.tsv", "pointer-slots.tsv", "direct-callers.tsv", "function-rows.tsv",
                                    "outcomes.tsv", "cases-sample.tsv", "variants.tsv", "structural-controls.tsv", "mutants.tsv",
                                    "evidence.json", "measure.json"})
        measure = fr.json.loads(one["measure.json"])
        for key in ("cases", "negative_controls", "negative_detected"):
            self.assertIn(key, measure)
        self.assertEqual(measure["negative_controls"], len(fr.VARIANTS) + 1)

    def test_owner_fields_name_every_structure_offset(self):
        text = fr.render({"image": self.image, "k": self.k, "stats": self.stats, "caught": self.caught, "sample": [],
                          "reached": self.reached, "cases": 0, "structural": [], "mutants": []})["owner-fields.tsv"]
        for offset in ("0x48", "0x50", "0x90", "0xd8", "0x120", "0x128", "0x130", "0x138", "0x140"):
            self.assertIn("\n" + offset + "\t", text)


if __name__ == "__main__":
    unittest.main()
