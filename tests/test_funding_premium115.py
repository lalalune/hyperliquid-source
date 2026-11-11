import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import funding_premium115 as fp  # noqa: E402


def bits(value):
    return fp.to_bits(value)


def value(outcome):
    return fp.to_float(outcome[1])


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = fp.load_image()
        cls.k = fp.constant_bits(cls.image)
        cls.harness = fp.Harness(cls.image)
        cls.cases = list(fp.named_cases()) + list(fp.random_cases(1500, seed=0xBEEF))
        cls.reached = fp.collections.Counter()
        cls.stats, cls.caught, cls.sample = fp.check_stream(cls.harness, cls.cases, cls.k, fp.VARIANTS, keep=50, hits=cls.reached)


class TestImage(unittest.TestCase):
    def test_digest_is_pinned(self):
        self.assertEqual(fp.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(fp.EvidenceError):
            fp.load_image(fp.BINARY, "0" * 64)

    def test_subject_is_one_fde(self):
        image = fp.load_image()
        start, end = image.exact_fde(fp.PREMIUM)
        self.assertEqual((start, end - start), (0x44D9060, 0x4A4))
        self.assertEqual(image.exact_fde(fp.RATE_BODY)[1] - fp.RATE_BODY, 0x47F)
        with self.assertRaises(fp.EvidenceError):
            image.exact_fde(fp.PREMIUM + 1)

    def test_constants_come_from_the_bytes(self):
        k = fp.constant_bits(fp.load_image())
        self.assertEqual(fp.one(k, "half"), 0.5)
        self.assertEqual(fp.one(k, "negative_half"), -0.5)
        self.assertEqual(fp.one(k, "hundred"), 100.0)
        self.assertEqual(fp.one(k, "negative_one"), -1.0)
        self.assertEqual([fp.scale_of(k, i) for i in range(7)], [10.0 ** i for i in range(7)])
        self.assertEqual(k["half_pair"], k["half"] * 2)
        self.assertEqual(fp.word(k, "finite_limit"), 0x7FDFFFFFFFFFFFFF)
        self.assertEqual(fp.word(k, "abs_mask"), 0x7FFFFFFFFFFFFFFF)

    def test_panic_locations_are_decoded_without_absolute_paths(self):
        rows = fp.location_rows(fp.load_image())
        self.assertEqual([row[2] for row in rows], ["l1/src/perp_meta.rs", "l1/src/perp_meta.rs", "z_vendor/indexmap/src/map.rs"])
        self.assertEqual([(row[3], row[4]) for row in rows], [(163, 38), (287, 28), (762, 26)])


class TestRuleList(unittest.TestCase):
    k = None

    @classmethod
    def setUpClass(cls):
        cls.k = fp.constant_bits(fp.load_image())

    def case(self, **fields):
        base = dict(asset=20007, oracle=1000000, dex=2, count=9, decimals=1, flag=0, default=10 ** 8, overrides=[], impact=(1010000, 1020000))
        base.update(fields)
        return fp.Case("hand", base.pop("asset"), base.pop("oracle"), base.pop("dex"), base.pop("count"), base.pop("decimals"),
                       base.pop("flag"), base.pop("default"), base.pop("overrides"), base.pop("impact"), **base)

    def test_mid_formula(self):
        # decimals 1 -> scale 1e5: oracle 10, sides 10.1 and 10.2, mid 10.15, 10.15 / 10 - 1 = 0.015
        outcome, log = fp.spec_premium(self.case(), self.k)
        self.assertAlmostEqual(value(outcome), 0.015, places=12)
        self.assertEqual(outcome[2:], (1010000, 1020000))
        self.assertEqual(log, [("impact", 0xA8, 10 ** 8), ("impact", 0xC8, 10 ** 8)])

    def test_impact_gap_formula(self):
        # up = max(10.1 - 10, 0) = 0.1, down = max(10 - 10.2, 0) = 0: (0.1 - 0) / 10
        outcome, _ = fp.spec_premium(self.case(flag=1), self.k)
        self.assertAlmostEqual(value(outcome), 0.01, places=12)
        outcome, _ = fp.spec_premium(self.case(flag=1, impact=(990000, 980000)), self.k)
        self.assertAlmostEqual(value(outcome), -0.02, places=12)

    def test_hl_only_divides_before_the_clamp(self):
        outcome, _ = fp.spec_premium(self.case(impact=(1500000, 1500000), hl_set=[20007]), self.k)
        self.assertAlmostEqual(value(outcome), 0.005, places=12)           # (15/10 - 1) / 100
        outcome, _ = fp.spec_premium(self.case(impact=(1500000, 1500000)), self.k)
        self.assertEqual(value(outcome), 0.5)                              # clamped at the band edge
        outcome, _ = fp.spec_premium(self.case(impact=(1, 1)), self.k)
        self.assertAlmostEqual(value(outcome), -0.5, places=12)

    def test_band_is_half(self):
        high, _ = fp.spec_premium(self.case(impact=((1 << 64) - 1,) * 2, decimals=6, oracle=1000), self.k)
        self.assertEqual(value(high), 0.5)
        low, _ = fp.spec_premium(self.case(flag=1, impact=(1, 1), oracle=10 ** 9), self.k)
        self.assertEqual(value(low), -0.5)

    def test_none_leaves_the_premium_word_alone(self):
        for case in (self.case(oracle=0), self.case(impact=(0, 5)), self.case(impact=(5, 0))):
            outcome, _ = fp.spec_premium(case, self.k)
            self.assertEqual(outcome, ("ret", fp.OUT_SENTINEL[0], 0, fp.OUT_SENTINEL[2]))

    def test_second_side_is_asked_even_when_the_first_is_zero(self):
        _, log = fp.spec_premium(self.case(impact=(0, 5)), self.k)
        self.assertEqual([entry[1] for entry in log], [0xA8, 0xC8])

    def test_override_lookup_shapes(self):
        one = self.case(overrides=[(20007, 77)])
        self.assertEqual(fp.spec_premium(one, self.k)[1][0], ("impact", 0xA8, 77))
        many = self.case(overrides=[(1, 11), (2, 22), (20007, 77)])
        log = fp.spec_premium(many, self.k)[1]
        self.assertEqual(log[:3], [("hash", 20007), ("find", 20007), ("impact", 0xA8, 77)])
        miss = self.case(overrides=[(1, 11), (2, 22)])
        self.assertEqual(fp.spec_premium(miss, self.k)[1][2], ("impact", 0xA8, 10 ** 8))
        bad = self.case(overrides=[(1, 11), (2, 22)], bad_index=True)
        self.assertEqual(fp.spec_premium(bad, self.k)[0][0], "panic")

    def test_panics(self):
        self.assertEqual(fp.spec_premium(self.case(dex=3), self.k)[0][0], "panic")
        self.assertEqual(fp.spec_premium(self.case(asset=20009), self.k)[0][0], "panic")
        self.assertEqual(fp.spec_premium(self.case(decimals=7), self.k)[0][0], "panic")
        self.assertEqual(fp.spec_premium(self.case(decimals=6), self.k)[0][0], "ret")

    def test_oracle_zero_side_call(self):
        self.assertEqual(fp.spec_premium(self.case(oracle=0, once_word=3), self.k)[1], [("once", fp.ONCE_WORD)])
        self.assertEqual(fp.spec_premium(self.case(oracle=0), self.k)[1], [])

    def test_every_variant_changes_some_hand_case(self):
        probes = [self.case(), self.case(flag=1), self.case(impact=(1500000, 1500000), hl_set=[20007]), self.case(oracle=0, once_word=1), self.case(oracle=0),
                  self.case(impact=(0, 5)), self.case(decimals=7), self.case(dex=3), self.case(asset=20009), self.case(impact=(1, 1)),
                  self.case(overrides=[(1, 11), (20007, 0)], default=9), self.case(overrides=[(1, 11), (20007, 5)]),
                  self.case(oracle=1 << 63), self.case(oracle=(1 << 63) + 10 ** 9, impact=((1 << 63) + 10 ** 9,) * 2), self.case(impact=(10 ** 9, 10 ** 9), hl_set=[20007]), self.case(flag=1, impact=(1500000, 1500000), hl_set=[20007])]
        for name in fp.VARIANTS:
            changed = any(fp.spec_premium(case, self.k, frozenset((name,))) != fp.spec_premium(case, self.k) for case in probes)
            if name == "first_entry_only":
                changed = fp.spec_premium(self.case(overrides=[(1, 11), (20007, 5)]), self.k, frozenset((name,))) != \
                    fp.spec_premium(self.case(overrides=[(1, 11), (20007, 5)]), self.k)
            self.assertTrue(changed, name)

    def test_tree_shape_keeps_every_key(self):
        items = list(range(1, 20))

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
            self.assertEqual(flatten(fp.split_tree(items, height, list(plan))), items)


class TestBytes(Fixture):
    def test_every_case_matches(self):
        self.assertEqual(self.stats["cases"], len(self.cases))
        self.assertGreater(self.stats["cases"], 1500)
        self.assertEqual(self.stats["mismatches"], 0, self.stats["first_mismatch"])

    def test_all_outcomes_occur_for_both_formulas(self):
        kinds = set(self.stats["kinds"])
        for formula in ("mid", "binance"):
            for outcome in ("premium", "none", "local", "decimals", "bounds"):
                self.assertIn((formula, outcome), kinds)

    def test_every_named_deviation_is_refused(self):
        for name in fp.VARIANTS:
            self.assertGreater(self.caught[name][0], 0, name)

    def test_every_instruction_class_is_reached(self):
        start, end = self.image.exact_fde(fp.PREMIUM)
        rows = fp.decode_range(self.image, start, end)
        reached = sum(1 for row in rows if row.va in self.reached)
        self.assertGreater(reached / len(rows), 0.9)
        # the only unreached arms: the non-finite sum arm, the duplicated decimals panic, the nonfinite clamp bypass and the second bounds copy
        unreached = [row.va for row in rows if row.va not in self.reached]
        self.assertLess(len(unreached), 30)

    def test_condition_and_field_edits_are_seen(self):
        mutants = fp.mutants_of(self.image, self.reached)
        self.assertGreater(len(mutants), 60)
        picked = [m for m in mutants if m[1] in ("condition", "displacement")][:14]
        rows = fp.run_mutants(self.image, picked, self.cases[:len(fp.named_cases()) + 300], self.k)
        survivors = [row for row in rows if not row[5]]
        # the cold Once closure edits are caught by the closure chain check; only arithmetic-equivalent edits may survive
        self.assertLessEqual(len(survivors), 1, survivors)

    def test_equivalent_survivors_are_the_finite_arm_selector(self):
        picked = [m for m in fp.mutants_of(self.image, self.reached) if m[0] in (0x44D9377, 0x44D937A)]
        self.assertEqual(len(picked), 2)
        rows = fp.run_mutants(self.image, picked, self.cases[:300], self.k)
        self.assertEqual([row[5] for row in rows], [False, False])

    def test_structural_controls_all_detected(self):
        results = fp.structural_controls(self.image, self.harness, self.k, self.cases)
        self.assertGreaterEqual(len(results), 15)
        for name, detected, _ in results:
            self.assertTrue(detected, name)

    def test_stale_slot_past_the_node_length_is_not_a_member(self):
        case = next(c for c in fp.named_cases() if c.name == "stale-key-past-length")
        got, _ = fp.run_case(self.harness, case)
        member = fp.Case(case.name, case.asset, case.oracle, case.dex, case.count, case.decimals, case.flag, case.default, [],
                         case.impact, hl_set=[1, 2, case.asset])
        divided, _ = fp.run_case(self.harness, member)
        self.assertNotEqual(got, divided)
        self.assertEqual(got, fp.spec_premium(case, self.k)[0])

    def test_unmodelled_inputs_stop_the_evaluator(self):
        case = next(c for c in fp.named_cases() if c.name == "override-many-found-last")
        for patches in ({fp.PREMIUM: 0xCC}, {fp.PREMIUM + 0x11: 0x0F}):
            got, _ = fp.run_case(fp.Harness(self.image, patches), case)
            self.assertNotEqual(got, fp.spec_premium(case, self.k)[0])

    def test_output_pointer_is_the_only_write_target(self):
        for case in self.cases[:40]:
            self.harness.run(case)        # raises Halt if the heap changed outside the output record


class TestTables(Fixture):
    def test_render_is_deterministic_and_clean(self):
        first = fp.analyse(150, mutate=False, image=self.image)
        second = fp.analyse(150, mutate=False, image=self.image)
        one, two = fp.render(first), fp.render(second)
        self.assertEqual(one, two)
        for name, text in one.items():
            self.assertNotIn("/" + "home", text, name)
            self.assertNotIn("/" + "tmp", text, name)
        self.assertEqual(sorted(one), sorted(set(one)))

    def test_measure_counts_match_the_run(self):
        result = fp.analyse(150, mutate=False, image=self.image)
        files = fp.render(result)
        import json
        measure = json.loads(files["measure.json"])
        self.assertEqual(measure["cases"], 150 + len(fp.named_cases()))
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(measure["negative_controls"], 30)

    def test_owner_fields_show_the_shared_tracker_layout(self):
        rows = fp.field_rows(self.image)
        premium = {(reg, disp) for body, reg, disp, _ in rows if body == "premium"}
        rate = {(reg, disp) for body, reg, disp, _ in rows if body == "rate"}
        for field in ("0x148", "0x150", "0x158", "0x168", "0x38", "0x40", "0x10", "0x8"):
            self.assertIn(("rsi", field), premium)
        for field in ("0x48", "0x90", "0xd8", "0x120", "0x140"):
            self.assertIn(("rbx", field), rate)

    def test_slot_rows_name_both_bodies(self):
        rows = fp.slot_rows(self.image)
        self.assertEqual([(slot, addend) for slot, addend, _ in rows], [("0x00000000064e5f70", "0x44d9060"), ("0x00000000064e7898", "0x44d8590")])


if __name__ == "__main__":
    unittest.main()
