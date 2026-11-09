import collections
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vault_base_conversion115 as v  # noqa: E402


class VaultBaseConversionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = v.load_image()
        cls.harness = v.Harness(cls.image)
        cls.named = v.named_cases()
        cls.random = list(v.random_cases(900, seed=0x5EED0001))

    def check(self, case, flags=frozenset()):
        return v.run_case(self.harness, case) == v.spec_loop(case, flags)

    def test_image_and_boundaries(self):
        self.assertEqual(self.image.exact_fde(v.LOOP)[1] - v.LOOP, 994)
        self.assertEqual(self.image.exact_fde(v.CALLEE)[1] - v.CALLEE, 0x167)
        self.assertEqual(self.image.exact_fde(v.RANGE)[1] - v.RANGE, 548)

    def test_named_cases_match_the_rule_list(self):
        for case in self.named:
            self.assertTrue(self.check(case), case.name)

    def test_random_cases_match_the_rule_list(self):
        for case in self.random:
            self.assertTrue(self.check(case), case.name)

    def test_random_mix_reaches_every_outcome_kind(self):
        kinds = collections.Counter()
        for case in self.random:
            outcome, log = v.spec_loop(case)
            kinds[outcome[0] if outcome[0] != "panic" else "panic-" + outcome[1]] += 1
            if log:
                kinds["events"] += 1
        for kind in ("ok", "panic-bounds", "panic-unwrap", "halt", "events"):
            self.assertGreater(kinds[kind], 0, kind)

    def test_every_named_wrong_reading_is_refused(self):
        refused = set()
        for case in self.named + self.random:
            got = v.run_case(self.harness, case)
            for name in v.VARIANTS:
                if name not in refused and v.spec_loop(case, frozenset((name,))) != got:
                    refused.add(name)
        self.assertEqual(refused, set(v.VARIANTS))

    def test_structural_controls_all_detected(self):
        for name, detected, how in v.structural_controls(self.image, self.named):
            self.assertTrue(detected, name)

    def test_reciprocal_matches_division(self):
        for key in v.EDGE_KEYS:
            self.assertEqual(v.reciprocal(key), key // 10000)

    def test_amount_rules_by_hand(self):
        log = []
        row = v.row_value(0, 7, 0, 3, 0)
        self.assertEqual(v.amount_spec(row, 100, 1, 255, 0, log), ("ok", 0, 300, 42, 300, 0, 42))
        self.assertEqual(v.amount_spec(row, 100, 4, 5, 0, log)[6], 60)
        self.assertEqual(v.amount_spec(row, 100, 0, 5, 0, log)[6], 0)
        carried = v.amount_spec(v.row_value(1, 7, -500, 3, 0), 100, 1, 255, 0, log)
        self.assertEqual(carried[:6], ("ok", 1, -200, 0, 300, -500))
        self.assertEqual(v.amount_spec(row, 1 << 63, 1, 255, 0, log), ("panic", "unwrap"))
        self.assertEqual(v.amount_spec(v.row_value(0, 1, 0, v.INT_MAX, 0), 3, 1, 255, 0, log), ("panic", "unwrap"))
        down = v.amount_spec(row, 100, 2, 255, 4, [])
        up = v.amount_spec(row, 100, 3, 255, 4, [])
        self.assertEqual((down[6], up[6]), ((300 * 1 + 4) // 3, (300 + 4 + 2) // 3))

    def test_saturating_adds(self):
        log = []
        self.assertEqual(v.sat_signed(v.INT_MAX, 1, v.LOC_SIGNED, log), v.INT_MAX)
        self.assertEqual(v.sat_signed(v.INT_MIN, -1, v.LOC_SIGNED, log), v.INT_MIN)
        self.assertEqual(v.sat_unsigned(v.U64, 1, v.LOC_UNSIGNED, log), v.U64)
        self.assertEqual(v.sat_unsigned(5, 6, v.LOC_UNSIGNED, log), 11)
        self.assertEqual(log, [("overflow", v.LOC_SIGNED)] * 2 + [("overflow", v.LOC_UNSIGNED)])

    def test_tree_shapes_are_valid(self):
        for case in self.named:
            if case.store == "btree" and case.items:
                shape = v.tree_shape(case)
                self.assertIsNotNone(shape, case.name)
                self.assertEqual(v.shape_walk(shape), list(case.items))

    def test_byte_edits_are_caught(self):
        reached = collections.Counter()
        harness = v.Harness(self.image)
        for case in self.named[:40]:
            v.run_case(harness, case)
            reached.update(harness.machine.seen)
        edits = v.mutants_of(self.image, reached)
        self.assertGreater(len(edits), 30)
        killed = 0
        for edit in edits[:: max(1, len(edits) // 25)]:
            va, kind, at, old, new = edit
            patched = v.Harness(self.image, {at: new})
            patched.machine.step_limit = v.MUTANT_STEP_LIMIT
            if any(v.run_case(patched, case) != v.spec_loop(case) for case in self.named + self.random[:200]):
                killed += 1
        self.assertGreater(killed, 15)

    def test_out_of_range_inputs_do_not_pass(self):
        case = next(c for c in self.named if c.name == "deque accumulators saturate")
        broken = v.Harness(self.image, {v.CALLEE: 0xCC})
        self.assertEqual(v.run_case(broken, case)[0][0], "halt")
        with self.assertRaises(v.EvidenceError):
            self.image.offset(0)
        with self.assertRaises(v.EvidenceError):
            v.load_image(v.BINARY, "1" * 64)

    def test_source_has_no_external_programs_or_paths(self):
        text = pathlib.Path(v.__file__).read_text()
        for needle in ("subprocess", "os." + "system", "/" + "home/", "/" + "mnt/", "/" + "srv/", "/" + "tmp/"):
            self.assertNotIn(needle, text)


class AmountBodyTests(unittest.TestCase):
    """Direct calls of the per-entry body 0x448b800: the rule list against the real bytes on grids and hand-made rows."""

    @classmethod
    def setUpClass(cls):
        cls.image = v.load_image()
        cls.harness = v.Harness(cls.image)

    def run_one(self, row, value, mode, capb=255, ctx=0):
        case = v.AmountCase("hand", row, value, mode, capb, ctx)
        got = v.run_case(self.harness, case)
        self.assertEqual(got, v.spec_case(case), (row, value, mode))
        return got

    def test_grid_matches_for_every_combination(self):
        count = 0
        for case in v.grid_cases():
            self.assertEqual(v.run_case(self.harness, case), v.spec_case(case), case.name)
            count += 1
        self.assertEqual(count, 5 * len(v.GRID_VALUES) * len(v.GRID_MULTS) * len(v.GRID_ROWS))

    def test_quotient_rules_per_mode(self):
        row = v.row_value(0, 7, 0, 5, 9)
        self.assertEqual(self.run_one(row, 1000, 0)[0][6], 0)
        self.assertEqual(self.run_one(row, 1000, 1)[0][6], 5000 // 7)
        self.assertEqual(self.run_one(row, 1000, 4, capb=3)[0][6], 5000 // 3)
        self.assertEqual(self.run_one(row, 1000, 4, capb=200)[0][6], 5000 // 7)
        self.assertEqual(self.run_one(row, 1000, 2, ctx=11)[0][6], (5000 * 10 + 11) // 3)
        self.assertEqual(self.run_one(row, 1000, 3, ctx=11)[0][6], (5000 * 10 + 11 + 2) // 3)

    def test_stub_events_are_the_only_events(self):
        row = v.row_value(0, 7, 0, 5, 9)
        self.assertEqual(self.run_one(row, 1000, 2, ctx=11)[1], [("prep", 11, 9), ("down", 5000)])
        self.assertEqual(self.run_one(row, 1000, 3, ctx=11)[1], [("prep", 11, 9), ("up", 5000)])
        self.assertEqual(self.run_one(row, 1000, 1)[1], [])

    def test_tag_one_adds_the_offset_and_clamps_the_second_word(self):
        outcome = self.run_one(v.row_value(1, 7, -9000, 5, 0), 1000, 1)[0]
        self.assertEqual(outcome, ("ok", 1, -4000, 0, 5000, -9000, 5000 // 7))
        outcome = self.run_one(v.row_value(1, 7, 9000, 5, 0), 1000, 1)[0]
        self.assertEqual(outcome, ("ok", 1, 14000, 14000, 5000, 9000, 5000 // 7))
        outcome = self.run_one(v.row_value(2, 7, 9000, 5, 0), 1000, 1)[0]
        self.assertEqual(outcome, ("ok", 0, 5000, 5000 // 7, 5000, 0, 5000 // 7))

    def test_offset_overflow_saturates_with_its_own_location(self):
        up = self.run_one(v.row_value(1, 1, v.INT_MAX, 2, 0), 3, 1)
        self.assertEqual(up[0][2], v.INT_MAX)
        self.assertEqual(up[1], [("overflow", v.LOC_CALLEE)])
        down = self.run_one(v.row_value(1, 1, v.INT_MIN, -2, 0), 3, 1)
        self.assertEqual(down[0][2], v.INT_MIN)
        self.assertEqual(down[0][3], 0)

    def test_refusals_and_extremes(self):
        row = v.row_value(0, 3, 0, v.INT_MIN, 0)
        self.assertEqual(self.run_one(row, 1, 1)[0][4], 1 << 63)
        self.assertEqual(self.run_one(row, 2, 1)[0], ("panic", "unwrap"))
        self.assertEqual(self.run_one(v.row_value(0, 3, 0, 1, 0), 1 << 63, 1)[0], ("panic", "unwrap"))
        self.assertEqual(self.run_one(v.row_value(0, 0, 0, 1, 0), 5, 1)[0], ("halt", "Halt"))

    def test_cap_byte_above_the_divisor_changes_nothing(self):
        for capb in (7, 8, 100, 255):
            self.assertEqual(self.run_one(v.row_value(0, 7, 0, 1, 0), 49, 4, capb=capb)[0][6], 7)

    def test_wrong_amount_readings_are_refused_by_the_grid(self):
        amount_flags = ("negative_allowed", "multiplier_wraps", "abs_not_taken", "mode0_quotient_one", "mode1_uses_cap", "mode4_ignores_cap",
                        "mode4_max_instead_of_min", "modes_2_3_swapped", "tag_nonzero_adds", "offset_wraps", "second_unclamped")
        refused = set()
        for case in v.grid_cases():
            got = v.run_case(self.harness, case)
            for flag in amount_flags:
                if flag not in refused and v.spec_case(case, frozenset((flag,))) != got:
                    refused.add(flag)
        self.assertEqual(refused, set(amount_flags))


class LoopOrderTests(unittest.TestCase):
    """Entry order, skipping and the two container shapes, one property per test, on the real bytes."""

    @classmethod
    def setUpClass(cls):
        cls.image = v.load_image()
        cls.harness = v.Harness(cls.image)

    def make(self, store, items, rows, **kw):
        extra = dict(cap=len(items) + 2, head=1) if store == "deque" else dict(height=0)
        return v.Case("hand", store, items, rows, **dict(extra, **kw))

    def both(self, items, rows, **kw):
        outcomes = []
        for store in ("deque", "btree"):
            case = self.make(store, items, rows, **kw)
            got = v.run_case(self.harness, case)
            self.assertEqual(got, v.spec_case(case))
            outcomes.append(got)
        self.assertEqual(outcomes[0], outcomes[1])
        return outcomes[0]

    def test_both_shapes_give_one_answer(self):
        items = [(k, v.row_value(0, 1 + k, k, 3 + k, k)) for k in range(6)]
        outcome, log = self.both(items, [10 * (k + 1) for k in range(6)], mode=1)
        self.assertEqual(outcome[0], "ok")
        self.assertEqual(log, [])

    def test_skip_rule_uses_only_the_low_flag_byte(self):
        items = [(0, v.row_value(0, 1, 0, 1, 0)), (1, v.row_value(1, 1, 7, 1, 0))]
        rows = [4, 5]
        plain = self.both(items, rows, flag=0)[0]
        self.assertEqual(plain[1:], (4, 4, 4, 0))
        self.assertEqual(self.both(items, rows, flag=0, junk=1)[0], plain)
        self.assertEqual(self.both(items, rows, flag=2)[0][1:], (16, 16, 9, 7))

    def test_key_reduction_is_modulo_ten_thousand(self):
        items = [(30000 + 1, v.row_value(0, 1, 0, 1, 0)), (10000 * 1844674407370955, v.row_value(0, 1, 0, 2, 0))]
        outcome = self.both(sorted(items), [6, 7])[0]
        self.assertEqual(outcome[1:], (19, 19, 19, 0))
        self.assertEqual(outcome[0], "ok")

    def test_bounds_panic_keeps_the_partial_sums(self):
        items = [(0, v.row_value(0, 1, 0, 1, 0)), (3, v.row_value(0, 1, 0, 1, 0))]
        outcome, log = self.both(items, [4, 5])
        self.assertEqual(outcome, ("panic", "bounds", 4, 4, 4, 0))

    def test_order_changes_saturation(self):
        up, down = v.row_value(0, 1, 0, 1, 0), v.row_value(0, 1, 0, -1, 0)
        rows = [1 << 62, 1 << 62, 1 << 62]
        start = v.INT_MAX - (1 << 62) + 1
        first = self.both([(0, up), (1, up), (2, down)], rows, start=start)
        second = self.both([(0, up), (1, down), (2, up)], rows, start=start)
        self.assertNotEqual(first[0][1], second[0][1])
        self.assertEqual([event for event in first[1]], [("overflow", v.LOC_SIGNED)] * len(first[1]))
        self.assertNotEqual(len(first[1]), len(second[1]))


if __name__ == "__main__":
    unittest.main()
