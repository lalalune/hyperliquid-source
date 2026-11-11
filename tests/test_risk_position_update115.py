import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import risk_position_update115 as tool  # noqa: E402

MAX = tool.INT_MAX
MIN = tool.INT_MIN


class PositionUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.named = tool.named_cases()
        cls.sample = cls.named + list(tool.vector_cases(300, seed=0x77))

    def run_case(self, case, variant=frozenset()):
        return self.harness.run(case), tool.spec_run(case, variant)

    def by_name(self, name):
        return next(case for case in self.named if case.name == name)

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = pathlib.Path(folder) / "node"
            fake.write_bytes(b"not the node")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(fake)

    def test_function_bounds_and_decode(self):
        start, end = self.image.exact_fde(tool.ENTRY)
        self.assertEqual((start, end), (0x448BC30, 0x448C925))
        rows = tool.decode_range(self.image, start, end)
        self.assertEqual(len(rows), 804)
        self.assertEqual(sum(row.size for row in rows), end - start)
        self.assertEqual(end - start, 3317)

    def test_bounds_refuse_other_addresses(self):
        for va in (tool.ENTRY + 1, tool.ENTRY - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_external_slots_are_relative_relocations(self):
        relative = self.image.relative()
        self.assertEqual(relative[tool.SLOT_REPORT], 0x4524E40)
        self.assertEqual(relative[tool.SLOT_PANIC], 0x1680C30)
        start, end = self.image.exact_fde(tool.ENTRY)
        sites = tool.site_rows(self.image, start, end)
        self.assertEqual([row[2] for row in sites], [22, 2])

    def test_location_records(self):
        rows = {int(row[0], 16): row for row in tool.location_rows(self.image)}
        self.assertEqual(rows[tool.LOC_A][3:], ("l1/src/qtys/mod.rs", 834, 1))
        self.assertEqual(rows[tool.LOC_S][3:], ("l1/src/qtys/mod.rs", 832, 1))
        self.assertEqual(rows[tool.LOC_NEG][3:], ("l1/src/qtys/mod.rs", 848, 1))
        self.assertEqual(rows[tool.LOC_QUOT][3:], ("l1/src/qtys/mod.rs", 847, 1))
        self.assertEqual(rows[tool.LOC_SIZE][3:], ("l1/src/qtys/impl_sz.rs", 39, 1))
        self.assertEqual(rows[tool.LOC_SUB][3:], ("l1/src/qtys/impl_ntl.rs", 70, 1))

    def test_location_use_names_every_call_site(self):
        start, end = self.image.exact_fde(tool.ENTRY)
        uses = tool.location_use_rows(tool.decode_range(self.image, start, end))
        self.assertEqual(len(uses), 24)
        self.assertEqual(sum(1 for use in uses if use[1] == "panic"), 2)
        self.assertNotIn("0x0", [use[2] for use in uses])
        self.assertEqual({int(use[2], 16) for use in uses}, {tool.LOC_A, tool.LOC_S, tool.LOC_SIZE, tool.LOC_SUB, tool.LOC_QUOT, tool.LOC_NEG})

    def test_named_and_sampled_cases_agree(self):
        for case in self.sample:
            got, want = self.run_case(case)
            self.assertEqual(got, want, case.name)

    def test_grid_slice_agrees(self):
        for index, case in enumerate(tool.grid_cases()):
            if index % 9 == 0:
                got, want = self.run_case(case)
                self.assertEqual(got, want, case.name)

    def test_zero_delta_copies_the_record(self):
        case = self.by_name("zero delta copies the record")
        kind, r9, record, events, detail = self.harness.run(case)
        self.assertEqual((kind, r9, events, detail), ("ok", 77, (), 0))
        self.assertEqual(record[2:4], (9, 5))
        self.assertEqual(record[6], 0x3333)

    def test_nonzero_delta_clears_the_clear_field(self):
        case = self.by_name("flat open long, cap above price")
        self.assertEqual(self.harness.run(case)[2][6], 0)

    def test_flat_open_numbers(self):
        above = self.harness.run(self.by_name("flat open long, cap above price"))
        self.assertEqual(above[:2], ("ok", 1000))
        self.assertEqual(above[2][2:4], (-5000, 100))
        below = self.harness.run(self.by_name("flat open long, cap below price"))
        self.assertEqual(below[:2], ("ok", 0))
        self.assertEqual(below[2][2:4], (-4000, 100))

    def test_short_open_takes_the_larger_of_price_and_cap(self):
        above = self.harness.run(self.by_name("flat open short, cap above price"))
        self.assertEqual(above[:2], ("ok", 0))
        self.assertEqual(above[2][2:4], (6000, -100))
        below = self.harness.run(self.by_name("flat open short, cap below price"))
        self.assertEqual(below[:2], ("ok", 1000))
        self.assertEqual(below[2][2:4], (5000, -100))

    def test_fee_divisor_floors_the_quotient(self):
        case = tool.mk("fee", delta=100, px=50, cap=50, divisor=3, base=0, floor=-10 ** 9)
        kind, r9, record, events, detail = self.harness.run(case)
        self.assertEqual((kind, r9, record[2], record[3]), ("ok", -1666, -3334, 100))
        ceiling = tool.spec_run(case, frozenset(("quotient-ceil",)))
        self.assertEqual((ceiling[1], ceiling[2][2]), (-1667, -3333))

    def test_zero_divisor_faults_only_on_the_open_arm(self):
        self.assertEqual(self.harness.run(self.by_name("flat open, zero divisor faults"))[0], "fault")
        self.assertEqual(self.harness.run(self.by_name("reduce long, proportional share"))[0], "ok")
        zero = tool.mk("zero divisor on a reduce", divisor=0, size=100, delta=-40, px=60, acc=5000)
        self.assertEqual(self.harness.run(zero)[0], "ok")

    def test_quotient_panic_carries_the_location(self):
        outcome = self.harness.run(self.by_name("flat open, quotient 2^63 panics"))
        self.assertEqual(outcome[0], "panic")
        self.assertEqual(outcome[4], tool.panic_args(tool.LOC_QUOT))
        self.assertEqual(outcome[4][1:], (0x2B, 0x7D3212, 0x648C598))

    def test_error_leaves_the_result_block_untouched(self):
        outcome = self.harness.run(self.by_name("flat open, negative price"))
        self.assertEqual(outcome[:2], ("err", None))
        block = self.harness.machine.memory.bytes_at(tool.OUT, 0x48)
        self.assertEqual(block[:4], b"\x02\0\0\0")
        self.assertEqual(block[4:], b"\xa5" * 0x44)

    def test_mode_other_than_one_is_a_plain_fill(self):
        for mode in (0, 2, 7, 0xFFFFFFFF):
            case = tool.mk("plain", mode=mode, size=10, delta=5, px=7, base=100, acc=55)
            kind, r9, record, events, detail = self.harness.run(case)
            self.assertEqual((kind, r9, record[2], record[3]), ("ok", 100 - 35, 55, 15))

    def test_mode_one_is_not_the_plain_fill(self):
        case = tool.mk("not plain", mode=1, size=10, delta=5, px=7, base=100, acc=55, cap=7)
        self.assertEqual(self.harness.run(case)[1], 100)

    def test_overflow_reports_and_saturates(self):
        case = self.by_name("add past the top")
        kind, r9, record, events, detail = self.harness.run(case)
        self.assertIn(tool.LOC_SIZE, events)
        self.assertLessEqual(record[3], MAX)
        self.assertEqual(record[3], MAX)
        down = self.harness.run(self.by_name("add past the bottom"))
        self.assertEqual(down[2][3], MIN)

    def test_share_is_truncated_not_rounded(self):
        case = tool.mk("share", size=3, delta=-1, px=1, acc=10, cap=10 ** 9)
        self.assertEqual(self.harness.run(case)[2][2], 7)
        negative = tool.mk("share negative", size=3, delta=-1, px=100, acc=-10, cap=10 ** 9)
        self.assertEqual(self.harness.run(negative)[2][2], -7)
        half = tool.mk("share half", size=4, delta=-3, px=1, acc=7, cap=10 ** 9)
        self.assertEqual(self.harness.run(half)[2][2], 2)

    def test_float_conversion_edges(self):
        self.assertEqual(tool.f64_to_i64(float("nan")), 0)
        self.assertEqual(tool.f64_to_i64(2.0 ** 63), MAX)
        self.assertEqual(tool.f64_to_i64(-2.0 ** 63), MIN)
        self.assertEqual(tool.f64_to_i64(1.9), 1)
        self.assertEqual(tool.f64_to_i64(-1.9), -1)
        self.assertEqual(tool.f64_to_i64(2.0 ** 63 - 1024), MAX - 1023)

    def test_saturation_helpers(self):
        self.assertEqual(tool.sat(MAX + 1), MAX)
        self.assertEqual(tool.sat(MIN - 1), MIN)
        self.assertEqual(tool.sat(5), 5)
        self.assertEqual(tool.to_i64(1 << 63), MIN)
        self.assertEqual(tool.to_i64((1 << 64) - 1), -1)
        self.assertEqual([tool.sign(x) for x in (-5, 0, 5)], [-1, 0, 1])

    def test_stream_is_fixed(self):
        stream = tool.Stream(1)
        first = [stream.bits() for _ in range(3)]
        again = tool.Stream(1)
        self.assertEqual(first, [again.bits() for _ in range(3)])
        self.assertEqual(hashlib.sha256(repr(first).encode()).hexdigest()[:8], hashlib.sha256(repr(first).encode()).hexdigest()[:8])
        count = sum(1 for _ in tool.vector_cases(50))
        self.assertEqual(count, 50)

    def test_every_variant_is_caught(self):
        for name in tool.VARIANTS:
            failure = tool.first_failure(self.harness, self.sample, frozenset((name,)))
            self.assertIsNotNone(failure, name)

    def test_unknown_variant_changes_nothing(self):
        self.assertIsNone(tool.first_failure(self.harness, self.sample, frozenset(("nothing",))))

    def test_edited_conditions_are_caught(self):
        start, end = self.image.exact_fde(tool.ENTRY)
        rows = tool.decode_range(self.image, start, end)
        probe = tool.Harness(self.image)
        tool.run_stream(probe, self.sample)
        seen = set(probe.machine.seen)
        order = self.sample
        edits = tool.edits_for(self.image, rows, seen)
        self.assertGreater(len(edits), 60)
        caught = 0
        for va, kind, patch in edits[:40]:
            harness = tool.Harness(self.image, patch)
            harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
            if tool.first_failure(harness, order) is not None:
                caught += 1
        self.assertGreater(caught, 28)

    def test_edit_of_the_entry_check_is_caught(self):
        patch = {0x448BC41: self.image.blob[self.image.offset(0x448BC41)] ^ 1}
        harness = tool.Harness(self.image, patch)
        self.assertIsNotNone(tool.first_failure(harness, self.sample))

    def test_unedited_bytes_pass_under_the_mutant_limit(self):
        harness = tool.Harness(self.image)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        self.assertIsNone(tool.first_failure(harness, self.sample))

    def test_a_wrong_rule_list_disagrees_with_the_bytes(self):
        case = self.by_name("flip long to short")
        got, want = self.run_case(case, frozenset(("flip-no-reopen",)))
        self.assertNotEqual(got, want)

    def test_structural_controls_all_detected(self):
        rows = tool.structural_controls(self.image, self.named)
        self.assertEqual(len(rows), 10)
        self.assertEqual({row[1] for row in rows}, {"detected"})

    def test_analysis_summary_and_determinism(self):
        first = tool.render(tool.analyse(self.image, vectors=400, mutate=False))
        second = tool.render(tool.analyse(self.image, vectors=400, mutate=False))
        self.assertEqual(first, second)
        measure = json.loads(first["measure.json"])
        self.assertEqual(set(measure), {"cases", "negative_controls", "negative_detected", "equivalent"})
        self.assertEqual(measure["cases"], len(self.named) + 1080 + 400)
        evidence = json.loads(first["evidence.json"])
        self.assertEqual(evidence["sha256"], tool.SHA256)
        self.assertGreaterEqual(evidence["unreached_rows"], 112)
        self.assertEqual(evidence["instructions"], 804)

    def test_unreachable_groups_cover_every_unreached_row(self):
        result = tool.analyse(self.image, vectors=400, mutate=False)
        rows = tool.unreachable_rows(result["unreached"])
        self.assertEqual(sum(row[1] for row in rows), len(result["unreached"]))
        with self.assertRaises(tool.EvidenceError):
            tool.unreachable_rows(result["unreached"] + [0x448BC30])
        with self.assertRaises(tool.EvidenceError):
            tool.unreachable_rows([va for va in result["unreached"] if va < 0x448C42D])

    def test_committed_evidence_matches_a_fresh_render(self):
        work = ROOT / "research" / "work-items" / "RE-007-position-update-115"
        if not (work / "measure.json").exists():
            self.fail("evidence folder is missing")
        measure = json.loads((work / "measure.json").read_text())
        self.assertEqual(measure["negative_controls"], measure["negative_detected"] + measure["equivalent"])
        self.assertGreaterEqual(measure["cases"], 10000)


# (case name, kind, returned balance, reported locations in order: A accumulator add, S size add, Z delta add, N subtract), read from the bytes
NAMED_OUTCOMES = (
    ('zero delta copies the record', 'ok', 77, ''),
    ('zero delta keeps even a bad price', 'ok', -3, ''),
    ('flat open long, cap above price', 'ok', 1000, ''),
    ('flat open long, cap below price', 'ok', 0, ''),
    ('flat open short, cap above price', 'ok', 0, ''),
    ('flat open short, cap below price', 'ok', 1000, ''),
    ('flat open, divisor 1', 'ok', 0, ''),
    ('flat open, divisor 0xffffffff', 'ok', 0, ''),
    ('flat open, worth past 32 bits', 'ok', 0, ''),
    ('flat open, zero divisor faults', 'fault', None, ''),
    ('flat open, zero worth with zero divisor still faults', 'fault', None, ''),
    ('flat open, quotient 2^63 panics', 'panic', None, ''),
    ('flat open, worth 2^63 - 2 under divisor 1', 'err', None, ''),
    ('flat open, cap with the top bit is refused', 'ok', 0, ''),
    ('flat open short, cap with the top bit is the maximum', 'err', None, ''),
    ('flat open, negative price', 'err', None, ''),
    ('flat open, price times delta overflows', 'err', None, ''),
    ('flat open, delta at the minimum', 'ok', 0, 'N'),
    ('flat open, balance saturates down', 'ok', 0, 'NN'),
    ('flat open, accumulator saturates up', 'ok', 0, 'A'),
    ('flat open, floor above balance', 'ok', 1000000, ''),
    ('flat open, floor equal balance', 'ok', 0, ''),
    ('add to long', 'ok', 500, ''),
    ('add to short', 'ok', 500, ''),
    ('add past the top', 'ok', 0, 'ZS'),
    ('add past the bottom', 'ok', 0, 'ZS'),
    ('reduce long, proportional share', 'ok', 4500, ''),
    ('reduce short, proportional share', 'ok', 100, ''),
    ('reduce long, negative accumulator', 'ok', 500, ''),
    ('reduce long, value below zero', 'ok', 100, ''),
    ('close long exactly', 'ok', 11100, ''),
    ('close short exactly', 'ok', -10900, ''),
    ('close exactly, floor above', 'ok', 11100, ''),
    ('flip long to short', 'ok', 10600, ''),
    ('flip short to long', 'ok', 0, ''),
    ('flip with value below zero', 'ok', 0, ''),
    ('flip short with value below zero', 'ok', 0, ''),
    ('price times size overflows, long', 'ok', 10, ''),
    ('price times size overflows, short', 'ok', 0, ''),
    ('price times size plus accumulator overflows', 'ok', 12582912, 'N'),
    ('share of a huge accumulator', 'ok', 3074457345618258434, 'N'),
    ('share of a huge negative accumulator', 'ok', 0, ''),
    ('share is exactly the accumulator', 'ok', 12368, ''),
    ('share minus value overflows', 'ok', 7686143364045646589, ''),
    ('base plus share overflows', 'ok', 9223372036854775807, 'NAN'),
    ('size sum overflows in mode 1', 'err', None, 'Z'),
    ('size sum overflows downward in mode 1', 'err', None, 'Z'),
    ('fold of the accumulator overflows', 'ok', 9223372036854775807, 'A'),
    ('fold of the accumulator overflows downward', 'ok', -9223372036854775808, 'N'),
    ('base plus share saturates, zero value', 'ok', 9223372036854775807, 'A'),
    ('flip, base plus accumulator saturates down', 'ok', -9223372036854775808, 'A'),
    ('flip short, base plus accumulator saturates down', 'ok', -9223372036854775806, 'AN'),
    ('mark cleared when the sign flips', 'ok', 0, ''),
    ('mark kept when the sign holds', 'ok', 10, ''),
    ('mode 0 buys', 'ok', 65, ''),
    ('mode 2 sells', 'ok', 135, ''),
    ('mode 0xffffffff', 'ok', 65, ''),
    ('mode 0 size overflows', 'ok', -35, 'ZS'),
    ('mode 0 size underflows', 'ok', 35, 'ZS'),
    ('mode 0 negative price', 'err', None, ''),
    ('mode 0 price times delta overflows', 'err', None, 'ZS'),
    ('mode 0 balance saturates', 'ok', 9223372036854775807, 'N'),
    ('mode 0 balance saturates below', 'ok', -9223372036854775808, 'N'),
    ('mode 0 sign flip clears the mark', 'ok', 8, ''),
)


class NamedOutcomeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.named = {case.name: case for case in tool.named_cases()}
        cls.letters = {tool.LOC_A: "A", tool.LOC_S: "S", tool.LOC_SIZE: "Z", tool.LOC_SUB: "N"}

    def test_every_named_case_is_pinned(self):
        self.assertEqual(len(NAMED_OUTCOMES), len(self.named))
        self.assertEqual({row[0] for row in NAMED_OUTCOMES}, set(self.named))

    def test_named_outcomes(self):
        for name, kind, balance, letters in NAMED_OUTCOMES:
            outcome = self.harness.run(self.named[name])
            self.assertEqual(outcome[0], kind, name)
            self.assertEqual(outcome[1], balance, name)
            self.assertEqual("".join(self.letters[event] for event in outcome[3]), letters, name)

    def test_named_outcomes_by_rules(self):
        for name, kind, balance, letters in NAMED_OUTCOMES:
            outcome = tool.spec_run(self.named[name])
            self.assertEqual((outcome[0], outcome[1]), (kind, balance), name)
            self.assertEqual("".join(self.letters[event] for event in outcome[3]), letters, name)

    def test_variants_change_a_pinned_outcome(self):
        changed = 0
        for name in tool.VARIANTS:
            for row in NAMED_OUTCOMES:
                outcome = tool.spec_run(self.named[row[0]], frozenset((name,)))
                if (outcome[0], outcome[1]) != (row[1], row[2]) or "".join(self.letters[e] for e in outcome[3]) != row[3]:
                    changed += 1
                    break
        self.assertGreaterEqual(changed, 14)

    def test_every_report_location_appears_in_the_pinned_table(self):
        seen = set("".join(row[3] for row in NAMED_OUTCOMES))
        self.assertEqual(seen, {"A", "S", "Z", "N"})

    def test_kinds_in_the_table(self):
        kinds = {row[1] for row in NAMED_OUTCOMES}
        self.assertEqual(kinds, {"ok", "err", "fault", "panic"})


class ArmTest(unittest.TestCase):
    """Hand-worked numbers for each arm, checked against both the bytes and the rule list."""

    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def both(self, case):
        got = self.harness.run(case)
        self.assertEqual(got, tool.spec_run(case), case.name)
        return got

    def test_exact_close_with_positive_accumulator(self):
        # share = 5000 (ratio 1), balance = 100 + 5000 - (60 * -100) = 11100, then the zero accumulator is folded
        kind, r9, record, events, detail = self.both(tool.mk("close", size=100, delta=-100, px=60, acc=5000, base=100))
        self.assertEqual((kind, r9, record[2], record[3], events), ("ok", 11100, 0, 0, ()))

    def test_partial_reduce_by_value_keeps_the_balance(self):
        # acc + px*size = -4900 < 0: the value arm; acc = -5000 - (1 * -40) = -4960; the balance is not touched
        kind, r9, record, events, detail = self.both(tool.mk("reduce", size=100, delta=-40, px=1, acc=-5000, base=100))
        self.assertEqual((kind, r9, record[2], record[3]), ("ok", 100, -4960, 60))

    def test_partial_reduce_by_share(self):
        # ratio 40/100, share = trunc(5000 * 0.4) = 2000; balance = 100 + 2000 - (60 * -40) = 4500
        kind, r9, record, events, detail = self.both(tool.mk("share", size=100, delta=-40, px=60, acc=5000, base=100))
        self.assertEqual((kind, r9, record[2], record[3]), ("ok", 4500, 3000, 60))

    def test_flip_by_value_pays_out_the_accumulator_then_opens(self):
        kind, r9, record, events, detail = self.both(tool.mk("flip", size=100, delta=-150, px=1, acc=-5000, base=100, divisor=10000, cap=1))
        self.assertEqual((kind, record[3]), ("ok", -50))
        # first leg: acc = -5000 + 100 = -4900 goes into the balance (100 - 4900 = -4800); second leg opens -50 at price 1
        # the second leg adds worth 50 to the zeroed accumulator; the floor 0 then takes 4800 off it: 50 - 4800
        self.assertEqual((r9, record[2]), (0, -4750))

    def test_add_in_the_same_direction_only_opens(self):
        kind, r9, record, events, detail = self.both(tool.mk("add", size=50, delta=25, px=40, cap=40, base=500, acc=1000, divisor=10 ** 9))
        self.assertEqual((kind, record[3]), ("ok", 75))
        # worth = 40 * 25 = 1000, fee 0: balance 500 - 1000 + 1000 = 500, acc 1000 - 1000 = 0
        self.assertEqual((r9, record[2]), (500, 0))

    def test_floor_lifts_the_result_and_charges_the_accumulator(self):
        kind, r9, record, events, detail = self.both(tool.mk("floor", size=0, delta=10, px=10, cap=10, base=5, floor=1000, acc=0, divisor=10 ** 9))
        # balance 5 stays 5 (open at the price), the floor 1000 is returned and acc = -100 (worth) - (1000 - 5)
        self.assertEqual((kind, r9, record[2]), ("ok", 1000, -100 - 995))

    def test_error_tag_keeps_earlier_record_writes(self):
        case = tool.mk("late error", size=0, delta=5, px=-3, cap=10, acc=7, divisor=10)
        kind, r9, record, events, detail = self.both(case)
        self.assertEqual(kind, "err")
        self.assertEqual(record[6], 0)
        self.assertEqual(record[2], 12)  # the fee 5 was added to the accumulator before the price check failed

    def test_plain_fill_error_order(self):
        case = tool.mk("plain late", mode=0, size=1, delta=3, px=-1, mark=9)
        kind, r9, record, events, detail = self.both(case)
        self.assertEqual((kind, record[3], record[5]), ("err", 4, 9))

    def test_untouched_words_survive_every_arm(self):
        for case in (tool.mk("a", size=5, delta=3, px=2), tool.mk("b", size=5, delta=-9, px=2), tool.mk("c", mode=0, size=5, delta=-9, px=2), tool.mk("d", delta=4)):
            record = self.both(case)[2]
            self.assertEqual((record[4], record[7], record[8]), (0x1111, 0x4444, 0x5555), case.name)

    def test_digest_is_stable_and_distinguishes_outcomes(self):
        a = tool.digest_of(self.harness.run(tool.mk("a", delta=4, px=2, cap=2)))
        b = tool.digest_of(self.harness.run(tool.mk("b", delta=5, px=2, cap=2)))
        self.assertEqual(a, tool.digest_of(self.harness.run(tool.mk("a2", delta=4, px=2, cap=2))))
        self.assertNotEqual(a[2], b[2])


if __name__ == "__main__":
    unittest.main()
