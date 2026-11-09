import collections
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vault_withdraw_gate_115 as T  # noqa: E402


class Shared:
    image = None
    constants = None
    harness = None
    named = None

    @classmethod
    def setup(cls):
        if cls.image is None:
            cls.image = T.load_image()
            cls.constants = T.constant_values(cls.image)
            cls.harness = T.Harness(cls.image)
            cls.named = {case.name: case for case in T.named_cases()}
        return cls


def outcome(name):
    shared = Shared.setup()
    got, log = T.run_case(shared.harness, shared.named[name])
    return got, log


class ImageTests(unittest.TestCase):
    def test_binary_identity_and_bounds(self):
        shared = Shared.setup()
        self.assertEqual(shared.image.exact_fde(T.GATE), (0x44AB4A0, 0x44ABFAF))
        self.assertEqual(shared.image.exact_fde(T.DEQ)[0], 0x45578E0)
        with self.assertRaises(T.EvidenceError):
            T.load_image(T.BINARY, "0" * 64)
        with self.assertRaises(T.EvidenceError):
            shared.image.exact_fde(T.GATE + 4)
        with self.assertRaises(T.EvidenceError):
            shared.image.offset(shared.image.named[".bss"]["address"] + 8)

    def test_gate_decodes_to_the_end_of_its_frame(self):
        shared = Shared.setup()
        rows = T.decode_range(shared.image, *shared.image.exact_fde(T.GATE))
        self.assertEqual(rows[0].va, T.GATE)
        self.assertEqual(rows[-1].next, 0x44ABFAF)
        with self.assertRaises(T.EvidenceError):
            T.decode_range(shared.image, T.GATE, 0x44ABFAE)

    def test_constants_come_from_the_bytes(self):
        k = Shared.setup().constants
        self.assertEqual(k["usd_scale"], 1000000.0)
        self.assertEqual(k["minimum_ratio"], 1e-8)
        self.assertEqual(k["minimum_base_value"], 1e-15)
        self.assertEqual(k["self_slack_factor"], 0.05)
        self.assertEqual(k["kind_floor"], 0.2)
        self.assertEqual((k["latest_date"], k["latest_seconds"], k["latest_fraction"]), (2147473118, 86399, 999999999))


class HandDerivedOutcomes(unittest.TestCase):
    """Each expectation below is worked out by hand from the listing, not taken from the rule list."""

    def test_plain_success_for_a_tag_one_vault(self):
        # fee base 1e9, available 2e8: ratio 0.2, taken 2e8, kind 0 (no locked amount hook for tag 1)
        got, log = outcome("good")
        self.assertEqual(got, ("ok", 0, T.bits64(2e8), 200000000, T.bits64(0.2)))
        self.assertEqual([entry[0] for entry in log], ["fee", "available"])

    def test_error_tags(self):
        self.assertEqual(outcome("base-zero")[0], ("err", 0xA))
        self.assertEqual(outcome("base-negative")[0], ("err", 0xA))
        self.assertEqual(outcome("absent-key")[0], ("err", 0xB))
        self.assertEqual(outcome("empty-map")[0], ("err", 0xB))
        self.assertEqual(outcome("tree-null-root")[0], ("err", 0xB))
        self.assertEqual(outcome("date-tag0-fail")[0], ("err", 0xC))
        self.assertEqual(outcome("mode1-over-available")[0], ("err", 0xD))
        self.assertEqual(outcome("ratio-above-fraction")[0], ("err", 0xE))
        self.assertEqual(outcome("ratio-below-floor")[0], ("err", 0xE))
        self.assertEqual(outcome("self-key-slack")[0], ("err", 0xF))
        self.assertEqual(outcome("self-key-small")[0], ("err", 0x10))
        self.assertEqual(outcome("excess-small")[0], ("err", 0x2A))
        self.assertEqual(outcome("remaining-too-small")[0], ("err", 0x11F))

    def test_unlock_date_boundary(self):
        # stored 730000 day, 100 s; lock 3600 s: unlocked from second 3700 of the same day (equal passes)
        self.assertEqual(outcome("date-tag0-equal")[0][0], "ok")
        self.assertEqual(outcome("date-tag0-equal-minus-one")[0], ("err", 0xC))
        got, log = outcome("date-tag0-equal")
        self.assertEqual(log[1:4], [("duration", T.bits64(3600.0)), ("time-add", 100, 5, 3600, 0), ("date-add", 730000, 0)])

    def test_day_carry_goes_through_the_date_hook(self):
        got, log = outcome("date-day-carry")
        self.assertEqual(got, ("err", 0xC))
        # 100 s + 90000 s carries one whole day: the date hook is asked for the day count 1
        self.assertIn(("time-add", 100, 5, 90000, 0), log)
        self.assertIn(("date-add", 730000, 1), log)

    def test_duration_hook_panics(self):
        for name in ("duration-negative", "duration-nan", "duration-huge"):
            self.assertEqual(outcome(name)[0], ("panic", "duration"), name)
        # a duration above i64::MAX nanoseconds is saturated, so the request date is long before it unlocks
        self.assertEqual(outcome("duration-saturating")[0], ("err", 0xC))

    def test_kind_and_locked_amount(self):
        self.assertEqual(outcome("tag0-under-locked")[0][1], 0)
        self.assertIsNone(outcome("tag0-under-locked")[0][2])      # the result is read after a call that clobbers the register
        self.assertEqual(outcome("tag0-kind-flag")[0][:3], ("ok", 1, T.bits64(0.2)))
        self.assertEqual(outcome("tag0-over-locked")[0][:3], ("ok", 1, T.bits64(0.2)))
        # a small ratio is shown as the floor 0.2 when the taken amount is above the locked amount
        got = outcome("tag0-over-locked-small-ratio")[0]
        self.assertEqual((got[0], got[1], got[2], got[3]), ("ok", 1, T.bits64(0.2), 1000000))

    def test_address_set_walk(self):
        got, log = outcome("set-12")
        self.assertEqual(got[0], "ok")
        self.assertEqual(sum(1 for entry in log if entry[0] == "fee"), 13)     # the leader and twelve set members
        fees = [entry[1] for entry in log if entry[0] == "fee"]
        self.assertEqual(fees[1:], sorted(fees[1:]))                           # in-order walk of the B-tree
        self.assertEqual(outcome("set-len-too-big")[0], ("panic", "set-exhausted"))
        self.assertEqual(sum(1 for e in outcome("set-short-len")[1] if e[0] == "fee"), 3)
        self.assertEqual(sum(1 for e in outcome("set-len-zero")[1] if e[0] == "fee"), 1)
        self.assertEqual(sum(1 for e in outcome("set-null-root")[1] if e[0] == "fee"), 1)

    def test_deep_set_reaches_unrolled_descent(self):
        for name, count in (("set-deep-8", 511), ("set-deep-9", 1023)):
            got, log = outcome(name)
            self.assertEqual(got[0], "ok")
            self.assertEqual(sum(1 for entry in log if entry[0] == "fee"), count + 1)

    def test_set_fee_sum_saturates_and_logs(self):
        got, log = outcome("set-overflow-down")
        self.assertEqual(got, ("err", 0xA))
        self.assertIn(("overflow", 0), log)
        got, log = outcome("set-overflow-up")
        self.assertEqual(got[0], "err")
        self.assertIn(("overflow", 0), log)
        # i64::MAX - 3 + 10 saturates, then -MAX brings it back to 0 which is not a positive base
        self.assertEqual(outcome("set-recovers")[0], ("err", 0xA))

    def test_key_compares_all_twenty_bytes(self):
        for name in ("key-prefix-collision", "key-prefix-collision-tree"):
            self.assertEqual(outcome(name)[0][0], "ok", name)

    def test_float_edge_of_the_self_key_bound(self):
        # 0.3 - 0.2 is 0.09999999999999998 in binary64, so the bound of 1e8 is missed by one unit
        self.assertEqual(outcome("self-key-bound-edge")[0], ("err", 0x10))


class ModelTests(unittest.TestCase):
    def test_duration_contract(self):
        self.assertEqual(T.model_duration(T.bits64(3600.25)), (3600, 250000000))
        self.assertEqual(T.model_duration(T.bits64(0.0)), (0, 0))
        for bad in (-0.5, math.nan, math.inf, 2.0 ** 64):
            with self.assertRaises(T.Panicked):
                T.model_duration(T.bits64(bad))

    def test_time_and_date_contracts(self):
        self.assertEqual(T.model_time_add(86399, 999999999, 0, 1), (0, 0, 86400))
        self.assertEqual(T.model_time_add(10, 20, 5, 30), (15, 50, 0))
        self.assertEqual(T.model_date_add(5, 0xFFFFFFFF), 4)
        self.assertEqual(T.model_date_add(5, 0xFFFFFFF0), 0)
        self.assertEqual(T.model_date_add(0x7FFFFFFF, 1), 0)

    def test_saturating_truncation(self):
        k = Shared.setup().constants
        self.assertEqual(T.sat_trunc(math.nan, k, True), 0)
        self.assertEqual(T.sat_trunc(-5.5, k, True), 0)
        self.assertEqual(T.sat_trunc(-5.5, k, False), -5)
        self.assertEqual(T.sat_trunc(1e30, k, False), T.I64_MAX)
        self.assertEqual(T.sat_trunc(-1e30, k, False), T.I64_MIN)
        self.assertEqual(T.sat_trunc(math.inf, k, False), 0)
        self.assertEqual(T.sat_trunc(12345.9, k, True), 12345)

    def test_tree_builder_keeps_order_and_height(self):
        for count in (1, 5, 11, 12, 23, 140, 511):
            keys = [struct.pack(">I", index) + bytes(16) for index in range(count)]
            for height in T.feasible_heights(count):
                shape = T.split_tree(keys, height, T.lcg(9 + count))
                self.assertEqual(T.tree_inorder(shape), keys)

                def depth(node):
                    return 0 if node[1] is None else 1 + {depth(child) for child in node[1]}.pop()
                self.assertEqual(depth(shape), height)
        self.assertEqual(T.feasible_heights(11), [0, 1, 2])
        self.assertEqual(T.feasible_heights(12)[0], 1)


class RuleListAgreement(unittest.TestCase):
    def test_named_and_random_cases_agree_with_the_bytes(self):
        shared = Shared.setup()
        mismatches, kinds = [], collections.Counter()
        for index, case in enumerate(T.draw_stream(1200)):
            got, log = T.run_case(shared.harness, case)
            expected = T.spec_gate(case, shared.constants)
            kinds[expected[0][0]] += 1
            if (got, log) != expected:
                mismatches.append((index, case.name, got, expected[0]))
        self.assertEqual(mismatches, [])
        self.assertGreater(kinds["ok"], 100)
        self.assertGreater(kinds["err"], 400)
        self.assertGreater(kinds["panic"], 10)

    def test_every_named_deviation_is_refused(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(2500))
        _, caught, _ = T.check_stream(shared.harness, cases, shared.constants, T.VARIANTS)
        missing = [name for name, (count, _) in caught.items() if count == 0]
        self.assertEqual(missing, [])
        self.assertGreaterEqual(len(caught), 30)

    def test_error_record_only_writes_its_tag(self):
        shared = Shared.setup()
        got, _ = T.run_case(shared.harness, shared.named["absent-key"])
        self.assertEqual(got, ("err", 0xB))
        raw = shared.harness.machine.memory.bytes_at(T.OUT, 0x40)
        self.assertEqual(raw[2:], bytes(0x3E * [0xEE]))


class ByteLevelControls(unittest.TestCase):
    def test_edited_conditions_are_noticed(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(500))
        reached = collections.Counter()
        T.check_stream(shared.harness, cases[:300], shared.constants, hits=reached)
        mutants = T.mutants_of(shared.image, reached)
        self.assertGreater(len(mutants), 150)
        picked = mutants[::6]
        rows = T.run_mutants(shared.image, picked, cases, shared.constants)
        survivors = [row for row in rows if not row[5]]
        self.assertEqual(survivors, [])

    def test_structural_controls_all_detected(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(700))
        rows = T.structural_controls(shared.image, shared.harness, shared.constants, cases)
        self.assertGreaterEqual(len(rows), 17)
        self.assertEqual([name for name, detected, _ in rows if not detected], [])

    def test_wrong_digest_and_missing_stub_are_refused(self):
        shared = Shared.setup()
        stripped = T.Harness(shared.image)
        del stripped.machine.calls[T.FEE]
        with self.assertRaises(T.Halt):
            stripped.run(shared.named["good"])
        trapped = T.Harness(shared.image, {T.GATE: 0xCC})
        with self.assertRaises(T.Halt):
            trapped.run(shared.named["good"])


class ToolOutput(unittest.TestCase):
    def test_small_run_is_deterministic_and_complete(self):
        first = T.render(T.analyse(150, mutate=False))
        second = T.render(T.analyse(150, mutate=False))
        self.assertEqual(first, second)
        self.assertEqual(first["evidence.json"].count("mismatches"), 1)
        for name in ("constants.tsv", "state-fields.tsv", "call-sites.tsv", "function-rows.tsv", "outcomes.tsv", "variants.tsv",
                     "structural-controls.tsv", "measure.json", "unreached.tsv", "stub-calls.tsv"):
            self.assertIn(name, first)
        self.assertIn('"mismatches": 0', first["measure.json"])

    def test_no_path_text_in_the_output(self):
        files = T.render(T.analyse(60, mutate=False))
        for text in files.values():
            for marker in tuple("/" + word + "/" for word in ("home", "mnt", "srv", "tmp", "root", "opt", "var", "etc")):
                self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()
