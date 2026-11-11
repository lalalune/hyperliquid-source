import json
import math
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import order_price_shape_115 as T  # noqa: E402


class Shared(unittest.TestCase):
    image = None
    cases = None

    def setUp(self):
        if Shared.image is None:
            Shared.image = T.load_image()
            Shared.cases = list(T.named_cases())

    def run_case(self, case, copy=0):
        harness = T.Harness(self.image, T.COPIES[copy])
        got, log = harness.run(case)
        want, want_log = T.expected(case)
        self.assertTrue(T.agree(case, got, log, want, want_log), (got, want))
        return got


class ArithmeticTests(unittest.TestCase):
    def test_round_half_away(self):
        self.assertEqual(T.round_away(0.5), 1.0)
        self.assertEqual(T.round_away(-0.5), -1.0)
        self.assertEqual(T.round_away(2.4999999999999996), 2.0)
        self.assertTrue(math.isnan(T.round_away(math.nan)))

    def test_saturate(self):
        self.assertEqual(T.saturate(0.0), 1)
        self.assertEqual(T.saturate(-5.0), 1)
        self.assertEqual(T.saturate(math.inf), 1)
        self.assertEqual(T.saturate(math.nan), 1)
        self.assertEqual(T.saturate(2.0 ** 64), T.M64)
        self.assertEqual(T.saturate(2.0 ** 63), 1 << 63)
        self.assertEqual(T.saturate(1.5), 2)

    def test_case_rejects_unknown_field(self):
        with self.assertRaises(T.EvidenceError):
            T.Case(bogus=1)


class SpecTests(unittest.TestCase):
    def test_blocked(self):
        out, rax, log = T.spec(T.Case(blocked=1))
        self.assertEqual(out[0x10:0x12], (0x19C).to_bytes(2, "little"))
        self.assertEqual(len(log), 1)

    def test_market_panic(self):
        with self.assertRaises(T.Panic) as caught:
            T.spec(T.Case(asset=30000))
        self.assertEqual(caught.exception.label, "market")

    def test_step_to_zero_is_error(self):
        out, _, _ = T.spec(T.Case(flag_a=1, side=1, delta=700, optref=0))
        self.assertEqual(out[0x10:0x12], (0xDE).to_bytes(2, "little"))

    def test_minimum_value_payload(self):
        out, _, _ = T.spec(T.Case(size=1, rows=(5, 6, 7, 8)))
        self.assertEqual(out[0x10:0x12], (0xC8).to_bytes(2, "little"))
        self.assertEqual(out[0x20:0x28], (0x4024000000000000).to_bytes(8, "little"))

    def test_accept_record(self):
        out, _, _ = T.spec(T.Case(gate=1))
        self.assertEqual(out[0:8], bytes(8))
        self.assertEqual(int.from_bytes(out[0x60:0x68], "little"), 1 << 63)

    def test_system_user_skips_value_floor(self):
        low = T.Case(size=1, rows=(5, 6, 7, 8), user=T.SYSTEM_USERS[1])
        self.assertEqual(T.spec(low)[0][0:8], bytes(8))


class RealByteTests(Shared):
    def test_named_cases_match_on_every_copy(self):
        for copy in range(3):
            harness = T.Harness(self.image, T.COPIES[copy])
            for group, case in self.cases:
                reason = T.check(harness, case)
                self.assertIsNone(reason, (copy, case.label, reason))

    def test_copies_have_equal_length_and_few_differences(self):
        rows = T.copy_rows(self.image)
        self.assertEqual(rows[0][5], 10)
        self.assertTrue(rows[0][4])

    def test_outcome_words(self):
        seen = set()
        harness = T.Harness(self.image, T.COPIES[0])
        for group, case in self.cases:
            got, _ = harness.run(case)
            seen.add(T.outcome(case, got))
        for word in ("accepted", "status 0x19c", "status 0xde", "status 0x6d", "status 0x6c", "status 0xc8", "panic market"):
            self.assertIn(word, seen)

    def test_group_sizes(self):
        counts = {}
        for group, _ in T.all_cases():
            counts[group] = counts.get(group, 0) + 1
        self.assertGreater(sum(counts.values()), 6000)
        for group in ("step", "fraction", "tick", "value", "gate", "time", "band", "zero size", "top", "equal band", "cap edge", "random"):
            self.assertGreater(counts[group], 10, group)


class NegativeTests(Shared):
    def test_mutated_condition_is_caught(self):
        harness = T.Harness(self.image, T.COPIES[0], {0x5A2160B: 0x85 ^ 1})
        found = [T.check(harness, c) for _, c in self.cases]
        self.assertTrue(any(found))

    def test_wrong_rules_are_caught_by_named_cases(self):
        harness = T.Harness(self.image, T.COPIES[0])
        results = [harness.run(c) for _, c in self.cases]
        caught = 0
        for flaw in ("cond_strict", "ignore_optref", "stop_zero", "factor_swap", "fraction_sign", "cap_scale", "no_system", "add_wrap"):
            for (_, c), (got, log) in zip(self.cases, results):
                try:
                    out, rax, wlog = T.spec(c, flaw)
                    want = (rax, bytes(out))
                except T.Panic as error:
                    want, wlog = ("panic", error.label), None
                if not T.agree(c, got, log, want, wlog):
                    caught += 1
                    break
        self.assertGreaterEqual(caught, 6)

    def test_corrupted_constant_is_caught(self):
        harness = T.Harness(self.image, T.COPIES[0])
        harness.machine.memory.statics[0x459400] = int.from_bytes(bytes(self.image.blob[self.image.offset(0x459400):][:8]), "little") ^ (1 << 48)
        self.assertTrue(any(T.check(harness, c) for _, c in self.cases))

    def test_wrong_stub_argument_is_rejected(self):
        harness = T.Harness(self.image, T.COPIES[0])
        harness.exempt = None
        case = T.Case()
        harness.case = case
        with self.assertRaises(T.Mismatch):
            harness.need(False, "x")

    def test_rejected_inputs(self):
        rows = T.rejected_inputs(self.image)
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(ok for _, ok in rows))

    def test_wrong_digest(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image(T.BINARY, "0" * 64)

    def test_address_outside_function(self):
        with self.assertRaises(T.EvidenceError):
            self.image.exact_fde(T.COPIES[1]["start"] + 3)


class EvidenceTests(unittest.TestCase):
    def test_slot_targets_and_constants(self):
        image = T.load_image()
        rel = image.relative()
        self.assertEqual(rel[T.SLOT_EXEMPT], 0x421A3C0)
        self.assertEqual(rel[T.SLOT_AVAIL], 0x3D19870)
        self.assertEqual(rel[T.SLOT_ROUND], 0x63EFE40)
        import struct
        self.assertEqual(struct.unpack_from("<d", image.blob, image.offset(0x459400))[0], 1.1)
        self.assertEqual(struct.unpack_from("<d", image.blob, image.offset(0x459788))[0], 0.9)
        self.assertEqual(struct.unpack_from("<d", image.blob, image.offset(0x4599A0))[0], 1000000.0)

    def test_system_user_bytes(self):
        image = T.load_image()
        for at in (0x93E30B, 0x93EB11):
            raw = bytes(image.blob[image.offset(at):image.offset(at) + 16])
            self.assertIn(raw, (b"\xff" * 16, b"\xee" * 16))


class TableTests(unittest.TestCase):
    """Worked rows of the specification, checked against numbers worked out by hand."""

    def price(self, **kw):
        base = T.Case(size=0, user=T.SYSTEM_USERS[0], asset=10001, rows=(1000,) * 4)
        seen = T.probe_internals(base.changed(**kw))
        return seen["price"]

    def test_side_zero_floors_to_tick(self):
        self.assertEqual(self.price(side=0, tick=7), 1099)
        self.assertEqual(self.price(side=0, tick=1), 1100)

    def test_side_one_adds_a_whole_tick(self):
        self.assertEqual(self.price(side=1, tick=7), 903)
        self.assertEqual(self.price(side=1, tick=900), 1800)

    def test_fraction_moves_the_reference(self):
        self.assertEqual(self.price(side=0, delta=1000), 1111)
        self.assertEqual(self.price(side=1, delta=1000), 892)

    def test_amount_moves_the_reference(self):
        self.assertEqual(self.price(side=0, flag_a=1, delta=100), 1210)
        self.assertEqual(self.price(side=1, flag_a=1, delta=100), 811)

    def test_zero_tick_result_is_lifted_to_one(self):
        self.assertEqual(self.price(side=0, tick=1 << 40), 1)

    def test_reference_choice(self):
        base = T.Case(size=0, user=T.SYSTEM_USERS[0], asset=10001, rows=(1000,) * 4, tick=1)
        for side, optref, stop in ((0, 900, 0), (0, 1100, 1000), (1, 900, 1000), (1, 1100, 0), (0, 1000, 1000), (1, 1000, 1000), (0, 0, 1000)):
            out = T.spec(base.changed(side=side, optref=optref))[0]
            self.assertEqual(int.from_bytes(out[0xD8:0xE0], "little"), stop, (side, optref))

    def test_time_window_flag(self):
        base = T.Case(gate=1, tri1=(5, 5, 4), tri2=(5, 5, 5), last=100)
        self.assertEqual(T.spec(base.changed(now=5100))[0][0x12], 1)
        self.assertEqual(T.spec(base.changed(now=5099))[0][0x12], 0)

    def test_asset_word_remap(self):
        out = T.spec(T.Case(size=1, asset=10001, rows=(5,) * 4))[0]
        self.assertEqual(int.from_bytes(out[0x14:0x18], "little"), 110001)
        out = T.spec(T.Case(size=1, asset=1, rows=(5,) * 4, markets=3))[0]
        self.assertEqual(int.from_bytes(out[0x14:0x18], "little"), 1)


class GroupTests(Shared):
    def test_first_cases_of_every_group_on_every_copy(self):
        by_group = {}
        for group, case in T.all_cases(random_count=60):
            rows = by_group.setdefault(group, [])
            if len(rows) < 25:
                rows.append(case)
        self.assertGreaterEqual(len(by_group), 14)
        for copy in T.COPIES:
            harness = T.Harness(self.image, copy)
            for group, rows in by_group.items():
                for case in rows:
                    self.assertIsNone(T.check(harness, case), (copy["name"], group, case.label))

    def test_listing_is_deterministic(self):
        first = [c.label for _, c in T.all_cases(random_count=50)]
        second = [c.label for _, c in T.all_cases(random_count=50)]
        self.assertEqual(first, second)

    def test_mutation_rows_only_reached_instructions(self):
        harness = T.Harness(self.image, T.COPIES[0])
        harness.machine.seen = set()
        harness.run(T.Case(blocked=1))
        rows = T.mutation_rows(self.image, T.COPIES[0], harness.machine.seen)
        for va, kind, at, value in rows:
            self.assertIn(va, harness.machine.seen)


class StatusRecordTests(Shared):
    """Exact output bytes of each status on the real bytes of every copy, not only agreement with the specification."""

    def outputs(self, case):
        rows = []
        for copy in range(3):
            harness = T.Harness(self.image, T.COPIES[copy])
            got, log = harness.run(case)
            rows.append(got)
        self.assertEqual(rows[0], rows[1])
        self.assertEqual(rows[0], rows[2])
        return rows[0]

    def word(self, got, at, size=8):
        return int.from_bytes(got[1][at:at + size], "little")

    def test_blocked_record(self):
        got = self.outputs(T.Case(blocked=1))
        self.assertEqual(self.word(got, 0), 1)
        self.assertEqual(self.word(got, 0x10, 2), 0x19C)
        self.assertEqual(got[1][0x12], T.MARKER)

    def test_pass_through_copies_the_lookup_record(self):
        case = T.Case(ref_tag=0x77, fill=9)
        got = self.outputs(case)
        self.assertEqual(got[1][0x10:0x80], bytes(case.tmp()))
        self.assertEqual(got[1][0x80], T.MARKER)

    def test_step_record_has_status_and_stale_words(self):
        case = T.Case(flag_a=1, side=1, delta=700, fill=3)
        got = self.outputs(case)
        self.assertEqual(self.word(got, 0x10, 2), 0xDE)
        self.assertEqual(got[1][0x12:0x16], bytes(case.tmp())[2:6])
        self.assertEqual(got[1][0x18:0x20], bytes([T.MARKER]) * 8)

    def test_fee_record(self):
        got = self.outputs(T.Case(size=1 << 40, rows=(1 << 30,) * 4))
        self.assertEqual(self.word(got, 0x10, 2), 0x6D)

    def test_available_record_payload(self):
        got = self.outputs(T.Case(avail=2500))
        self.assertEqual(self.word(got, 0x10, 2), 0x6C)
        self.assertEqual(self.word(got, 0x18), T.bits(0.0025))

    def test_minimum_value_record(self):
        got = self.outputs(T.Case(size=1, rows=(5, 6, 7, 8), asset=10000 + 2))
        self.assertEqual(self.word(got, 0x10, 2), 0xC8)
        self.assertEqual(self.word(got, 0x14, 4), 100000 + 10002)
        self.assertEqual(self.word(got, 0x18), 0x8000000000000001)
        self.assertEqual(self.word(got, 0x20), 0x4024000000000000)

    def test_minimum_value_asset_word_for_market_zero(self):
        got = self.outputs(T.Case(size=1, rows=(5, 6, 7, 8), asset=3))
        self.assertEqual(self.word(got, 0x14, 4), 3)

    def test_time_record(self):
        got = self.outputs(T.Case(gate=1, tri1=(5, 5, 4), tri2=(5, 5, 5), last=7, now=5007))
        self.assertEqual(self.word(got, 0x10, 2), 0x78)
        self.assertEqual(got[1][0x12], 1)
        got = self.outputs(T.Case(gate=1, tri1=(5, 5, 4), tri2=(5, 5, 5), last=7, now=5006))
        self.assertEqual(got[1][0x12], 0)

    def test_band_record_payload(self):
        got = self.outputs(T.Case(p=0.0001, rows=(1000,) * 4, optref=0, size=1000, tick=1, side=0, asset=10001, user=T.SYSTEM_USERS[0]))
        if self.word(got, 0x10, 2) == 0x63:
            self.assertEqual(self.word(got, 0x18), T.bits(0.0001 * 100.0))
        else:
            self.fail("expected the band to refuse")

    def test_accepted_record_fields(self):
        case = T.Case(gate=1, flag_b=1, side=1, delta=3, junk=0x55, optref=900, rows=(1000,) * 4, asset=10001, size=77, stamp=0xABCDEF, p=0.5)
        got = self.outputs(case)
        self.assertEqual(self.word(got, 0), 0)
        self.assertEqual(self.word(got, 0x10), 77)
        self.assertEqual(self.word(got, 0x40), 8)
        self.assertEqual(self.word(got, 0x50), 10)
        self.assertEqual(self.word(got, 0x60), 1 << 63)
        self.assertEqual(self.word(got, 0xA0), 0xABCDEF)
        self.assertEqual(got[1][0xA8], 1)
        self.assertEqual(got[1][0xBA], 1)
        self.assertEqual(self.word(got, 0xC0), 0x5500)
        self.assertEqual(self.word(got, 0xC8), 3)
        self.assertEqual(self.word(got, 0xD0), 900)

    def test_system_users_pass_the_floor_and_others_do_not(self):
        for user, status in ((T.SYSTEM_USERS[0], None), (T.SYSTEM_USERS[1], None), (bytes(range(20)), 0xC8), (b"\xff" * 19 + b"\xfe", 0xC8)):
            got = self.outputs(T.Case(size=1, rows=(5, 6, 7, 8), user=user))
            if status is None:
                self.assertEqual(self.word(got, 0), 0)
            else:
                self.assertEqual(self.word(got, 0x10, 2), status)

    def test_panics_name_their_table(self):
        self.assertEqual(self.outputs(T.Case(asset=30001)), ("panic", "market"))
        self.assertEqual(self.outputs(T.Case(second=1, asset=10001)), ("panic", "second"))
        self.assertEqual(self.outputs(T.Case(asset=10009)), ("panic", "bounds"))

    def test_edge_log_order_on_acceptance(self):
        harness = T.Harness(self.image, T.COPIES[0])
        _, log = harness.run(T.Case(gate=1))
        self.assertEqual([row[0] for row in log], ["exempt", "drop", "ref", "drop", "drop", "tick", "avail", "look", "gate", "band", "stamp"])

    def test_stub_argument_check_fires(self):
        harness = T.Harness(self.image, T.COPIES[0])
        harness.case = T.Case()
        harness.machine.regs[T.RDI] = 0
        with self.assertRaises(T.Mismatch):
            harness.exempt(harness.machine)


class FlawTests(Shared):
    """Each wrong rule must disagree with the real bytes on at least one case of the group built for it."""

    def separated(self, flaw, group, limit=600):
        harness = T.Harness(self.image, T.COPIES[0])
        for name, case in T.all_cases(random_count=0):
            if name != group:
                continue
            limit -= 1
            if limit < 0:
                break
            got, log = harness.run(case)
            try:
                out, rax, wlog = T.spec(case, flaw)
                want = (rax, bytes(out))
            except T.Panic as error:
                want, wlog = ("panic", error.label), None
            if not T.agree(case, got, log, want, wlog):
                return True
        return False

    def test_step_rules(self):
        for flaw in ("add_wrap", "step_equal_ok", "cond_strict", "ignore_optref"):
            self.assertTrue(self.separated(flaw, "step"), flaw)

    def test_fraction_rules(self):
        for flaw in ("fraction_sign", "factor_swap"):
            self.assertTrue(self.separated(flaw, "fraction") or self.separated(flaw, "step") or self.separated(flaw, "band"), flaw)

    def test_tick_rules(self):
        for flaw in ("ceil_both", "floor_both"):
            self.assertTrue(self.separated(flaw, "tick"), flaw)

    def test_gate_rules(self):
        for flaw in ("no_system", "one_system", "pick_swap", "remap_short"):
            self.assertTrue(self.separated(flaw, "gate", 1400) or self.separated(flaw, "asset word"), flaw)

    def test_time_rules(self):
        for flaw in ("tri_strict", "lim_ge", "window_4999"):
            self.assertTrue(self.separated(flaw, "time", 900), flaw)

    def test_band_rules(self):
        self.assertTrue(self.separated("p_ge", "equal band"))
        self.assertTrue(self.separated("no_upper", "gate", 1400) or self.separated("no_upper", "band"))

    def test_cap_rules(self):
        self.assertTrue(self.separated("cap_ge", "available"))
        self.assertTrue(self.separated("cap_scale", "available"))

    def test_the_specification_without_a_flaw_agrees(self):
        harness = T.Harness(self.image, T.COPIES[2])
        count = 0
        for name, case in T.all_cases(random_count=0):
            if name == "equal band":
                self.assertIsNone(T.check(harness, case))
                count += 1
        self.assertGreater(count, 40)


if __name__ == "__main__":
    unittest.main()
