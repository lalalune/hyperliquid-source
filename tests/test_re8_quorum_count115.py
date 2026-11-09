import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re8_quorum_count115 as t  # noqa: E402


SHARED = {}


def shared():
    if not SHARED:
        SHARED["image"] = t.load_image()
        SHARED["cases"] = list(t.all_cases())
    return SHARED


class QuorumCount115(unittest.TestCase):
    def setUp(self):
        self.image = shared()["image"]
        self.cases = shared()["cases"]

    def sample(self, step, offset=0):
        return [(i, self.cases[i]) for i in range(offset, len(self.cases), step)]

    def test_wrong_digest_rejected(self):
        with self.assertRaises(t.EvidenceError):
            t.load_image(t.BINARY, "0" * 64)

    def test_function_bounds(self):
        self.assertEqual(self.image.exact_fde(t.QUORUM), (0x595BC40, 0x595C268))
        self.assertEqual([self.image.exact_fde(a)[1] - a for a in (0x4D3E1A0, 0x4E44C00, 0x4E406F0, 0x5138730, 0x57F54E0)], [365, 515, 669, 534, 459])
        with self.assertRaises(t.EvidenceError):
            self.image.exact_fde(t.QUORUM + 1)
        with self.assertRaises(t.EvidenceError):
            self.image.offset(0x10)

    def test_case_set_size_and_groups(self):
        self.assertGreaterEqual(len(self.cases), 10000)
        kinds = {kind for kind, _ in self.cases}
        self.assertEqual(kinds, {"fraction_grid", "random_trees", "precheck_value", "signer_root_null", "stake_root_null", "u64_rounding",
                         "stake_quorum_tree_boundary", "stake_quorum_tree_wide", "stake_quorum_tree_small",
                         "stake_quorum_ring_boundary", "stake_quorum_ring_wide", "stake_quorum_ring_small"})

    def test_bytes_match_rule_list_on_a_sample(self):
        lookup = t.Quorum(self.image)
        for index, (kind, world) in self.sample(41):
            got, want = t.run_case(lookup, world)
            self.assertEqual(got, want, "case %d %s" % (index, kind))

    def test_fraction_table(self):
        table = {0x0: None, 0x8000000000000000: None, 0x3FE0000000000000: 0.5, 0x3FECCCCCCCCCCCCD: 0.7, 0x3FF0000000000000: 0.7,
                 0x7FF0000000000000: 1.0, 0xFFF0000000000000: 1.0, 0x7FF8000000000000: 1.0, 0xBFF0000000000000: None,
                 0x7FEFFFFFFFFFFFFF: 0.7, 0x1: 5e-324, 0xFFEFFFFFFFFFFFFF: None}
        for bits, want in table.items():
            self.assertEqual(t.effective_fraction(bits), want, hex(bits))

    def test_precheck_false_reads_nothing_else(self):
        lookup = t.Quorum(self.image)
        world = t.make_world(5, 3, 1, 12, 0x3FE0000000000000, 12, pre=0x100)
        got, want = t.run_case(lookup, world)
        self.assertEqual(got, (0, (("pre", t.STAKES_AT, t.SIGNERS_AT),)))
        self.assertEqual(got, want)

    def test_strict_comparison_at_the_boundary(self):
        lookup = t.Quorum(self.image)
        base = t.make_world(7, 3, 0, 12, 0x3FE0000000000000, 6)  # 3 signers of 12, total 6: 3 > 0.5 * 6 is false
        self.assertEqual(lookup.run(base)[0], 0)
        self.assertEqual(lookup.run(dict(base, total=5))[0], 1)

    def test_stub_calls_in_order(self):
        lookup = t.Quorum(self.image)
        world = t.make_world(11, 2, 1, 40, 0x3FE0000000000000, 40)
        got, _ = t.run_case(lookup, world)
        self.assertEqual(got[1][0], ("pre", t.STAKES_AT, t.SIGNERS_AT))
        self.assertTrue(all(item[0] == "cmp" for item in got[1][1:]))
        self.assertGreater(len(got[1]), 3)

    def test_rule_list_flaws_all_detected(self):
        lookup = t.Quorum(self.image)
        for flaw, detected, where in t.flaw_rows(self.cases, self.image):
            self.assertTrue(detected, flaw)

    def killed(self, patch, step=23, pick=None):
        lookup = t.Quorum(self.image, patch)
        lookup.machine.step_limit = 60000
        rows = self.sample(step) if pick is None else [(i, c) for i, c in enumerate(self.cases) if pick(c[1])][:12]
        for index, (kind, world) in rows:
            try:
                got, want = t.run_case(lookup, world)
            except t.CAUGHT:
                return True
            if got != want:
                return True
        return False

    def test_condition_flip_after_precheck_is_detected(self):
        row = self.image.blob[self.image.offset(0x595BC65)]
        self.assertEqual(row, 0x74)  # je after test %al,%al
        self.assertTrue(self.killed({0x595BC65: 0x75}))

    def test_unedited_bytes_are_not_flagged(self):
        self.assertFalse(self.killed({}, 97))

    def test_clamp_constant_edit_is_detected(self):
        # the compare against 0x7fefffffffffffff: flip the low immediate byte of the movabs
        at = 0x595BC84
        edge = lambda world: world["frac"] & 0x7FFFFFFFFFFFFFFF == 0x7FEFFFFFFFFFFFFF
        self.assertTrue(self.killed({at: self.image.blob[self.image.offset(at)] ^ 1}, pick=edge))

    def test_damaged_layouts_are_detected(self):
        for job in (("set", "koff"), ("set", "length"), ("argument", "fraction"), ("argument", "stake_total")):
            t.STATE.update(image=self.image, cases=self.cases, layout_cases=[i for i, _ in self.sample(53)])
            self.assertTrue(t.layout_task(job)[2], job)

    def test_signer_root_null_ignores_the_length_word(self):
        lookup = t.Quorum(self.image)
        world = t.make_world(13, 4, 0, 12, 0x3FE0000000000000, 12)
        a = lookup.run(dict(world, a_null=3, alen=2))
        b = lookup.run(dict(world, a_null=3, alen=40))
        self.assertEqual(a, b)
        self.assertEqual(a[0], 0)

    def test_range_controls_all_refused(self):
        for name, detected in t.range_controls(self.image):
            self.assertTrue(detected, name)

    def test_fixture_tree_check_refuses_a_wrong_order(self):
        lookup = t.Quorum(self.image)
        lookup.prepare(self.cases[0][1])
        with self.assertRaises(t.EvidenceError):
            lookup.check_set(0, 0, [b"b" * 20, b"a" * 20])


class StakeQuorum115(unittest.TestCase):
    def setUp(self):
        self.image = shared()["image"]
        self.keys = sorted(t.address(n) for n in range(30, 36))

    def world(self, values, signers, form="tree"):
        keys = self.keys
        return dict(t.make_world(21, 0, 0, 6, 0, 6), A=tuple(signers), B=tuple(keys), total=6, stake_map=tuple(zip(keys, values)),
                    stake_form=form, ring_head=3, ring_spare=2)

    def test_exactly_two_thirds_fails_and_one_more_passes(self):
        lookup = t.Quorum(self.image)
        for form in ("tree", "ring"):
            equal = self.world((2, 2, 1, 1, 0, 0), self.keys[:2], form)  # signed 4, total 6: 12 > 12 is false
            more = self.world((3, 2, 1, 1, 0, 0), self.keys[:2], form)  # signed 5, total 7: 15 > 14
            self.assertEqual(lookup.run(equal)[0], 0, form)
            self.assertEqual(lookup.run(more)[0], 1, form)
            self.assertEqual(t.run_case(lookup, more)[0], t.run_case(lookup, more)[1], form)

    def test_sums_saturate_at_u64_max(self):
        top = (1 << 64) - 1
        self.assertEqual(t.saturating_sum([top, 5]), top)
        self.assertNotEqual(t.saturating_sum([top, 5], "wrapping_sums"), top)
        lookup = t.Quorum(self.image)
        world = self.world((top, top, top, 0, 0, 0), self.keys[:2])
        got, want = t.run_case(lookup, world)
        self.assertEqual(got, want)

    def test_ring_and_tree_forms_agree(self):
        lookup = t.Quorum(self.image)
        for values, signers in (((5, 4, 3, 2, 1, 0), 3), ((1, 1, 1, 1, 1, 1), 5), ((0, 0, 0, 0, 0, 9), 6), ((7, 0, 0, 0, 0, 0), 1)):
            tree = self.world(values, self.keys[:signers], "tree")
            ring = dict(tree, stake_form="ring")
            self.assertEqual(lookup.run(tree)[0], lookup.run(ring)[0], values)

    def test_every_ring_head_position_matches_the_rule_list(self):
        lookup = t.Quorum(self.image)
        for head in range(0, 9):
            for spare in (0, 1, 3):
                world = dict(self.world((4, 3, 2, 1, 1, 1), self.keys[1:4], "ring"), ring_head=head, ring_spare=spare)
                got, want = t.run_case(lookup, world)
                self.assertEqual(got, want, (head, spare))

    def test_nonfinite_fraction_means_one(self):
        lookup = t.Quorum(self.image)
        keys = self.keys
        base = dict(t.make_world(31, 6, 0, 6, 0, 6), pre=1)
        # six of six signers found, total 6: 6 > f * 6 holds for every finite f up to 0.7 but not for 1.0
        for bits, want in ((0x7FF0000000000000, 0), (0xFFF8000000000000, 0), (0x3FE0000000000000, 1), (0xBFF0000000000000, 1)):
            self.assertEqual(lookup.run(dict(base, frac=bits))[0], want, hex(bits))

    def test_u64_total_is_converted_with_one_rounding(self):
        lookup = t.Quorum(self.image)
        total = (1 << 60) + 3
        bits = t.to_bits(3.0 / float(total))
        world = dict(t.make_world(33, 3, 0, 6, bits, total), pre=1)
        got, want = t.run_case(lookup, world)
        self.assertEqual(got, want)
        self.assertEqual(want[0], int(3.0 > t.to_float(bits) * float(total)))

    def test_unlisted_signers_add_nothing(self):
        lookup = t.Quorum(self.image)
        outsider = t.address(999)
        world = self.world((1, 1, 1, 0, 0, 0), [outsider])
        self.assertEqual(lookup.run(world)[0], 0)


if __name__ == "__main__":
    unittest.main()
