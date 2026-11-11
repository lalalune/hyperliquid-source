import itertools
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import risk_position_ratio115 as tool  # noqa: E402


class PositionRatioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.locs = tool.Locations(cls.image)
        cls.floor = tool.min_ratio(cls.image)
        cls.harness = tool.Harness(cls.image)
        cls.cases = {case.name: case for case in tool.named_cases()}

    def run_case(self, name):
        before, got = self.harness.run(self.cases[name])
        return got, tool.spec_run(self.cases[name], self.locs, self.floor)

    def custom(self, **kw):
        fields = dict(name="custom", mode="deque", entries=[(3, tool.entry(tag=0, v=5, b=40))], key=3, flag=1, rows=[0, 0, 0, 100], helper=1000, cap=2, head=1)
        fields.update(kw)
        case = tool.Case(fields["name"], fields["mode"], fields["entries"], fields["key"], fields["flag"], fields["rows"], helper=fields["helper"], cap=fields["cap"], head=fields["head"])
        before, got = self.harness.run(case)
        return case, got

    def test_digest_is_pinned(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not the node")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_functions_are_whole_fdes(self):
        for target, size in ((tool.SUBJECT, 1008), (tool.RING, 284), (tool.TREE, 146)):
            start, end = self.image.exact_fde(target)
            self.assertEqual(end - start, size)
            self.assertEqual(sum(row.size for row in tool.decode_range(self.image, start, end)), size)

    def test_non_function_addresses_refused(self):
        for va in (tool.SUBJECT + 1, tool.SUBJECT - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_floor_constant_from_bytes(self):
        self.assertEqual(self.floor, 1e-8)

    def test_location_records(self):
        relative = self.image.relative()
        self.assertEqual(self.image.location(self.locs.size, relative)[0], "l1/src/clearinghouse/position.rs")
        self.assertEqual(self.image.location(self.locs.index, relative)[0], "l1/src/clearinghouse/oracle/oracle.rs")
        self.assertEqual(self.image.location(self.locs.add, relative)[0], "l1/src/qtys/impl_ntl.rs")
        self.assertEqual(self.locs.add, self.locs.sub)
        self.assertEqual(self.locs.fmt_length, 0x2B)

    def test_all_named_cases_agree(self):
        for name in self.cases:
            got, want = self.run_case(name)
            self.assertEqual(got, want, name)

    def test_refusals_leave_output_untouched(self):
        for name in ("missing key", "zero size", "wrong side", "empty deque", "empty tree", "tree absent key"):
            got, _ = self.run_case(name)
            self.assertEqual(got[0], "ret")
            self.assertEqual(got[1][:8], bytes(8))
            self.assertEqual(got[1][8:], tool.OUT_INIT[8:])
            self.assertEqual(got[2], ())

    def test_ratio_formula(self):
        # notional 5 * 100, margin figure 1000, other word 40 taken from the notional on the long side
        case, got = self.custom(rows=[0, 0, 0, 100], helper=1000)
        self.assertEqual(struct.unpack_from("<d", got[1], 8)[0], 0.5 * 11.5)
        self.assertEqual(got[2][0], ("ctor", case.r8, 7))
        self.assertEqual(got[2][1], ("step", 500))
        self.assertEqual(got[2][2][0], "route")

    def test_short_side_adds_the_stored_balance(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=1, v=-5, b=40, c=100))], flag=0)
        self.assertEqual([row[0] for row in got[2]], ["ctor", "step"])
        self.assertEqual(got[2][1], ("step", 500))
        # the figure is -500 + 100, not positive, so the first factor is the floor; the second sees no positive numerator
        self.assertEqual(struct.unpack_from("<d", got[1], 8)[0], 1e-8 * 1e-8)

    def test_helper_not_positive_gives_the_floor(self):
        for helper in (0, -1, tool.MIN64):
            case, got = self.custom(helper=helper)
            ratio = struct.unpack_from("<d", got[1], 8)[0]
            self.assertEqual(ratio, 1e-8 * max((500.0 - 40.0) / 40.0, 1e-8))

    def test_zero_other_word_gives_the_floor(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=0, v=5, b=0))], helper=1000)
        self.assertEqual(struct.unpack_from("<d", got[1], 8)[0], 0.5 * 1e-8)

    def test_negative_other_word_is_a_formatted_panic(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=0, v=5, b=-1))])
        self.assertEqual(got[0], "fmt")
        self.assertEqual(got[1][1], 0x2B)

    def test_row_index_panic_reports_index_and_count(self):
        case, got = self.custom(rows=[1, 2])
        self.assertEqual(got[:3], ("index", 3, 2))
        self.assertEqual(got[3], self.locs.index)

    def test_key_is_taken_modulo_10000(self):
        rows = [0] * 4 + [3]
        case, got = self.custom(key=20004, entries=[(20004, tool.entry(tag=0, v=5, b=40))], rows=rows)
        self.assertEqual(got[2][1], ("step", 15))

    def test_negative_row_and_product_overflow_share_one_site(self):
        _, negative = self.custom(rows=[0, 0, 0, tool.MIN64 & tool.TOP])
        _, overflow = self.custom(entries=[(3, tool.entry(tag=0, v=tool.MAX64, b=1))], rows=[0, 0, 0, 2])
        self.assertEqual(negative[:2], ("panic", self.locs.size))
        self.assertEqual(overflow[:2], ("panic", self.locs.size))

    def test_most_negative_product_keeps_bit_pattern(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=0, v=tool.MIN64, b=1))], flag=0, rows=[0, 0, 0, 1])
        self.assertEqual(got[2][1], ("step", 1 << 63))

    def test_saturating_add_is_logged_twice(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=1, v=5, b=3, c=tool.MAX64))])
        self.assertEqual([row[0] for row in got[2]], ["ctor", "step", "sat", "sat"])
        self.assertEqual(got[2][2], ("sat", 0, self.locs.add))

    def test_saturating_subtract_only_on_the_low_side(self):
        case, got = self.custom(entries=[(3, tool.entry(tag=0, v=tool.MIN64, b=1 << 62))], flag=2, rows=[0, 0, 0, 1], helper=5)
        self.assertEqual(got[2][-1], ("sat", 0, self.locs.sub))
        value = struct.unpack_from("<d", got[1], 8)[0]
        self.assertEqual(value, max(2.0 ** 63 / 5.0, 1e-8) * 1e-8)

    def test_tail_words_copied_from_the_block(self):
        case, got = self.custom()
        self.assertEqual(got[1][0x10:0x24], case.blk)
        self.assertEqual(got[1][0x24:], tool.OUT_INIT[0x24:])

    def test_ring_search_all_wrap_offsets(self):
        for count in (0, 1, 3, 7, 11):
            keys = [3 * slot + 1 for slot in range(count)]
            entries = [(key, tool.entry(tag=0, v=1 + slot, b=1)) for slot, key in enumerate(keys)]
            for head in range(count + 2):
                for key in keys + [0, 3 * count + 2, 2]:
                    case = tool.Case("probe", "deque", entries, key, 1, [0] * 40 + [9], helper=100, cap=count + 2, head=head)
                    before, got = self.harness.run(case)
                    self.assertEqual(got, tool.spec_run(case, self.locs, self.floor))
                    self.assertEqual(got[1][0] == 1, key in keys)

    def test_tree_search_two_levels(self):
        for count in (11, 12, 23, 33):
            entries = [(2 * slot + 2, tool.entry(tag=0, v=1 + slot, b=1)) for slot in range(count)]
            for key in [entry[0] for entry in entries] + [1, 2 * count + 3, 7]:
                case = tool.Case("probe", "tree", entries, key, 1, [0] * 80, helper=100)
                before, got = self.harness.run(case)
                self.assertEqual(got, tool.spec_run(case, self.locs, self.floor))

    def test_imul_flags(self):
        machine = self.harness.machine
        self.assertEqual(machine.signed_product(3, 4, 8), 12)
        self.assertFalse(machine.of)
        self.assertEqual(machine.signed_product(tool.MAX64, 2, 8), (tool.MAX64 * 2) & tool.TOP)
        self.assertTrue(machine.of and machine.cf)
        machine.signed_product(tool.TOP, 5, 8)
        self.assertFalse(machine.of)
        machine.signed_product(1 << 63, tool.TOP, 8)
        self.assertTrue(machine.of)

    def test_vectors_agree_with_the_rule_list(self):
        harness = tool.Harness(self.image)
        count = tool.check_stream(harness, tool.vector_cases(600, seed=0x4242), self.locs, self.floor)
        self.assertEqual(count, 600)

    def test_edge_cases_agree(self):
        harness = tool.Harness(self.image)
        count = tool.check_stream(harness, itertools.islice(tool.edge_cases(), 0, None, 9), self.locs, self.floor)
        self.assertGreater(count, 200)

    def test_every_wrong_reading_is_refused(self):
        sample = list(self.cases.values()) + list(tool.vector_cases(300, seed=0x77)) + list(itertools.islice(tool.grid_cases(), 0, 4000, 7))
        sample += [case for case in tool.edge_cases() if case.flag == 2][::2]
        for name in tool.VARIANTS:
            failure = tool.first_failure(self.harness, sample, self.locs, self.floor, frozenset((name,)))
            self.assertIsNotNone(failure, name)

    def test_wrong_constant_is_refused(self):
        sample = list(self.cases.values())
        self.assertIsNotNone(tool.first_failure(self.harness, sample, self.locs, self.floor * 2))
        self.assertIsNotNone(tool.first_failure(self.harness, sample, self.locs, 0.0))

    def test_swapped_locations_are_refused(self):
        sample = list(self.cases.values())
        wrong = tool.Locations(self.image)
        wrong.index, wrong.size = wrong.size, wrong.index
        self.assertIsNotNone(tool.first_failure(self.harness, sample, wrong, self.floor))

    def test_byte_edits_are_killed(self):
        sample = list(self.cases.values()) + list(itertools.islice((c for c in tool.edge_cases() if c.flag == 2), 0, None, 4))
        table = {target: tool.decode_range(self.image, *self.image.exact_fde(target)) for target in tool.TARGETS}
        harness = tool.Harness(self.image)
        for case in sample:
            harness.run(case)
        edits = tool.edits_for(self.image, table[tool.SUBJECT], harness.machine.seen)
        self.assertGreater(len(edits), 60)
        killed = 0
        for va, kind, patch in edits[:40]:
            mutant = tool.Harness(self.image, patch)
            mutant.machine.step_limit = tool.MUTANT_STEP_LIMIT
            killed += tool.first_failure(mutant, sample, self.locs, self.floor) is not None
        self.assertGreater(killed, 30)

    def test_out_of_range_inputs_are_not_matched(self):
        case = self.cases["deque long route"]
        broken = tool.Case(case.name, case.mode, case.entries, case.key, case.flag, case.rows, r8=case.r8 + 1, helper=case.helper, cap=case.cap, head=case.head, blk=case.blk)
        before, got = self.harness.run(case)
        self.assertNotEqual(tool.spec_run(broken, self.locs, self.floor), got)

    def test_generation_is_deterministic(self):
        rows = tool.analyse(self.image, vectors=60, mutate=False)
        again = tool.analyse(self.image, vectors=60, mutate=False)
        self.assertEqual(tool.render(rows), tool.render(again))
        self.assertIn('"negative_controls"', tool.render(rows)["measure.json"])


if __name__ == "__main__":
    unittest.main()
