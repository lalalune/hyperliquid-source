import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vault_amount_helper115 as vh  # noqa: E402

KEY = bytes(range(1, 21))
EMPTY = vh.Store("deque", [], 1, 0)


def make(**kw):
    fields = dict(cell=100, default_cell=555, flag1=0, store2=EMPTY, default2=EMPTY, flag2=0, store3=EMPTY, extra_flag=0, extra=0,
                  m1=(1, 0), m2=(1, 0))
    fields.update(kw)
    return vh.Case("t", KEY, fields["cell"], fields["default_cell"], fields["flag1"], fields["store2"], fields["default2"], fields["flag2"],
                   fields["store3"], 0, fields["extra_flag"], fields["extra"], fields["m1"], fields["m2"])


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = vh.load_image()
        cls.harness = vh.Harness(cls.image)
        cls.cases = vh.named_cases() + list(vh.random_cases(1200, seed=0xBEEF))
        cls.reached = vh.collections.Counter()
        cls.stats, cls.caught, cls.sample = vh.check_stream(cls.harness, cls.cases, vh.VARIANTS, keep=100, hits=cls.reached)


class TestImage(unittest.TestCase):
    def test_digest_is_pinned(self):
        self.assertEqual(vh.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(vh.EvidenceError):
            vh.load_image(vh.BINARY, "0" * 64)

    def test_function_extents(self):
        image = vh.load_image()
        sizes = {entry: image.exact_fde(entry)[1] - entry for entry in vh.FUNCTIONS}
        self.assertEqual(sizes[vh.FEE], 0x37F)
        self.assertEqual(sizes[vh.DEQUE32], 0x121)
        for entry in vh.FUNCTIONS:
            with self.assertRaises(vh.EvidenceError):
                image.exact_fde(entry + 1)

    def test_nobits_has_no_bytes(self):
        image = vh.load_image()
        with self.assertRaises(vh.EvidenceError):
            image.offset(image.named[".bss"]["address"] + 8)

    def test_truncated_elf_is_refused(self):
        with self.assertRaises(Exception):
            vh.Image(bytes(48))


class TestRuleList(unittest.TestCase):
    def test_quotient_and_saturation(self):
        got, log = vh.spec(make(store2=vh.Store("deque", [(0, 12345)], 1, 0)))
        self.assertEqual(got, ("ret", 100 + 123))
        got, log = vh.spec(make(cell=vh.I64_MAX, store2=vh.Store("deque", [(0, 10 ** 6)], 1, 0)))
        self.assertEqual(got, ("ret", vh.I64_MAX))
        self.assertEqual([row for row in log if row[0] == "overflow"], [("overflow", vh.LOC_TOTAL)])
        got, log = vh.spec(make(store2=vh.Store("deque", [(0, (1 << 64) - 1)], 1, 0), store3=vh.Store("deque", [(0, 1)], 1, 0), extra=9))
        self.assertEqual(got, ("ret", 100 + ((1 << 64) - 1) // 100))
        self.assertIn(("overflow", vh.LOC_SUM), log)

    def test_extra_flag_bit_zero_means_none(self):
        base = dict(store2=vh.Store("deque", [(0, 1000)], 1, 0), store3=vh.Store("deque", [(0, 1)], 1, 0), extra=5000)
        self.assertEqual(vh.spec(make(extra_flag=0, **base))[0], ("ret", 160))
        self.assertEqual(vh.spec(make(extra_flag=1, **base))[0], ("ret", 110))
        self.assertEqual(vh.spec(make(extra_flag=2, **base))[0], ("ret", 160))

    def test_missing_cell_uses_default(self):
        self.assertEqual(vh.spec(make(cell=None))[0], ("ret", 555))

    def test_bad_probe_index_panics(self):
        got, log = vh.spec(make(m1=(3, 1)))
        self.assertEqual(got, ("panic", "bounds"))
        self.assertEqual(log[-1], ("bounds", 6, 3))

    def test_deque_rule(self):
        wrapped = vh.Store("deque", [(2, 1), (0, 2)], 2, 1)
        self.assertEqual(vh.deque_find(wrapped, ()), 1)
        self.assertIsNone(vh.deque_find(vh.Store("deque", [(2, 1), (3, 2)], 3, 1), ()))
        self.assertEqual(vh.deque_find(vh.Store("deque", [(0, 1), (0, 2), (0, 3)], 3, 0), ()), 2)

    def test_tree_rule_reads_only_the_leftmost_path(self):
        deep = vh.Store("tree", [], 0, 0, vh.Tree([4], [1], [vh.Tree([0], [77]), vh.Tree([9], [2])]), 1)
        self.assertEqual(vh.tree_find(deep, True, ()), 77)
        shallow = vh.Store("tree", [], 0, 0, vh.Tree([4, 0], [1, 5]), 0)
        self.assertIsNone(vh.tree_find(shallow, True, ()))

    def test_siphash13_known_properties(self):
        a = vh.siphash13(1, 2, bytes(20))
        self.assertEqual(a, vh.siphash13(1, 2, bytes(20)))
        self.assertNotEqual(a, vh.siphash13(2, 1, bytes(20)))
        self.assertNotEqual(a, vh.siphash13(1, 2, bytes(19)))
        self.assertNotEqual(a, vh.siphash13(1, 2, bytes(19) + b"\x01"))

    def test_divisor_is_exact(self):
        error, exact, points, mismatches = vh.magic_rows()[0]
        self.assertEqual((exact, mismatches), (1, 0))
        self.assertLess(error * (1 << 62), 1 << 66)


class TestAgainstBytes(Fixture):
    def test_every_case_matches_the_rule_list(self):
        self.assertEqual(self.stats["mismatches"], 0, self.stats["first_mismatch"])
        self.assertGreaterEqual(self.stats["cases"], 1200)

    def test_every_outcome_class_occurs(self):
        kinds = {kind for _, _, kind in self.stats["kinds"]}
        self.assertEqual(kinds, {"plain", "saturated", "panic"})
        stores = {(a, b) for a, b, _ in self.stats["kinds"]}
        for pair in (("deque", "deque"), ("tree", "tree"), ("deque", "tree"), ("tree", "deque"), ("none", "deque")):
            self.assertIn(pair, stores)

    def test_every_wrong_reading_is_refused(self):
        missed = [name for name, (count, _) in self.caught.items() if not count]
        self.assertEqual(missed, [])
        self.assertGreaterEqual(len(self.caught), 23)

    def test_real_helpers_are_reached(self):
        for entry in vh.FUNCTIONS:
            self.assertIn(entry, self.reached)

    def test_real_siphash_matches_the_written_rounds(self):
        hashed = [case for case in self.cases if case.m1[0] > 1]
        self.assertGreater(len(hashed), 100)
        for case in hashed[:60]:
            got, log = vh.run_case(self.harness, case)
            self.assertEqual((got, log), vh.spec(case))
            self.assertTrue(any(row[0] == "probe" and row[1] == "map1" for row in log))

    def test_lazy_initialisers_install_the_default_store(self):
        case = make(store2=vh.Store("none"), default2=vh.Store("deque", [(0, 4000)], 1, 0), flag2=3, m2=(0, 0))
        got, log = vh.run_case(self.harness, case)
        self.assertEqual(got, ("ret", 140))
        self.assertIn(("init", vh.FLAG2), log)
        quiet = make(store2=vh.Store("none"), default2=vh.Store("deque", [(0, 4000)], 1, 0), flag2=0, m2=(0, 0))
        self.assertEqual(vh.run_case(self.harness, quiet)[0], ("ret", 140))

    def test_wrong_reading_changes_the_result(self):
        case = make(store2=vh.Store("deque", [(0, 12345)], 1, 0))
        got, log = vh.run_case(self.harness, case)
        self.assertEqual((got, log), vh.spec(case))
        self.assertNotEqual(vh.spec(case, frozenset({"ceil_division"})), (got, log))
        self.assertNotEqual(vh.spec(case, frozenset({"no_division"})), (got, log))


class TestControls(Fixture):
    def test_structural_controls_all_detected(self):
        rows = vh.structural_controls(self.image, self.harness, self.cases)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual([name for name, detected, _ in rows if not detected], [])

    def test_edited_condition_is_killed(self):
        picked = self.cases[:60]
        first = [m for m in vh.mutants_of(self.image, self.reached) if m[0] == 0x44A9462 or m[1] == "condition"][:6]
        rows = vh.run_mutants(self.image, first, picked)
        self.assertTrue(any(row[5] for row in rows))

    def test_equivalent_mutant_is_not_killed(self):
        picked = self.cases[:200]
        mutant = next(m for m in vh.mutants_of(self.image, self.reached) if (m[0], m[1]) == (0x44A979F, "immediate"))
        rows = vh.run_mutants(self.image, [mutant], picked)
        self.assertFalse(rows[0][5])
        self.assertEqual(((1 << 64) - 2) >> 2, ((1 << 64) - 1) >> 2)

    def test_every_equivalent_row_has_a_reason(self):
        self.assertEqual(len(vh.EQUIVALENT), 16)
        for reason in vh.EQUIVALENT.values():
            self.assertGreater(len(reason), 40)

    def test_unlisted_survivor_is_refused(self):
        with self.assertRaises(vh.EvidenceError):
            vh.analyse(150, True, 10)

    def test_corrupted_entry_byte_is_caught(self):
        trapped = vh.Harness(self.image, {vh.DEQUE40: 0xCC})
        case = make(store3=vh.Store("deque", [(0, 1)], 1, 0), store2=vh.Store("deque", [(0, 1000)], 1, 0), extra=7)
        with self.assertRaises(vh.Halt):
            trapped.run(case)

    def test_out_of_range_address_is_refused(self):
        with self.assertRaises(vh.EvidenceError):
            self.image.exact_fde(0x10)


class TestExhaustiveShapes(Fixture):
    """Small exhaustive grids: every ring shape and every tree shape up to a bound, both stores, against the rule list."""

    def test_every_ring_shape_for_both_deques(self):
        count = 0
        for cap in range(1, 5):
            for head in range(cap):
                for length in range(cap + 1):
                    for zero_at in [None] + list(range(length)):
                        keys = [3 + 2 * i for i in range(length)]
                        if zero_at is not None:
                            keys[zero_at] = 0
                        entries = [(key, 100 * (index + 1)) for index, key in enumerate(keys)]
                        ring = vh.Store("deque", entries, cap, head)
                        case = make(store2=ring, store3=ring, extra=2000)
                        self.assertEqual(vh.run_case(self.harness, case), vh.spec(case), (cap, head, length, zero_at))
                        count += 1
        self.assertEqual(count, 105)

    def test_every_tree_shape_up_to_height_two(self):
        count = 0
        for height in range(3):
            for zero_level in [None] + list(range(height + 1)):
                for fan in (1, 2):
                    def node(level):
                        keys = [0] if level == zero_level and level == 0 else [5 + level]
                        if zero_level is not None and level == zero_level and level != 0:
                            keys = [0]
                        keys = keys + [30 + level + i for i in range(fan - 1)]
                        kids = None if level == 0 else [node(level - 1) for _ in range(len(keys) + 1)]
                        return vh.Tree(keys, [111 * (i + 1) for i in range(len(keys))], kids)
                    tree = vh.Store("tree", [], 0, 0, node(height), height)
                    case = make(store2=tree, store3=tree, extra=700)
                    self.assertEqual(vh.run_case(self.harness, case), vh.spec(case), (height, zero_level, fan))
                    count += 1
        self.assertEqual(count, 3 * 3 * 2 + (0))

    def test_map_arms(self):
        for size in range(0, 6):
            for present in (False, True):
                if present and size == 0:
                    continue
                for bad in (0, 1):
                    case = make(cell=None if not present else 321, m1=(size, bad))
                    got = vh.run_case(self.harness, case)
                    self.assertEqual(got, vh.spec(case), (size, present, bad))
                    probes = [row for row in got[1] if row[0] == "probe"]
                    self.assertEqual(len(probes), 1 if size > 1 else 0)
                    if present and bad and size > 1:
                        self.assertEqual(got[0], ("panic", "bounds"))

    def test_key_lanes_are_all_compared(self):
        """A decoy differing from the key in any one of the 20 bytes must not be taken for the key (16 byte compare plus 4 byte tail)."""
        for lane in range(20):
            harness = vh.Harness(self.image)
            harness.decoy_lane = staticmethod(lambda index, lane=lane: lane)
            for shape in ((1, 0), (2, 0), (3, 0)):
                case = make(cell=None, m1=shape)
                got = vh.run_case(harness, case)
                self.assertEqual(got, vh.spec(case), (lane, shape))
                self.assertEqual(got[0], ("ret", 555))


class TestWrongReadings(Fixture):
    """One crafted case per named wrong reading: the real bytes must agree with the rule list and disagree with the wrong reading."""

    @staticmethod
    def crafted():
        deque = lambda value, key=0: vh.Store("deque", [(key, value)], 1, 0)
        present = vh.Store("deque", [(0, 1)], 1, 0)
        deep = vh.Store("tree", [], 0, 0, vh.Tree([9], [1], [vh.Tree([0], [5000]), vh.Tree([20], [2])]), 1)
        deep_set = vh.Store("tree", [], 0, 0, vh.Tree([9], None, [vh.Tree([0]), vh.Tree([20])]), 1)
        big = (1 << 64) - 1
        return {
            "no_division": make(store2=deque(12350)),
            "divide_128": make(store2=deque(12350)),
            "ceil_division": make(store2=deque(12350)),
            "round_half_up": make(store2=deque(12350)),
            "u64_wraps": make(store2=deque(big), store3=present, extra=5),
            "i64_wraps": make(cell=vh.I64_MAX, store2=deque(100000)),
            "i64_saturates_min": make(cell=vh.I64_MAX, store2=deque(100000)),
            "base_unsigned": make(cell=(1 << 63) + 5, store2=deque(1000)),
            "extra_when_absent": make(store2=deque(1000), store3=vh.Store("deque", [(4, 1)], 1, 0), extra=3000),
            "extra_ignored": make(store2=deque(1000), store3=present, extra=3000),
            "extra_doubled": make(store2=deque(1000), store3=present, extra=3000),
            "extra_flag_bit1": make(store2=deque(1000), store3=present, extra=3000, extra_flag=2),
            "extra_flag_any": make(store2=deque(1000), store3=present, extra=3000, extra_flag=2),
            "present_inverted": make(store2=deque(1000), store3=present, extra=3000),
            "held_ignored": make(store2=deque(1000)),
            "cell_default_ignored": make(cell=None),
            "default_store_ignored": make(store2=vh.Store("none"), default2=deque(900), m2=(0, 0)),
            "deque_last_entry": make(store2=vh.Store("deque", [(0, 700), (5, 1)], 2, 0)),
            "entry_key_as_value": make(store2=deque(700)),
            "overflow_not_logged": make(cell=vh.I64_MAX, store2=deque(100000)),
            "init_skipped": make(flag1=3),
            "swap_lookup_order": make(store2=deque(1000), m2=(2, 0)),
            "tree_no_descend": make(store2=deep, store3=deep_set, extra=900),
        }

    def test_every_variant_has_a_crafted_case(self):
        self.assertEqual(sorted(self.crafted()), sorted(vh.VARIANTS))

    def test_real_bytes_follow_the_rule_list_on_each_crafted_case(self):
        for name, case in self.crafted().items():
            with self.subTest(name):
                got = vh.run_case(self.harness, case)
                self.assertEqual(got, vh.spec(case))

    def test_each_wrong_reading_disagrees_with_the_bytes(self):
        for name, case in self.crafted().items():
            with self.subTest(name):
                got = vh.run_case(self.harness, case)
                self.assertNotEqual(vh.spec(case, frozenset({name})), got)

    def test_two_wrong_readings_together_still_disagree(self):
        case = self.crafted()["extra_doubled"]
        got = vh.run_case(self.harness, case)
        self.assertNotEqual(vh.spec(case, frozenset({"extra_doubled", "no_division"})), got)

    def test_expected_numbers(self):
        self.assertEqual(vh.spec(self.crafted()["divide_128"])[0], ("ret", 100 + 123))
        self.assertEqual(vh.spec(self.crafted()["round_half_up"], frozenset({"round_half_up"}))[0], ("ret", 100 + 124))
        self.assertEqual(vh.spec(self.crafted()["i64_wraps"])[0], ("ret", vh.I64_MAX))
        self.assertEqual(vh.spec(self.crafted()["base_unsigned"])[0], ("ret", ((1 << 63) + 5 - (1 << 64)) + 10 & vh.MASK[8]))


class TestFacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = vh.load_image()

    def test_every_fact_holds_on_the_pinned_binary(self):
        rows = vh.fact_rows(self.image)
        self.assertGreaterEqual(len(rows), 30)
        self.assertEqual([row[0] for row in rows if not row[7]], [])

    def test_fact_sites_lie_inside_their_function(self):
        for name, entry, kind, value, count in vh.FACTS:
            start, end = self.image.exact_fde(entry)
            for row in vh.fact_rows(self.image):
                if row[0] == name:
                    for site in row[6].split():
                        self.assertTrue(start <= int(site, 16) < end, name)

    def test_edited_multiplier_breaks_the_fact(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x44A96AF)] ^= 1
        edited = vh.Image(bytes(blob))
        broken = [row[0] for row in vh.fact_rows(edited) if not row[7]]
        self.assertEqual(broken, ["division multiplier"])

    def test_edited_stride_breaks_the_fact(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x4716C8C)] ^= 1
        edited = vh.Image(bytes(blob))
        self.assertIn("first map entry stride", [row[0] for row in vh.fact_rows(edited) if not row[7]])

    def test_call_rows_name_the_relocation_targets(self):
        rows = vh.call_rows(self.image)
        notes = {row[3]: row[4] for row in rows if row[2] == "indirect"}
        self.assertIn("0x3beb980", notes["0x64e6d20"])
        self.assertIn("0x369a210", notes["0x64e6498"])
        self.assertEqual(len([row for row in rows if row[2] == "direct" and row[3] == "0x4717440"]), 2)


class TestRender(Fixture):
    def test_render_is_deterministic(self):
        result = vh.analyse(500, False)
        one, two = vh.render(result), vh.render(vh.analyse(500, False))
        self.assertEqual(one, two)
        self.assertIn("measure.json", one)
        self.assertNotIn("/" + "home" + "/", "".join(one.values()))


if __name__ == "__main__":
    unittest.main()
