import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import oi_fold_scale_115 as tool  # noqa: E402


def ring(items, cap=None, head=0):
    cap = len(items) if cap is None else cap
    return dict(kind="ring", items=dict(items), cap=cap, head=head)


def tree(items, height=0, root=True):
    return dict(kind="tree", items=dict(items), height=height, root=root)


def case(first, second, mult=0, cursor=0, end=1, init=0, array=(5,), pulls=0, start=0):
    return dict(mult=mult, cursor=cursor, end=end, init=init, first=first, second=second, array=list(array), pulls=pulls, start=start)


def set_up_class(cls):
    cls.image = tool.load_image()
    cls.constants = tool.constants_of(cls.image)
    cls.runner = tool.Runner(cls.image, constants=cls.constants)


class Bytes(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_digest_is_checked(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_function_bounds_come_from_unwind_records(self):
        for entry in tool.ENTRIES:
            start, end = self.image.exact_fde(entry)
            self.assertEqual(start, entry)
            self.assertGreater(end, start)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.FOLD + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x10)

    def test_known_sizes(self):
        sizes = {entry: self.image.exact_fde(entry)[1] - entry for entry in tool.ENTRIES}
        self.assertEqual(sizes[tool.FOLD], 861)
        self.assertEqual(sizes[tool.OWNER], 254)
        self.assertEqual(sizes[tool.SCALE_CLAMPED], 224)
        self.assertEqual(sizes[tool.SCALE_SIGNED], 196)
        self.assertEqual(sizes[tool.RING_SEARCH], 289)
        self.assertEqual(sizes[tool.COLLECT], 518)

    def test_constants(self):
        low, high, top = self.constants
        self.assertEqual((low, high), (-(2.0 ** 63), 2.0 ** 63))
        self.assertEqual(top, float(2 ** 63 - 1024))

    def test_got_slots_resolve_through_relocations(self):
        relative = tool.relative_slots(self.image)
        for slot in tool.SLOTS:
            self.assertIn(slot, relative)
        self.assertEqual(len(set(relative[slot] for slot in tool.SLOTS)), len(tool.SLOTS))


class FoldCases(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def check(self, value, expected):
        self.assertEqual(tool.fold_spec(value), expected)
        self.assertIsNone(tool.judge(self.runner.fold, value))

    def test_empty_range_returns_initial_sum(self):
        self.check(case(ring([]), ring([]), end=0, init=-7), ("ok", 1, -7, 0))

    def test_sum_of_products(self):
        first = tree({0: 3, 1: 4}, 0)
        second = ring({0: 10, 1: 100}.items(), cap=4, head=3)
        self.check(case(first, second, end=2, init=1), ("ok", 1, 1 + 30 + 400, 2))

    def test_missing_second_adds_zero(self):
        self.check(case(tree({0: 9}), ring([]), end=1, init=4), ("ok", 1, 4, 1))

    def test_array_fallback_for_missing_first(self):
        self.check(case(ring([]), tree({0: 6}), end=1, array=[8]), ("ok", 1, 48, 1))

    def test_array_bounds_panic(self):
        self.check(case(ring([]), ring([]), end=2, array=[1]), ("panic", "bounds", 2, 1, 1))

    def test_negative_first_stops_without_adding(self):
        self.check(case(tree({0: -1}), tree({0: 5}), end=3, init=9), ("ok", 0, 9, 1))

    def test_product_overflow_stops(self):
        self.check(case(tree({0: 4}), tree({0: 1 << 62}), end=3), ("ok", 0, 0, 1))

    def test_sum_overflow_keeps_wrapped_sum(self):
        self.check(case(tree({0: 1}), tree({0: 1}), end=3, init=(1 << 63) - 1), ("ok", 0, -(1 << 63), 1))

    def test_multiplier_overflow_panics(self):
        self.check(case(ring([]), ring([]), mult=1844674407370956), ("panic", "mul", 1))

    def test_key_addition_overflow_panics(self):
        self.check(case(ring([]), ring([]), mult=1844674407370955, cursor=tool.U64 - 1, end=tool.U64), ("panic", "add", tool.U64))

    def test_deep_tree_and_wrapped_ring(self):
        items = {10000 * 2 + index: index + 1 for index in range(30)}
        first = tree(items, 2)
        second = ring({key: 2 for key in items}.items(), cap=40, head=25)
        total = sum(2 * (index + 1) for index in range(10))
        self.check(case(first, second, mult=2, end=10), ("ok", 1, total, 10))

    def test_generated_cases_agree(self):
        for number in range(250):
            value = tool.make_fold_case(11, number)
            self.assertIsNone(tool.judge(self.runner.fold, value), number)


class OwnerCases(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_tree_is_consumed_pulls_plus_one_times(self):
        value = case(tree({0: 2, 3: 4}, 1), ring([]), end=1, array=[6], pulls=2)
        want, events = tool.spec_owner(value)
        self.assertEqual(want, ("ok", 1, 0))
        self.assertEqual(len(events), 3)
        self.assertIsNone(tool.judge(self.runner.owner, value))

    def test_ring_buffer_is_freed_with_sixteen_byte_entries(self):
        value = case(ring([(0, 1)], cap=5), ring([]), end=1)
        self.assertEqual(tool.spec_owner(value)[1], [("free", tool.RING_FIRST, 80, 0)])
        self.assertIsNone(tool.judge(self.runner.owner, value))

    def test_zero_capacity_ring_is_left_alone(self):
        value = case(ring([], cap=0), ring([]), end=0)
        self.assertEqual(tool.spec_owner(value)[1], [])
        self.assertIsNone(tool.judge(self.runner.owner, value))

    def test_empty_tree_has_no_iterator_front(self):
        value = case(tree({}, 0, root=False), ring([]), end=0, pulls=1)
        self.assertEqual(tool.spec_owner(value)[1], [("next", 0, 0, 0)] * 2)
        self.assertIsNone(tool.judge(self.runner.owner, value))

    def test_panic_skips_the_consumer(self):
        value = case(tree({}, 0), ring([]), end=2, array=[1])
        want, events = tool.spec_owner(value)
        self.assertEqual((want[0], events), ("panic", []))
        self.assertIsNone(tool.judge(self.runner.owner, value))

    def test_generated_cases_agree(self):
        for number in range(200):
            value = tool.make_fold_case(12, number, owner=True)
            self.assertIsNone(tool.judge(self.runner.owner, value), number)


class CollectCases(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def check(self, value, expected):
        self.assertEqual(tool.collect_spec(value), expected)
        self.assertIsNone(tool.judge(self.runner.collect, value))

    def test_missing_keys_collect_zero(self):
        second = tree({1: 7, 3: -2}, 0)
        self.check(case(ring([]), second, cursor=0, end=4, start=2), ("ok", [0, 7, 0, -2], 6))

    def test_empty_range_writes_nothing(self):
        self.check(case(ring([]), ring([(0, 9)]), cursor=3, end=3, start=1), ("ok", [], 1))

    def test_ring_with_rotated_head(self):
        second = ring([(10000 * 3 + index, index + 10) for index in range(4)], cap=6, head=5)
        self.check(case(ring([]), second, mult=3, end=4), ("ok", [10, 11, 12, 13], 4))

    def test_multiplier_overflow_panics_before_the_first_write(self):
        self.check(case(ring([]), ring([]), mult=1844674407370956, end=2), ("panic", "mul", []))

    def test_add_overflow_panics_after_earlier_writes(self):
        value = case(ring([]), ring([]), mult=1844674407370955, cursor=1614, end=1620)
        self.assertEqual(tool.collect_spec(value)[:2], ("panic", "add"))
        self.assertGreater(len(tool.collect_spec(value)[2]), 0)
        self.assertIsNone(tool.judge(self.runner.collect, value))

    def test_generated_cases_agree(self):
        for number in range(250):
            value = tool.make_fold_case(16, number)
            self.assertIsNone(tool.judge(self.runner.collect, value), number)

    def test_patched_collector_is_detected(self):
        found = [row for row in tool.mutants(self.image) if row[0] == tool.COLLECT and row[2] == "jcc"]
        self.assertGreaterEqual(len(found), 10)
        runner = tool.Runner(self.image, found[3][3], self.constants)
        cases = [tool.make_fold_case(17, number) for number in range(120)]
        self.assertTrue(any(tool.judge(runner.collect, value) for value in cases))


class RingAndScale(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_ring_search_positions(self):
        base = case(ring([(10, 0), (20, 1), (30, 2)], cap=5, head=4), ring([]))
        for key, want in ((10, (0, 0)), (20, (0, 1)), (30, (0, 2)), (5, (1, 0)), (25, (1, 2)), (99, (1, 3))):
            value = dict(base, key=key)
            self.assertEqual(tool.spec_ring(value), want)
            self.assertIsNone(tool.judge(self.runner.ring, value), key)

    def test_empty_ring_search(self):
        value = dict(case(ring([], cap=0), ring([])), key=7)
        self.assertEqual(tool.spec_ring(value), (1, 0))
        self.assertIsNone(tool.judge(self.runner.ring, value))

    def test_generated_ring_cases_agree(self):
        for number in range(250):
            self.assertIsNone(tool.judge(self.runner.ring, tool.make_ring_case(13, number)), number)

    def test_scale_hand_values(self):
        one = tool.to_bits(1.0)
        self.assertEqual(tool.scale_spec(5, 1.0, self.constants, True), 5)
        self.assertEqual(tool.scale_spec(tool.U64, 0.0, self.constants, True), tool.U64)
        self.assertEqual(tool.scale_spec(10 ** 17, 10.0, self.constants, True), 0x147AE147AE147AE)
        self.assertEqual(tool.scale_spec(3, float("nan"), self.constants, False), 0)
        self.assertEqual(tool.scale_spec(1 << 62, -4.0, self.constants, False), ("panic", "negate"))
        self.assertEqual(tool.scale_spec(5, -1.0, self.constants, True), 0)
        self.assertEqual(tool.scale_spec(5, -1.0, self.constants, False), (-5) & tool.U64)
        self.assertEqual(self.runner.harness.run_scale(tool.SCALE_CLAMPED, 5, one), 5)
        self.assertEqual(self.runner.harness.run_scale(tool.SCALE_SIGNED, 5, tool.to_bits(-1.0)), (-5) & tool.U64)

    def test_generated_scale_cases_agree(self):
        for entry, variant in ((tool.SCALE_CLAMPED, 14), (tool.SCALE_SIGNED, 15)):
            for number in range(250):
                pair = tool.make_scale_case(variant, number)
                self.assertIsNone(tool.judge(lambda item: self.runner.scale(entry, item), pair), (entry, number))


class NegativeControls(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def sample(self):
        return [tool.make_fold_case(21, number) for number in range(80)]

    def test_flipped_loop_exit_is_detected(self):
        found = [row for row in tool.mutants(self.image) if row[0] == tool.FOLD and row[2] == "jcc"]
        self.assertGreaterEqual(len(found), 15)
        runner = tool.Runner(self.image, found[0][3], self.constants)
        self.assertTrue(any(tool.judge(runner.fold, value) for value in self.sample()))

    def test_wrong_specification_is_detected(self):
        genuine = tool.fold_spec

        def wrong(value):
            return genuine(dict(value, mult=value["mult"] + 1))

        original = tool.fold_spec
        tool.fold_spec = wrong
        try:
            failures = [value for value in self.sample() if tool.judge(self.runner.fold, value)]
        finally:
            tool.fold_spec = original
        self.assertTrue(failures)

    def test_wrong_stride_in_specification_is_detected(self):
        original = tool.KEY_STRIDE
        tool.KEY_STRIDE = 10001
        try:
            failures = [value for value in self.sample() if tool.judge(self.runner.fold, value)]
        finally:
            tool.KEY_STRIDE = original
        self.assertTrue(failures)

    def test_corrupted_scale_constant_is_detected(self):
        wrong = (self.constants[0], self.constants[1], 1.0)
        runner = tool.Runner(self.image, constants=wrong)
        failures = [pair for pair in (tool.make_scale_case(31, number) for number in range(300))
                    if tool.judge(lambda item: runner.scale(tool.SCALE_SIGNED, item), pair)]
        self.assertTrue(failures)

    def test_corrupted_ring_byte_is_detected(self):
        found = [row for row in tool.mutants(self.image) if row[0] == tool.RING_SEARCH and row[2] == "jcc"]
        self.assertTrue(found)
        runner = tool.Runner(self.image, found[0][3], self.constants)
        cases = [tool.make_ring_case(22, number) for number in range(120)]
        self.assertTrue(any(tool.judge(runner.ring, value) for value in cases))

    def test_out_of_range_inputs_are_rejected(self):
        self.assertFalse(tool.tree_fits(12, 0))
        self.assertIsNone(tool.tree_children(1, 2))
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)
        with self.assertRaises(tool.Halt):
            self.runner.harness.machine.memory.bytes_at(0x10, 8)

    def test_unmapped_write_halts(self):
        with self.assertRaises(tool.Halt):
            self.runner.harness.machine.memory.write(0x10, 8, 1)


class Evidence(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_mutant_inventory_is_fixed_and_every_survivor_is_explained(self):
        found = tool.mutants(self.image)
        self.assertEqual(len(found), 220)
        self.assertTrue(all(row[1] >= row[0] for row in found))
        known = {key for key in tool.EQUIVALENT}
        present = {(row[0], row[1], row[2]) for row in found}
        self.assertTrue(known <= present)

    def test_regeneration_is_byte_identical_and_consistent(self):
        outputs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as folder:
                out = pathlib.Path(folder) / "evidence"
                summary, unexplained = tool.build(out, tool.FOLD_CASES, tool.OWNER_CASES, tool.RING_CASES, tool.SCALE_CASES, tool.COLLECT_CASES, tool.SAMPLE)
                self.assertEqual(unexplained, [])
                outputs.append({path.name: path.read_bytes() for path in sorted(out.iterdir())})
        self.assertEqual(outputs[0], outputs[1])
        measure = json.loads(outputs[0]["measure.json"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"] + measure["equivalent"])
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        rows = outputs[0]["equivalent-mutants.tsv"].decode().splitlines()
        self.assertEqual(len(rows) - 1, measure["equivalent"])
        for name, data in outputs[0].items():
            text = data.decode()
            for forbidden in ("/" + word + "/" for word in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")):
                self.assertNotIn(forbidden, text, name)


if __name__ == "__main__":
    unittest.main()
