"""Tests for tools/oi_cap_predicate_115.py: the open-interest at-cap test of node #115 run on its real bytes."""

import itertools
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import oi_cap_predicate_115 as tool  # noqa: E402


def base_world(kind="pred", **fields):
    """A dex with three assets, no caps, no sizes, all prices 7."""
    world = {
        "kind": kind, "stream": 99, "dex": 1, "count": 3, "row_len": 3, "prices": tool.PriceTable((index, 7) for index in range(3)),
        "mode_set": False, "set": [], "set_height": 0, "sizes": {}, "sizes_kind": "tree", "sizes_option": 0,
        "caps": {}, "caps_kind": "tree", "caps_option": 0, "total": 1000, "asset": 10001, "filler": 10001,
    }
    world.update(fields)
    return world


class OiCapPredicateTests(unittest.TestCase):
    def setUp(self):
        self.image = tool.load_image()
        self.harness = tool.Harness(self.image)

    def check(self, world):
        outcome = tool.run_case(self.harness, world)
        self.assertEqual(outcome, tool.spec_for(world))
        return outcome

    def test_digest_mismatch_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.verify_digest(b"not the node binary")

    def test_threshold_is_floor_of_ninety_percent(self):
        self.assertEqual(tool.threshold(100), 90)
        self.assertEqual(tool.threshold(11), 9)
        self.assertEqual(tool.threshold(0), 0)
        self.assertLess(tool.threshold(tool.MAX_I64), tool.MAX_I64)

    def test_cap_line_in_both_map_shapes(self):
        for shape in ("tree", "flat"):
            for product, want in ((90, 0), (91, 1)):
                world = base_world(count=0, caps={10001: 100}, caps_kind=shape, sizes={10001: 1}, sizes_kind=shape, prices=tool.PriceTable({0: 7, 1: product, 2: 7}))
                self.assertEqual(self.check(world), ("ret", want))

    def test_absent_size_counts_as_zero(self):
        world = base_world(count=0, caps={10001: 100}, prices=tool.PriceTable({0: 7, 1: 10 ** 12, 2: 7}))
        self.assertEqual(self.check(world), ("ret", 0))

    def test_negative_price_and_product_overflow_are_at_cap(self):
        prices = tool.PriceTable({0: 7, 1: 1 << 63, 2: 7})
        self.assertEqual(self.check(base_world(count=0, caps={10001: 100}, prices=prices)), ("ret", 1))
        prices = tool.PriceTable({0: 7, 1: 1 << 62, 2: 7})
        self.assertEqual(self.check(base_world(count=0, caps={10001: 100}, sizes={10001: 4}, prices=prices)), ("ret", 1))

    def test_negative_cap_panics(self):
        outcome = self.check(base_world(count=0, caps={10001: 1 << 63}))
        self.assertEqual(outcome, ("panic", ("unwrap", tool.LOC_PRED_UNWRAP, tool.UNWRAP_LEN)))

    def test_row_bound_panic(self):
        outcome = self.check(base_world(count=0, row_len=1, caps={10001: 5}))
        self.assertEqual(outcome, ("panic", ("bounds", 1, 1, tool.LOC_PRED_BOUNDS)))

    def test_total_line_uses_the_sum_fold(self):
        sizes = {10000: 3, 10002: 4}
        for total, want in ((54, 1), (55, 0), (56, 0)):
            world = base_world(sizes=sizes, total=total)
            self.assertEqual(self.check(world), ("ret", want))

    def test_set_mode_reads_only_the_set(self):
        world = base_world(mode_set=True, set=[10001, 10005, 20000], set_height=1, caps={10001: 1})
        self.assertEqual(self.check(world), ("ret", 1))
        self.assertEqual(self.check(dict(world, asset=10002)), ("ret", 0))
        self.assertEqual(self.check(dict(world, set=[])), ("ret", 0))

    def test_fold_stops_on_overflow_and_keeps_wrapped_sum(self):
        world = base_world("fold", pos=0, length=2, init=tool.MAX_I64 - 5, sizes={10000: 1, 10001: 1}, cache=(0, 0))
        outcome = self.check(world)
        self.assertEqual(outcome[:2], ("fold", 0))
        self.assertEqual(outcome[2], (tool.MAX_I64 - 5 + 7) & tool.MASK[8])

    def test_fold_cache_replaces_the_row_read(self):
        world = base_world("fold", pos=0, length=2, init=0, sizes={10001: 2}, row_len=0, prices=tool.PriceTable(), cache=(9, 10001))
        outcome = self.check(dict(world, sizes={10001: 2}, row_len=2))
        self.assertEqual(outcome, ("fold", 1, 18, 2))

    def test_fold_arithmetic_panics(self):
        world = base_world("fold", dex=(1 << 64) // 10000 + 1, pos=0, length=1, init=0, cache=(0, 0))
        self.assertEqual(self.check(world)[0], "panic")

    def test_edge_and_far_families_agree(self):
        for index, world in enumerate(itertools.islice(tool.case_stream(), tool.CASE_PREDICATE + tool.CASE_FOLD, tool.CASE_PREDICATE + tool.CASE_FOLD + 400)):
            self.assertEqual(tool.run_case(self.harness, world), tool.spec_for(world), index)

    def test_wrong_specifications_are_caught(self):
        begin = tool.CASE_PREDICATE + tool.CASE_FOLD + tool.CASE_EDGE - 400
        stream = list(itertools.islice(tool.case_stream(), begin, begin + 1000))
        ran = [tool.run_case(self.harness, world) for world in stream]
        for bug in ("cap_factor_one", "round_cap", "cap_at_least", "total_at_least", "fold_local_1000", "bound_short"):
            self.assertTrue(tool.detects_bug(bug, lambda: zip(stream, ran)), bug)

    def test_corrupted_code_byte_is_caught(self):
        world = base_world(count=0, caps={10001: 100}, sizes={10001: 1}, prices=tool.PriceTable({0: 7, 1: 91, 2: 7}))
        self.assertEqual(self.check(world), ("ret", 1))
        rows = tool.decode_range(self.image, *self.image.exact_fde(tool.PREDICATE))
        jumps = [row for row in rows if row.op == "jcc"]
        killed = 0
        for row in jumps[:12]:
            self.harness.machine.patches = tool.mutate_patch(self.image, row.va, row.size - (2 if row.size == 2 else 5), "branch")
            self.harness.machine.cache.clear()
            if tool.run_case(self.harness, world) != tool.spec_for(world):
                killed += 1
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()
        self.assertGreater(killed, 3)

    def test_input_controls_all_detected(self):
        rows = tool.input_controls(self.image)
        self.assertGreaterEqual(len(rows), 7)
        self.assertTrue(all(ok for _, ok in rows), rows)

    def test_slot_and_function_bounds(self):
        relative = {slot: addend for slot, kind, addend, _ in self.image.relocations() if kind == 8}
        self.assertEqual(relative[tool.PREDICATE_SLOT], tool.PREDICATE)
        self.assertEqual(self.image.exact_fde(tool.PREDICATE), (0x44883F0, 0x448881F))
        self.assertEqual(self.image.exact_fde(tool.FOLD), (0x37C1480, 0x37C16E8))
        self.assertEqual(self.image.exact_fde(tool.SEARCH), (0x45547E0, 0x4554901))
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.PREDICATE + 1)

    def test_full_analysis_counts(self):
        state = tool.analyse(self.image)
        self.assertEqual(state["mismatches"], 0)
        self.assertGreaterEqual(state["cases"], 10000)
        self.assertGreaterEqual(len(state["controls"]), 30)
        self.assertTrue(all(ok for _, ok in state["controls"]))
        files = tool.render(self.image, state)
        self.assertIn("measure.json", files)


if __name__ == "__main__":
    unittest.main()
