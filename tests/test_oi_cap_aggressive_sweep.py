"""Tests for the node #94 cancel_aggressive_orders_at_oi_cap packet: spec, real-byte runs and negative controls."""

import importlib.util
import json
import math
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("oi_cap_aggressive_sweep", ROOT / "tools" / "oi_cap_aggressive_sweep.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def shared_setup(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared_setup)

    def sweep(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "sweep", world, copy))

    def host(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "host", world, copy))

    def test_rule_side_zero(self):
        self.assertTrue(tool.aggressive(1020000, 1000000, 0))
        self.assertFalse(tool.aggressive(1000000, 1000000, 0))
        self.assertFalse(tool.aggressive(980000, 1000000, 0))

    def test_rule_side_nonzero(self):
        self.assertTrue(tool.aggressive(980000, 1000000, 1))
        self.assertFalse(tool.aggressive(1020000, 1000000, 1))

    def test_exact_percent_rounds_over(self):
        self.assertGreater(tool.over_reference(101, 100, 0), 0.01)
        self.assertGreater(tool.over_reference(99, 100, 1), 0.01)

    def test_zero_reference(self):
        self.assertEqual(tool.over_reference(5, 0, 0), math.inf)
        self.assertTrue(math.isnan(tool.over_reference(0, 0, 0)))
        self.assertFalse(tool.aggressive(0, 0, 0))
        self.assertFalse(tool.aggressive(5, 0, 1))

    def test_real_sweep_cancels_with_reason_8(self):
        for copy in range(3):
            found = self.sweep(tool.sweep_world([(1020000, 0), (1000000, 0), (980000, 1)]), copy)
            self.assertEqual([event[2] for event in found["events"]], [501, 507])
            self.assertEqual({event[5] for event in found["events"]}, {8})
            self.assertEqual(found["leaked"], 0)

    def test_real_sweep_nan_keeps_order(self):
        self.assertEqual(self.sweep(tool.sweep_world([(0, 0)], 0))["events"], [])

    def test_real_sweep_exact_percent(self):
        self.assertEqual(len(self.sweep(tool.sweep_world([(101, 0)], 100))["events"]), 1)

    def test_cancels_wait_for_the_scan(self):
        found = self.sweep(tool.sweep_world([(1020000, 0), (980000, 1), (1020000, 0)], clobber=True))
        self.assertEqual([event[2] for event in found["events"]], [501, 504, 507])

    def test_second_tree_key_needs_the_hash(self):
        world = tool.sweep_world([(1020000, 0)], users=[{"user": tool.user_id(1), "first": [], "second": [999]}])
        self.assertEqual(self.sweep(world)["events"], [])

    def test_duplicate_key_cancels_once(self):
        world = tool.sweep_world([(1020000, 0)], users=[{"user": tool.user_id(1), "first": [0], "second": [501]}])
        self.assertEqual(len(self.sweep(world)["events"]), 1)

    def test_more_than_twenty_orders_reach_the_sort(self):
        world = tool.sweep_world([(1020000, 0)] * 25)
        self.assertEqual([event[2] for event in self.sweep(world)["events"]], [501 + 3 * index for index in range(25)])

    def test_host_gate_byte(self):
        found = self.host(tool.host_world(flag=0))
        self.assertEqual(found["events"], [])
        self.assertFalse(found["done"])

    def test_host_price_turns_over_at_1800_seconds(self):
        fresh = self.host(tool.host_world(now=(tool.DATE, 5400, 500)))
        stale = self.host(tool.host_world(now=(tool.DATE, 5400, 501)))
        self.assertEqual([event[2] for event in fresh["events"] if event[0] == "sweep"], [9000])
        self.assertEqual([event[2] for event in stale["events"] if event[0] == "sweep"], [7000])

    def test_host_mode_3_uses_first_word(self):
        found = self.host(tool.host_world(dexes=[tool.dex(mode=3)]))
        self.assertEqual([event[2] for event in found["events"] if event[0] == "sweep"], [7000])

    def test_host_second_copy_reads_other_list(self):
        found = self.host(tool.host_world(), 1)
        self.assertEqual(found["events"][0], ("predicate", tool.DEXES, 0))

    def test_predicate_mode_3_is_set_membership(self):
        run = lambda world: self.harness.run(tool.Case("t: x", "pred", world))["out"]
        self.assertTrue(run(tool.caps_world(mode=3, set=(5,))))
        self.assertFalse(run(tool.caps_world(mode=3, set=(6,))))

    def test_predicate_edge_on_real_bytes(self):
        run = lambda world: self.harness.run(tool.Case("t: x", "pred", world))
        over = run(tool.caps_world(sizes={5: 9}, prices=[1, 2, 3, 4, 5, 101, 7, 8]))
        equal = run(tool.caps_world(sizes={5: 9}, prices=[1, 2, 3, 4, 5, 100, 7, 8]))
        self.assertTrue(over["out"])
        self.assertEqual(over["events"], [])
        self.assertFalse(equal["out"])
        self.assertEqual(len(equal["events"]), 1)

    def test_every_case_matches(self):
        for case in tool.all_cases():
            self.assertEqual(tool.compare_run(self.harness, case), "", case.label)

    def test_negative_control_flipped_ratio_branch(self):
        machine = self.harness.machine
        va = 0x26E4E43
        machine.patches = tool.mutate_patch(self.image, va, 1, "branch")
        machine.cache.pop(va, None)
        try:
            self.assertNotEqual(tool.compare_run(self.harness, tool.Case("t: x", "sweep", tool.sweep_world([(1000000, 0)]), 0)), "")
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)

    def test_negative_control_wrong_spec(self):
        world = tool.sweep_world([(1020000, 0)])
        found = self.sweep(world)
        wrong = tool.spec_sweep(dict(world, ref=2000000))
        self.assertNotEqual(found["events"], wrong["events"])

    def test_bad_hash_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x26E48C1)

    def test_status_name(self):
        self.assertEqual(tool.status_names(self.image)[8], "openInterestCapCanceled")

    def test_step_rows(self):
        rows = tool.step_rows(self.image)
        self.assertEqual([row["period_field"] for row in rows], ["0x38b0", "0x4330", "0x38b0"])

    def test_anchor_mismatch_refused(self):
        saved = tool.SWEEP_ANCHORS
        tool.SWEEP_ANCHORS = (("wrong", 0x3C, "00"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.anchors(self.image)
        finally:
            tool.SWEEP_ANCHORS = saved

    def test_packet_files_match_a_static_render(self):
        folder = ROOT / "research" / "work-items" / "RE-006-oi-cap-aggressive-cancel-94"
        doc = json.loads((folder / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["reason"]["name"], "openInterestCapCanceled")
        rows = (folder / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        for row in rows:
            parts = row.split("\t")
            if parts[3] != "killed":
                self.assertTrue(parts[5])


if __name__ == "__main__":
    unittest.main()
