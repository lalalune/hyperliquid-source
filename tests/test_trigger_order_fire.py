"""Tests for the node #94 trigger order packet: spec, real-byte runs and negative controls."""

import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("trigger_order_fire", ROOT / "tools" / "trigger_order_fire.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def shared_setup(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared_setup)

    def select(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "select", world, copy))

    def fire(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "fire", world, copy))

    def wrap(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "wrap", world, copy))

    def test_rule_stop_and_take_profit(self):
        self.assertTrue(tool.fires({"trigger": 99, "side": 0, "kind": 1}, 100))
        self.assertFalse(tool.fires({"trigger": 101, "side": 0, "kind": 1}, 100))
        self.assertTrue(tool.fires({"trigger": 101, "side": 1, "kind": 1}, 100))
        self.assertTrue(tool.fires({"trigger": 101, "side": 0, "kind": 0}, 100))
        self.assertTrue(tool.fires({"trigger": 99, "side": 1, "kind": 0}, 100))
        self.assertTrue(tool.fires({"trigger": 100, "side": 0, "kind": 0}, 100))

    def test_rule_price(self):
        self.assertEqual(tool.to_price(1000000, 0), 1100000)
        self.assertEqual(tool.to_price(1000000, 1), 900000)
        self.assertEqual(tool.to_price(tool.MAX64, 0), tool.MAX64)
        self.assertEqual(tool.on_tick(21, 10, 0), 20)
        self.assertEqual(tool.on_tick(20, 10, 1), 30)

    def test_rule_reference_prefers_a_fresh_mark(self):
        world = tool.base(marks=[tool.fresh_mark(1), tool.fresh_mark(1), tool.fresh_mark(55, 20)])
        self.assertEqual(tool.reference_price(world, 7), 55)
        world = tool.base(marks=[tool.fresh_mark(1), tool.fresh_mark(1), tool.fresh_mark(55, 21)])
        self.assertEqual(tool.reference_price(world, 7), 7)
        self.assertEqual(tool.reference_price(tool.base(marks=[]), 7), 7)

    def test_real_bytes_order_by_size_not_by_key(self):
        world = tool.base(users=[tool.holder(5, [tool.order(1, trigger=1000000, size=30), tool.order(2, trigger=1000000, size=10), tool.order(3, trigger=1000000, size=20)])])
        for copy in (0, 1):
            self.assertEqual([oid for _, oid in self.select(world, copy)["rows"]], [2, 3, 1])

    def test_real_bytes_reduce_only_takes_the_position(self):
        world = tool.base(users=[tool.holder(5, [tool.order(1, side=1, trigger=1000000, reduce=1, size=500), tool.order(2, side=1, trigger=1000000, size=70)])], positions={5: {"rows": {tool.ASSET: 60}}})
        self.assertEqual([oid for _, oid in self.select(world)["rows"]], [1, 2])

    def test_real_bytes_wrong_side_position_sorts_first(self):
        world = tool.base(users=[tool.holder(5, [tool.order(1, side=0, trigger=1000000, reduce=1, size=500), tool.order(2, side=0, trigger=1000000, size=7)])], positions={5: {"rows": {tool.ASSET: 60}}})
        self.assertEqual([oid for _, oid in self.select(world)["rows"]], [1, 2])

    def test_real_bytes_no_top_gives_none(self):
        for top in ((0, 9), (9, 0)):
            self.assertEqual(self.select(tool.base(top=top)), {"none": True})

    def test_real_bytes_fresh_mark_is_the_reference(self):
        found = self.select(tool.base(marks=[tool.fresh_mark(1), tool.fresh_mark(1), tool.fresh_mark(5, 20)]))
        self.assertEqual((found["reference"], found["mid"]), (5, 1000001))
        found = self.select(tool.base(marks=[tool.fresh_mark(1), tool.fresh_mark(1), tool.fresh_mark(5, 21)]))
        self.assertEqual((found["reference"], found["mid"]), (1000001, 1000001))

    def test_real_bytes_every_firing_copy_sends_the_same(self):
        world = tool.fire_world(tool.order(9, side=1), top_pair=(950000, 980000))
        rows = [self.fire(world, 0), self.fire(world, 1)]
        self.assertEqual(rows[0], rows[1])
        self.assertEqual(rows[0]["word"], 0x25)
        third = self.wrap(world, 2)
        self.assertEqual(third["log"][:-1], rows[0]["log"])
        self.assertEqual(rows[0]["log"][1][5], 950000)

    def test_real_bytes_rejected_order_stays(self):
        found = self.fire(tool.fire_world(tool.order(9), gate=0))
        self.assertEqual(found["word"], tool.WORD_REJECTED)
        self.assertEqual(found["text"], "limit")
        self.assertFalse([row for row in found["log"] if row[0] in ("remove", "insert", "event")])

    def test_real_bytes_rejected_text_names_the_capped_price(self):
        found = self.fire(tool.fire_world(tool.order(9), gate=0, top_pair=(500, 600)))
        self.assertEqual((found["text"], found["px"]), ("opp", 600))

    def test_real_bytes_insert_error_removes_and_writes_two_rows(self):
        found = self.fire(tool.fire_world(tool.order(9), insert={"error": tool.NONE_WORD + 3}, relation=[{"tag": 1, "parent": 3}, {"tag": 0, "parent": 4}]))
        rows = [row for row in found["log"] if row[0] == "event"]
        self.assertEqual([row[-1] for row in rows], [3, 5])
        self.assertIn(["remove", tool.user_id(5).hex(), 9], found["log"])
        self.assertEqual(found["relations"], [0, 0])

    def test_real_bytes_market_byte_picks_the_price(self):
        price = {market: [row for row in self.fire(tool.fire_world(tool.order(9, market=market, limit=5)))["log"] if row[0] == "insert"][0][6] for market in (0, 1)}
        self.assertEqual(price, {0: 5, 1: 1100000})

    def test_real_bytes_count_stops_at_zero(self):
        self.assertEqual(self.fire(tool.fire_world(tool.order(9), count=0))["count"], 0)
        self.assertEqual(self.fire(tool.fire_world(tool.order(9), count=2))["count"], 1)

    def test_real_bytes_tracker_needs_no_resting_order(self):
        self.assertFalse([row for row in self.fire(tool.fire_world(tool.order(9), resting=[9]))["log"] if row[0] == "tracker"])
        self.assertTrue([row for row in self.fire(tool.fire_world(tool.order(9), resting=[8]))["log"] if row[0] == "tracker"])

    def test_real_bytes_wrapper_restores_depth_and_flushes(self):
        found = self.wrap(tool.fire_world(tool.order(9), depth=9))
        self.assertEqual(found["depth"], 9)
        self.assertEqual(found["log"][-1], ["flush", 1, 1])

    def test_real_bytes_fifth_argument_is_unread(self):
        # The direct runs pass the poison word in r8, and the wrapper passes it behind its fourth pointer.
        self.assertEqual(self.wrap(tool.fire_world(tool.order(9)), 2)["word"], 0x25)
        self.assertEqual(self.fire(tool.fire_world(tool.order(9)))["word"], 0x25)

    def test_every_case_matches(self):
        for case in tool.all_cases():
            self.assertEqual(tool.compare_run(self.harness, case), "", case.label)

    def test_negative_control_flipped_side_branch(self):
        machine = self.harness.machine
        va = 0x42FF210
        self.assertEqual(tool.code(self.image, va, 2), b"\x75\x44")
        machine.patches = tool.mutate_patch(self.image, va, 0, "branch")
        machine.cache.pop(va, None)
        try:
            self.assertNotEqual(tool.compare_run(self.harness, tool.Case("t: x", "fire", tool.fire_world(tool.order(9)))), "")
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)

    def test_negative_control_wrong_spec(self):
        world = tool.fire_world(tool.order(9))
        found = self.fire(world)
        self.assertEqual(found, tool.run_spec(tool.Case("t: x", "fire", world)))
        self.assertNotEqual(found["log"], tool.firing(tool.fire_world(tool.order(9, trigger=1000001)))["log"])

    def test_bad_hash_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x42FF011)

    def test_copies_differ_only_in_state_fields(self):
        rows = tool.copy_table(self.image)
        self.assertEqual([len(row["state_rows"]) for row in rows], [11, 2, 2])
        self.assertEqual(rows[0]["callees_that_differ"], [["0x4311140", "0x4314da0"]])

    def test_changed_constant_refused(self):
        saved = tool.CONSTANTS
        tool.CONSTANTS = ((0x20A8B8, 1.2),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(self.image)
        finally:
            tool.CONSTANTS = saved

    def test_changed_status_table_refused(self):
        saved = tool.STATUS_BY_INDEX
        tool.STATUS_BY_INDEX = bytes(8)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(self.image)
        finally:
            tool.STATUS_BY_INDEX = saved

    def test_host_sites(self):
        rows, slots = tool.host_rows(self.image)
        hosts = {(row[0], row[3]) for row in rows}
        self.assertIn((0x4321930, 0x4CF37F0), hosts)
        self.assertIn((0x42FF010, 0x4CF37F0), hosts)
        self.assertIn((0x27371F0, 0x27078A0), hosts)
        self.assertEqual(sum(1 for row in rows if row[0] == 0x4D44470), 3)
        self.assertEqual(sum(1 for row in rows if row[0] == 0x27371F0), 3)
        self.assertEqual(sum(len(row["sites_in_firing_copies"]) for row in slots if row["target"] == "0x3714e70"), 3)

    def test_host_site_outside_refused(self):
        saved = tool.HOST_SITES
        tool.HOST_SITES = ((0x4CF94A0, 0x42FF010, "fire"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.host_rows(self.image)
        finally:
            tool.HOST_SITES = saved

    def test_packet_files_match_a_static_render(self):
        folder = ROOT / "research" / "work-items" / "RE-006-trigger-order-fire-94"
        doc = json.loads((folder / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["fire_table"], tool.fire_table())
        self.assertEqual(doc["price_table"], tool.price_table())
        rows = (folder / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        for row in rows:
            parts = row.split("\t")
            if parts[3] != "killed":
                self.assertTrue(parts[5])


if __name__ == "__main__":
    unittest.main()
