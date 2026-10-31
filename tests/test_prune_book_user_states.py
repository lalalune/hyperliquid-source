"""Tests for the node #94 prune_book_empty_user_states packet: spec, real-byte runs and negative controls."""

import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prune_book_user_states", ROOT / "tools" / "prune_book_user_states.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def shared_setup(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)


def users(*numbers):
    return sorted(tool.user_id(number).hex() for number in numbers)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared_setup)

    def run_book(self, world, copy=0, closure="list"):
        return self.harness.run(tool.Case("t: x", "book", world, copy, closure))

    def run_step(self, world, copy=0):
        return self.harness.run(tool.Case("t: x", "step", world, copy))

    def test_rule_needs_both_maps_empty(self):
        self.assertEqual(tool.removed(tool.book([tool.entry(1)])), {tool.user_id(1)})
        self.assertEqual(tool.removed(tool.book([tool.entry(1, 0, 1, 0)])), set())
        self.assertEqual(tool.removed(tool.book([tool.entry(1, 0, 0, 1)])), set())

    def test_rule_ignores_r(self):
        self.assertEqual(tool.removed(tool.book([tool.entry(1, 5)])), {tool.user_id(1)})

    def test_rule_occupied_slot_keeps(self):
        self.assertEqual(tool.removed(tool.book([tool.entry(1)], [tool.slot(1)])), set())
        self.assertEqual(tool.removed(tool.book([tool.entry(1)], [tool.slot(1, tool.VACANT)])), {tool.user_id(1)})

    def test_rule_uses_the_low_dword(self):
        self.assertEqual(tool.removed(tool.book([tool.entry(1)], [tool.slot(1, 0x500000002)])), {tool.user_id(1)})

    def test_rule_table_on_real_bytes(self):
        for row in tool.rule_table():
            world = tool.book([tool.entry(1, row["r_length"], row["b_length"], row["u_length"])], [tool.slot(1, 0 if row["occupied_slot"] else tool.VACANT)])
            self.assertEqual(self.run_book(world)["books"][0]["length"], 0 if row["entry_removed"] else 1)

    def test_real_bytes_remove_with_r_data(self):
        for copy in (0, 1):
            for closure in ("list", "row"):
                found = self.run_book(tool.book([tool.entry(1, 3), tool.entry(2, 0, 1, 0), tool.entry(3, 0, 0, 2)]), copy, closure)
                self.assertEqual(found["books"][0]["users"], users(2, 3))
                self.assertEqual(found["books"][0]["length"], 2)
                self.assertEqual(found["leaked"], 0)
                self.assertTrue(found["intact"])

    def test_real_bytes_keep_when_a_slot_holds(self):
        found = self.run_book(tool.book([tool.entry(1), tool.entry(2)], [tool.slot(2), tool.slot(1, tool.VACANT)]))
        self.assertEqual(found["books"][0]["users"], users(2))

    def test_real_bytes_ignore_a_slot_past_the_length(self):
        found = self.run_book(tool.book([tool.entry(1), tool.entry(2)], [tool.slot(2, tool.VACANT), tool.slot(1)], 1))
        self.assertEqual(found["books"][0]["users"], [])

    def test_real_bytes_empty_every_tree_shape(self):
        for height, count in ((0, 5), (1, 23), (2, 30), (3, 61)):
            found = self.run_book(tool.book([tool.entry(number, 1) for number in range(1, count + 1)], height=height))
            self.assertEqual(found["books"][0], {"users": [], "length": 0})
            self.assertEqual(found["leaked"], 0)

    def test_step_gate_byte(self):
        one = tool.book([tool.entry(1)])
        for flag in (0, 2):
            found = self.run_step(tool.step_world(flag, [[one]], [one]))
            self.assertEqual(found["instants"], 0)
            self.assertEqual(found["books"][0]["length"], 1)

    def test_step_walks_rows_then_list(self):
        for copy in range(3):
            found = self.run_step(tool.step_world(1, [[tool.book([tool.entry(1)])], [tool.book([tool.entry(2)])]], [tool.book([tool.entry(3)])]), copy)
            self.assertTrue(found["done"])
            self.assertEqual([row["length"] for row in found["books"]], [0, 0, 0])

    def test_every_case_matches(self):
        for case in tool.all_cases():
            self.assertEqual(tool.compare_run(self.harness, case), "", case.label)

    def test_negative_control_flipped_filter_branch(self):
        machine = self.harness.machine
        va = 0x228D440
        self.assertEqual(tool.code(self.image, va, 2), b"\x75\xe9")
        machine.patches = tool.mutate_patch(self.image, va, 0, "branch")
        machine.cache.pop(va, None)
        try:
            self.assertNotEqual(tool.compare_run(self.harness, tool.Case("t: x", "book", tool.book([tool.entry(1, 0, 1, 0)]))), "")
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)

    def test_negative_control_wrong_spec(self):
        world = tool.book([tool.entry(1, 3)])
        self.assertEqual(self.run_book(world)["books"][0]["length"], 0)
        self.assertEqual(tool.spec_book(dict(world, entries=[tool.entry(1, 3, 1)]))["length"], 1)

    def test_bad_hash_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x2773721)

    def test_step_rows(self):
        rows = tool.step_rows(self.image)
        self.assertEqual([row["rows_field"] for row in rows], ["0x3368", "0x3368", "0x3de8"])
        self.assertEqual([row["period_field"] for row in rows], ["0x38c0", "0x38c0", "0x4340"])

    def test_filter_census(self):
        self.assertEqual([row["fde"] for row in tool.filter_sites(self.image)], ["0x228a440", "0x228d390", "0x47666a0", "0x476ece0"])

    def test_closure_copies_differ_only_in_displacements(self):
        self.assertEqual(len({row["masked_sha256"] for row in tool.copy_table(self.image)}), 1)

    def test_changed_copy_refused(self):
        saved = tool.COPIES
        tool.COPIES = (saved[0]._replace(list_closure=0x2577530),) + saved[1:]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.copy_table(self.image)
        finally:
            tool.COPIES = saved

    def test_anchor_mismatch_refused(self):
        saved = tool.CLOSURE_ANCHORS
        tool.CLOSURE_ANCHORS = (("wrong", 0x11, "00"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.anchors(self.image)
        finally:
            tool.CLOSURE_ANCHORS = saved

    def test_packet_files_match_a_static_render(self):
        folder = ROOT / "research" / "work-items" / "RE-006-prune-book-user-states-94"
        doc = json.loads((folder / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["step_name"], "prune_book_empty_user_states")
        self.assertEqual(doc["rule_table"], tool.rule_table())
        self.assertEqual(sum(row["entry_removed"] for row in doc["rule_table"]), 2)
        rows = (folder / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        for row in rows:
            parts = row.split("\t")
            if parts[3] != "killed":
                self.assertTrue(parts[5])


if __name__ == "__main__":
    unittest.main()
