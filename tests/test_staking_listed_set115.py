import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_listed_set115 as tool  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "staking-listed-set-btree-115"


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.cases = tool.all_cases()
        cls.runner = tool.SetRun(cls.image)

    def of_kind(self, *kinds):
        return [(index, case) for index, case in enumerate(self.cases) if case[0] in kinds]

    def check(self, case, flaws=()):
        got, want = tool.execute(self.runner, case, flaws)
        self.assertEqual(got, want, case)
        return got

    def check_every(self, kinds, step):
        rows = self.of_kind(*kinds)
        self.assertGreater(len(rows), 0)
        for position in range(0, len(rows), step):
            self.check(rows[position][1])
        return len(rows)


class Inventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = tool.all_cases()

    def test_case_count_and_groups(self):
        self.assertGreaterEqual(len(self.cases), 10000)
        kinds = {case[0] for case in self.cases}
        self.assertEqual(kinds, {"insert", "insert_twin", "grow", "fault", "drop", "builder_a", "builder_b", "builder_fault", "builder_real"})

    def test_case_list_is_deterministic(self):
        self.assertEqual(hashlib.sha256(repr(self.cases).encode()).hexdigest(), hashlib.sha256(repr(tool.all_cases()).encode()).hexdigest())

    def test_every_tree_shape_is_grown_to_height_two(self):
        tall = tool.model_tree(200, "shuffled", 202)
        self.assertEqual(tall.height, 2)
        self.assertEqual(len(tall.in_order()), 200)

    def test_digest_gate(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_scope_addresses_are_function_starts(self):
        image = tool.load_image()
        for address in tool.SCOPE:
            image.exact_fde(address)
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(tool.INSERT + 1)


class RuleList(unittest.TestCase):
    """The B-tree rule list on its own, with no bytes."""

    def test_split_points(self):
        tree = tool.MTree()
        want = [4, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 6]
        got = [tree.split_point(index)[0] for index in range(12)]
        self.assertEqual(got, want)
        sides = [tree.split_point(index)[1] for index in range(12)]
        self.assertEqual(sides[:6], [("left", index) for index in range(6)])
        self.assertEqual(sides[6], ("right", 0))
        self.assertEqual(sides[7:], [("right", index) for index in range(5)])

    def test_every_gap_keeps_sorted_order_and_links(self):
        for count in (0, 1, 11, 12, 23, 24, 60):
            for order in tool.ORDERS:
                tree = tool.model_tree(count, order, 5)
                keys = tree.in_order()
                self.assertEqual(keys, sorted(keys))
                self.assertEqual(len(keys), count)
                self.assertEqual(tree.length, count)
                for node in tree.nodes:
                    self.assertLessEqual(node.len, tool.CAP)
                    if node.internal:
                        for index in range(node.len + 1):
                            child = tree.nodes[node.edges[index]]
                            self.assertEqual((child.parent, child.pidx), (node.id, index))

    def test_first_split_lands_at_twelve_keys(self):
        tree = tool.model_tree(11, "asc", 0)
        self.assertEqual((tree.height, len(tree.nodes)), (0, 1))
        tree.insert(tool.key_of(99))
        self.assertEqual((tree.height, len(tree.nodes)), (1, 3))
        self.assertEqual(tree.allocs, [tool.LEAF, tool.INTERNAL])

    def test_duplicate_key_is_not_inserted(self):
        tree = tool.model_tree(5, "asc", 0)
        self.assertIsNone(tree.insert(tool.key_of(4)))
        self.assertEqual(tree.length, 5)

    def test_second_level_split_allocates_in_order(self):
        tree = tool.MTree()
        for value in range(1, 400):
            before = tree.height
            tree.allocs = []
            tree.insert(tool.key_of(value))
            if before == 1 and tree.height == 2:
                self.assertEqual(tree.allocs, [tool.LEAF, tool.INTERNAL, tool.INTERNAL])
                return
        self.fail("the tree never reached height two")

    def test_post_order_frees_children_before_parent(self):
        tree = tool.model_tree(60, "shuffled", 4)
        order = tree.post_order()
        self.assertEqual(order[-1], tree.root)
        position = {nid: index for index, nid in enumerate(order)}
        for node in tree.nodes:
            if node.internal:
                for index in range(node.len + 1):
                    self.assertLess(position[node.edges[index]], position[node.id])

    def test_flawed_rule_lists_differ_from_the_good_one(self):
        def grown(flaws):
            tree = tool.MTree(flaws)
            for value in tool.grow_values("shuffled", 4, 80):
                tree.insert(tool.key_of(value))
            return tree.dump(), tuple(tree.allocs)

        good = grown(())
        for flaw, kinds in tool.MODEL_FLAWS:
            if "insert" not in kinds and "grow" not in kinds:
                continue
            try:
                bad = grown((flaw,))
            except (TypeError, IndexError):
                continue
            self.assertNotEqual(good, bad, flaw)


class VacantInsert(Fixture):
    def test_insert_sample(self):
        self.check_every(("insert",), 5)

    def test_twin_sample(self):
        self.check_every(("insert_twin",), 5)

    def test_grow_sample(self):
        self.check_every(("grow",), 3)

    def test_the_split_arms_are_all_reached(self):
        seen = set()
        for index, case in self.of_kind("insert"):
            if case[1]["count"] in (11, 12, 23, 24, 143, 144, 145):
                self.runner.machine.seen = set()
                self.check(case)
                seen |= self.runner.machine.seen
        low, high = self.image.exact_fde(tool.INSERT)
        reached = [va for va in seen if low <= va < high]
        self.assertGreater(len(reached), 280)

    def test_every_split_position_of_a_full_leaf(self):
        for gap in range(0, 12):
            case = ("insert", dict(count=11, order="asc", seed=0, gap=gap, va=tool.VACANT))
            got = self.check(case)
            self.assertEqual(got[0], "ok")
            self.assertEqual(len(got[2][3]), 3)

    def test_empty_tree_allocates_one_leaf(self):
        got = self.check(("insert", dict(count=0, order="asc", seed=0, gap=0, va=tool.VACANT)))
        self.assertEqual(got[3], (tool.LEAF,))
        self.assertEqual(got[1], (0, 0, 0, True))

    def test_height_word_of_the_handle_is_ignored(self):
        key = tool.key_of(7)
        dumps = []
        for height in (0, 5, 0xFFFF):
            tree = tool.model_tree(11, "asc", 0)
            state, node, idx = tree.search(key)
            self.runner.run_vacant(tool.VACANT, tree, node.id, idx, key, height)
            dumps.append(self.runner.dump())
        self.assertEqual(dumps[0], dumps[1])
        self.assertEqual(dumps[0], dumps[2])

    def test_twin_bodies_differ_only_in_displacements(self):
        same, diffs, total = tool.masked_twin(self.image)
        self.assertTrue(same)
        self.assertEqual((diffs, total), (6, 67))

    def test_malloc_failure_reports_align_and_size(self):
        faults = self.of_kind("fault")
        self.assertGreater(len(faults), 100)
        for position in range(0, len(faults), 4):
            got = self.check(faults[position][1])
            self.assertEqual(got[0], "alloc_error")
            self.assertEqual(got[2][0][0], 8)
            self.assertIn(got[2][0][1], (tool.LEAF, tool.INTERNAL))


class Builders(Fixture):
    def test_real_builders_use_the_binary_keys(self):
        for case in (("builder_real", dict(which="a")), ("builder_real", dict(which="b"))):
            got = self.check(case)
            self.assertEqual(got[0], "ok")
        a = self.check(("builder_real", dict(which="a")))
        b = self.check(("builder_real", dict(which="b")))
        self.assertEqual(a[1][2], 5)
        self.assertEqual(b[1][2], 2)
        self.assertEqual(a[1][3:], (1, 1))

    def test_builder_a_sample(self):
        self.check_every(("builder_a",), 41)

    def test_builder_b_all(self):
        self.check_every(("builder_b",), 1)

    def test_builder_faults(self):
        self.check_every(("builder_fault",), 1)

    def test_equal_keys_are_inserted_once(self):
        got = self.check(("builder_a", dict(keys=(2, 2, 2, 2, 2), mode="sign")))
        self.assertEqual(got[1][2], 1)

    def test_memcmp_return_magnitude_does_not_matter(self):
        for keys in ((0, 6, 5, 4, 3), (3, 2, 1, 0, 6)):
            sign = self.check(("builder_a", dict(keys=keys, mode="sign")))
            diff = self.check(("builder_a", dict(keys=keys, mode="diff")))
            self.assertEqual(sign[2], diff[2])

    def test_rodata_keys_equal_the_inserted_keys(self):
        for group_set, pool in ((tool.IMM_A, tool.KEY_POOL_A), (tool.IMM_B, tool.KEY_POOL_B)):
            for index, group in enumerate(group_set):
                if not index:
                    continue
                inserted = self.runner.original_key(group)
                at = self.image.offset(pool[index - 1])
                self.assertEqual(bytes(self.image.blob[at:at + tool.KEY]), inserted)

    def test_lazy_rows_name_the_builders(self):
        relative = self.image.relative()
        self.assertEqual(relative[tool.STATIC_A], tool.BUILD_A)
        self.assertEqual(relative[tool.STATIC_B], tool.BUILD_B)

    def test_patched_first_key_moves_the_leaf_slot(self):
        low = tool.ALPHA[0]
        high = tool.ALPHA[6]
        first = self.check(("builder_a", dict(keys=(0, 1, 2, 3, 4), mode="sign")))
        second = self.check(("builder_a", dict(keys=(6, 1, 2, 3, 4), mode="sign")))
        self.assertNotEqual(first[2], second[2])
        self.assertNotEqual(low, high)


class Drop(Fixture):
    def test_drop_sample(self):
        self.check_every(("drop",), 3)

    def test_leaf_only_tree_frees_one_node(self):
        got = self.check(("drop", dict(count=5, order="asc", seed=0)))
        self.assertEqual(got[1], (("free", 0, tool.LEAF, 0),))

    def test_internal_nodes_use_the_larger_size(self):
        got = self.check(("drop", dict(count=60, order="asc", seed=0)))
        sizes = [entry[2] for entry in got[1]]
        self.assertIn(tool.INTERNAL, sizes)
        self.assertEqual(got[1][-1][2], tool.INTERNAL)

    def test_length_word_one_short_still_frees_every_node(self):
        for index, case in self.of_kind("drop"):
            if case[1].get("delta") == -1:
                self.check(case)

    def test_length_word_too_large_panics(self):
        tree = tool.model_tree(40, "shuffled", 3)
        tree.length += 1
        with self.assertRaises(tool.Panicked):
            self.runner.run_drop(tree)

    def test_empty_set_frees_nothing(self):
        got = self.check(("drop", dict(count=0, order="asc", seed=0)))
        self.assertEqual(got[1], ())


class Controls(Fixture):
    def test_every_rule_list_flaw_is_found(self):
        tool.STATE.update(cases=self.cases, flaw_run=self.runner)
        for job in tool.MODEL_FLAWS:
            flaw, found, where = tool.flaw_task(job)
            self.assertTrue(found, flaw)

    def test_condition_flips_in_the_split_are_caught(self):
        low, high = self.image.exact_fde(tool.INSERT)
        rows = [row for row in tool.decode_range(self.image, low, high) if row.op == "jcc"][:12]
        edits = tool.edits_for(self.image, rows)
        self.assertGreaterEqual(len(edits), 10)
        picked = [case for _, case in self.of_kind("insert") if case[1]["count"] in (11, 12, 24, 144)][:160]
        killed = 0
        for va, kind, patch in edits:
            run = tool.SetRun(self.image, patch)
            run.machine.step_limit = 90000
            for case in picked:
                try:
                    got, want = tool.execute(run, case)
                except tool.FAILURES:
                    killed += 1
                    break
                if got != want:
                    killed += 1
                    break
        self.assertGreaterEqual(killed, 8)

    def test_range_controls_are_all_detected(self):
        for name, detected in tool.range_controls(self.image):
            self.assertTrue(detected, name)

    def test_geometry_damage_is_caught(self):
        tool.STATE.update(image=self.image, cases=self.cases, geometry_cases=[i for i, c in enumerate(self.cases) if c[0] == "insert" and c[1]["count"] in (11, 12, 24, 144)][:60])
        for field in tool.GEOMETRY_FIELDS:
            name, detected = tool.geometry_task(field)
            self.assertTrue(detected, name)

    def test_geometry_globals_are_restored(self):
        before = (tool.F_PARENT, tool.F_KEYS, tool.F_PIDX, tool.F_LEN, tool.F_EDGES)
        tool.STATE.update(image=self.image, cases=self.cases, geometry_cases=[0])
        tool.geometry_task("F_LEN")
        self.assertEqual(before, (tool.F_PARENT, tool.F_KEYS, tool.F_PIDX, tool.F_LEN, tool.F_EDGES))

    def test_a_damaged_key_byte_in_the_fixture_is_seen(self):
        tree = tool.model_tree(30, "asc", 0)
        key = tool.key_of(31)
        state, node, idx = tree.search(key)
        tree2 = tool.model_tree(30, "asc", 0)
        self.runner.run_vacant(tool.VACANT, tree2, node.id, idx, key)
        good = self.runner.dump()
        tree3 = tool.model_tree(30, "asc", 0)
        tree3.nodes[node.id].keys[0] = bytes([0xFF]) * tool.KEY
        self.runner.run_vacant(tool.VACANT, tree3, node.id, idx, key)
        self.assertNotEqual(self.runner.dump(), good)


class Committed(unittest.TestCase):
    def test_generated_files_match_the_committed_packet(self):
        self.assertTrue(EVIDENCE.exists())
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temp:
            self.assertEqual(tool.main(["--out", temp]), 0)
            names = sorted(path.name for path in pathlib.Path(temp).iterdir())
            for name in names:
                self.assertEqual((pathlib.Path(temp) / name).read_bytes(), (EVIDENCE / name).read_bytes(), name)
            manifest = (EVIDENCE / "MANIFEST.sha256").read_text().splitlines()
            listed = {line.split("  ")[1]: line.split("  ")[0] for line in manifest}
            for name in names + ["README.md"]:
                self.assertEqual(listed[name], hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), name)
            measure = json.loads((EVIDENCE / "measure.json").read_text())
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])
            self.assertGreaterEqual(measure["cases"], 10000)


if __name__ == "__main__":
    unittest.main()
