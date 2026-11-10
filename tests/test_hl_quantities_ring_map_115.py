import random
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hl_quantities_ring_map_115 as tool  # noqa: E402


def logical(cap, rows, head, length):
    return [rows[tool.phys(cap, head, i)] for i in range(length)]


def sample(kind, seed):
    return tool.make_case(random.Random(seed), seed, kind)


def reference_search(keys, key):
    """Plain walk over a logical key list: (0, index) for the first equal key a binary search lands on is checked separately; here the keys are distinct."""
    for index, value in enumerate(keys):
        if value == key:
            return 0, index
    return 1, sum(1 for value in keys if value < key)


def distinct_sorted_case(seed):
    rnd = random.Random(seed)
    cap = rnd.randint(1, 20)
    length = rnd.randint(0, cap)
    head = rnd.randrange(cap)
    keys = sorted(rnd.sample(range(0, 200), length))
    rows = [(rnd.getrandbits(64),) * 3 for _ in range(cap)]
    for i, key in enumerate(keys):
        rows[tool.phys(cap, head, i)] = (key, rnd.getrandbits(64), rnd.getrandbits(64))
    return cap, rows, head, length, keys, rnd


class SearchTests(unittest.TestCase):
    def test_matches_reference_on_sorted_distinct_keys(self):
        for seed in range(400):
            cap, rows, head, length, keys, rnd = distinct_sorted_case(seed)
            for key in keys + [rnd.randint(0, 220) for _ in range(6)] + [0, tool.M64]:
                got = tool.search_model(cap, [r[0] for r in rows], head, length, key)
                self.assertEqual(got, reference_search(keys, key), (seed, key))

    def test_empty_handle_reports_absent_at_zero(self):
        self.assertEqual(tool.search_model(4, [1, 2, 3, 4], 2, 0, 9), (1, 0))

    def test_unsigned_order(self):
        keys = [1, 1 << 63, tool.M64]
        self.assertEqual(tool.search_model(3, keys, 0, 3, tool.M64), (0, 2))
        self.assertEqual(tool.search_model(3, keys, 0, 3, (1 << 63) - 1), (1, 1))

    def test_equal_first_of_second_slice_reports_first_slice_length(self):
        keys = [10, 20, 30, 40]
        # head 2: logical order is slots 2, 3, 0, 1 -> keys 30, 40, 10, 20 (unsorted on purpose); the second slice starts with key 10
        self.assertEqual(tool.search_model(4, keys, 2, 4, 10), (0, 2))

    def test_wrong_reference_is_detected(self):
        # negative control: a search that forgets the second slice disagrees with the model on a wrapped handle
        cap, keys, head, length = 6, [50, 60, 10, 20, 30, 40], 2, 6

        def flat_only(key):
            first = cap - head
            return tool.bsearch(keys, head, first, key)

        self.assertNotEqual(flat_only(50), tool.search_model(cap, keys, head, length, 50))


class CopyTests(unittest.TestCase):
    def test_overlapping_shift_up_and_down(self):
        rows = list(range(8))
        tool.wrap_copy_model(rows, 8, 2, 3, 4)
        self.assertEqual(rows, [0, 1, 2, 2, 3, 4, 5, 7])
        rows = list(range(8))
        tool.wrap_copy_model(rows, 8, 3, 2, 4)
        self.assertEqual(rows, [0, 1, 3, 4, 5, 6, 6, 7])

    def test_wraps_around_the_ring(self):
        rows = list(range(5))
        tool.wrap_copy_model(rows, 5, 3, 4, 3)
        self.assertEqual(rows, [4, 0, 2, 3, 3])

    def test_noop_cases(self):
        rows = list(range(5))
        tool.wrap_copy_model(rows, 5, 1, 1, 3)
        tool.wrap_copy_model(rows, 5, 1, 2, 0)
        self.assertEqual(rows, list(range(5)))


class RemoveTests(unittest.TestCase):
    def test_remove_keeps_logical_order(self):
        for seed in range(500):
            cap, rows, head, length, keys, rnd = distinct_sorted_case(seed)
            before = logical(cap, rows, head, length)
            key = rnd.choice(keys) if keys and seed % 3 else rnd.randint(0, 220)
            option, rows2, head2, length2 = tool.remove_model(cap, rows, head, length, key)
            after = logical(cap, rows2, head2, length2)
            expected = [r for r in before if r[0] != key]
            self.assertEqual(after, expected, seed)
            hit = [r for r in before if r[0] == key]
            self.assertEqual(option, (hit[0][1], hit[0][2]) if hit else None, seed)
            self.assertEqual(length2, len(expected))

    def test_head_moves_only_when_the_front_is_shorter(self):
        cap, rows, head, length, keys, rnd = distinct_sorted_case(7)
        keys = [r[0] for r in rows]
        for index in range(length):
            key = rows[tool.phys(cap, head, index)][0]
            _, _, head2, _ = tool.remove_model(cap, rows, head, length, key)
            tail = length - 1 - index
            self.assertEqual(head2, head if tail < index else tool.phys(cap, head, 1), index)


class UpsertTests(unittest.TestCase):
    def run_model(self, seed):
        case = sample("upsert", seed)
        mem = tool.Memory(None)
        tool.build(mem, case)
        tool.upsert_model(mem, case)
        return case, mem

    def test_growth_contract_and_logical_content(self):
        grown = 0
        for seed in range(600):
            case, mem = self.run_model(seed)
            cap, head = mem.read(tool.DQ, 8), mem.read(tool.DQ + 16, 8)
            length, buf = mem.read(tool.DQ + 24, 8), mem.read(tool.DQ + 8, 8)
            rows = [tuple(int.from_bytes(mem.bytes_at(buf + tool.ROW * i + 8 * w, 8), "little") for w in range(3)) for i in range(cap)]
            before = logical(case["cap"], case["slots"], case["head"], case["length"]) if case["cap"] else []
            after = logical(cap, rows, head, length)
            found, index = tool.search_model(case["cap"], [r[0] for r in case["slots"]], case["head"], case["length"], case["key"])
            if found == 0:
                expected = list(before)
                expected[index] = (before[index][0],) + case["val"]
                self.assertEqual(length, case["length"])
            else:
                expected = list(before)
                expected.insert(index, (case["key"],) + case["val"])
                self.assertEqual(length, case["length"] + 1)
            self.assertEqual(after, expected, seed)
            if cap != case["cap"]:
                grown += 1
                self.assertEqual(cap, max(2 * case["cap"], 4))
                self.assertEqual(buf, tool.BUF2)
        self.assertGreater(grown, 20)

    def test_replace_returns_previous_value_pair(self):
        for seed in range(300):
            case, mem = self.run_model(seed)
            found, index = tool.search_model(case["cap"], [r[0] for r in case["slots"]], case["head"], case["length"], case["key"])
            tag = mem.read(tool.OUT, 4)
            self.assertEqual(tag, 1 if found == 0 else 0)
            if found == 0:
                slot = tool.phys(case["cap"], case["head"], index)
                self.assertEqual(mem.bytes_at(tool.OUT + 4, 16), tool.row_bytes(case["slots"][slot][1:]))


def walk_tree(mem, node, height):
    """In-order keys of a tree laid out by build_tree (inner nodes hold values too)."""
    count = mem.read(node + 0x112, 2)
    keys = [mem.read(node + 0xB8 + 8 * i, 8) for i in range(count)]
    if height == 0:
        return keys
    out = []
    for i in range(count + 1):
        out += walk_tree(mem, mem.read(node + 0x118 + 8 * i, 8), height - 1)
        if i < count:
            out.append(keys[i])
    return out


class TreeTests(unittest.TestCase):
    def test_builder_produces_ordered_trees_within_node_capacity(self):
        for seed in range(300):
            rnd = random.Random(seed)
            keys = sorted(rnd.sample(range(500), rnd.choice([0, 1, 5, 11, 12, 20, 33, 45])))
            leaf = rnd.choice([3, 4, 5, 7, 10, 11])
            items = [(k, k * 3, k * 5) for k in keys]
            mem = tool.Memory(None)
            mem.reset(tool.USED)
            root, height = tool.build_tree(mem, tool.REGION[0], items, leaf)
            if not keys:
                self.assertEqual((root, height), (0, 0))
                continue
            self.assertEqual(walk_tree(mem, root, height), keys, seed)
            self.assertLessEqual(mem.read(root + 0x112, 2), 11)

    def test_trailing_separator_is_moved_into_its_own_leaf(self):
        items = [(k, 0, 0) for k in range(36)]
        mem = tool.Memory(None)
        mem.reset(tool.USED)
        root, height = tool.build_tree(mem, tool.REGION[0], items, 5)
        self.assertEqual(walk_tree(mem, root, height), list(range(36)))
        self.assertEqual(mem.read(root + 0x112, 2), 6)

    def test_triple_model_matches_plain_lookup(self):
        for seed in range(200):
            case = tool.make_triple(random.Random(seed), seed)
            mem = tool.Memory(None)
            tool.build(mem, case)
            tool.triple_model(mem, case)
            for n, spec in enumerate(case["maps"]):
                tag = mem.read(tool.OUT + tool.TRIPLE_OUT[n], 4)
                if spec["mode"] == "tree":
                    self.assertEqual(tag, int(any(i[0] == case["key"] for i in spec["items"])), (seed, n))


class RangeTests(unittest.TestCase):
    def model(self, **fields):
        case = tool.make_range(random.Random(3), 1)
        case.update(fields)
        mem = tool.Memory(None)
        tool.build(mem, case)
        log = []
        return tool.range_model(mem, case, tool.RangeWorld(case["fail"]), log), mem, log

    def test_empty_and_reversed_ranges_allocate_nothing(self):
        for start, end in ((5, 5), (9, 2)):
            crash, mem, log = self.model(start=start, end=end, asset=0, fail=False)
            self.assertIsNone(crash)
            self.assertEqual(log, [])
            self.assertEqual((mem.read(tool.VECOUT, 8), mem.read(tool.VECOUT + 8, 8), mem.read(tool.VECOUT + 16, 8)), (0, 4, 0))

    def test_allocation_size_and_failure(self):
        crash, mem, log = self.model(start=2, end=5, asset=0, fail=False)
        self.assertIsNone(crash)
        self.assertEqual(log, [("alloc", 3 * 0x3C)])
        crash, _, _ = self.model(start=2, end=5, asset=0, fail=True)
        self.assertEqual(crash, ("alloc_error", (4, 3 * 0x3C)))

    def test_multiplication_and_addition_overflow(self):
        crash, _, _ = self.model(start=0, end=2, asset=tool.M64, fail=False)
        self.assertEqual(crash[0], "panic_mul")
        crash, _, _ = self.model(start=tool.M64 - 5, end=tool.M64, asset=1, fail=False)
        self.assertEqual(crash[0], "panic_add")

    def test_count_above_limit_is_a_capacity_error_before_allocation(self):
        crash, _, log = self.model(start=0, end=tool.M64, asset=0, fail=False)
        self.assertEqual(crash[0], "alloc_error")
        self.assertEqual(crash[1][0], 0)
        self.assertEqual(log, [])


class CollectTests(unittest.TestCase):
    def run_model(self, quantities, tag=tool.TAG_EMPTY, fail_at=0):
        records = [(i, i, i, q) for i, q in enumerate(quantities)]
        case = dict(records=records, tag=tag, fail_at=fail_at)
        mem = tool.Memory(None)
        mem.reset(tool.USED)
        tool.build_collect(mem, case)
        log = []
        crash = tool.collect_model(mem, case, tool.BumpWorld(fail_at), log)
        vec = tuple(mem.read(tool.VOUT2 + 8 * i, 8) for i in range(3))
        return crash, vec, log, mem

    def test_stops_at_first_record_at_the_limit(self):
        crash, vec, log, mem = self.run_model([1, 2, 0x2711, 3])
        self.assertIsNone(crash)
        self.assertEqual((vec[0], vec[2]), (4, 2))
        self.assertEqual(mem.read(tool.ERRSLOT, 2), tool.TAG_LIMIT)
        self.assertEqual(mem.read(tool.ERRSLOT + 8, 8), tool.SLICE + 0x20 * 2)
        self.assertEqual(log, [("alloc", 0x20)])

    def test_just_below_the_limit_is_collected(self):
        crash, vec, _, mem = self.run_model([0x2710] * 3)
        self.assertEqual(vec[2], 3)
        self.assertEqual(mem.read(tool.ERRSLOT, 2), tool.TAG_EMPTY)

    def test_capacity_doubles_from_four(self):
        _, vec, log, _ = self.run_model([5] * 9)
        self.assertEqual((vec[0], vec[2]), (16, 9))
        self.assertEqual([row for row in log if row[0] == "realloc"], [("realloc", 64), ("realloc", 128)])

    def test_empty_slice_and_first_record_over_limit_allocate_nothing(self):
        for quantities in ([], [0x3000, 1]):
            crash, vec, log, _ = self.run_model(quantities)
            self.assertIsNone(crash)
            self.assertEqual((vec[0], vec[1], vec[2]), (0, 8, 0))
            self.assertEqual(log, [])

    def test_drop_logged_only_for_a_filled_error_slot(self):
        _, _, log, _ = self.run_model([0x3000], tag=tool.TAG_EMPTY)
        self.assertEqual(log, [])
        _, _, log, _ = self.run_model([0x3000], tag=0x10)
        self.assertEqual(log, [("drop", tool.ERRSLOT)])

    def test_allocation_failure_reports_alignment_and_size(self):
        crash, _, _, _ = self.run_model([1, 2], fail_at=1)
        self.assertEqual(crash, ("alloc_error", (8, 0x20)))
        crash, _, _, _ = self.run_model([5] * 6, fail_at=2)
        self.assertEqual(crash, ("alloc_error", (8, 64)))


def tree_entries(node):
    """In-order (key, value) list of a model tree."""
    out = []
    for i, key in enumerate(node.keys):
        if node.kids:
            out += tree_entries(node.kids[i])
        out.append((key, node.vals[i]))
    if node.kids:
        out += tree_entries(node.kids[-1])
    return out


def check_shape(test, node, height, root=True):
    """B-tree invariants: fill, back links, uniform depth."""
    test.assertLessEqual(len(node.keys), tool.CAPACITY)
    if not root:
        test.assertGreaterEqual(len(node.keys), tool.MIN_LEN)
    if height == 0:
        test.assertEqual(node.kids, [])
        return
    test.assertEqual(len(node.kids), len(node.keys) + 1)
    for i, kid in enumerate(node.kids):
        test.assertIs(kid.parent, node)
        test.assertEqual(kid.pidx, i)
        check_shape(test, kid, height - 1, False)


def model_run(case):
    log, events = [], []
    root = tool.instantiate(case["spec"], [0])
    result = tool.tremove_model(root, case["height"], case["total"], case["key"], log, events)
    return root, result, log, events


class TreeRemoveTests(unittest.TestCase):
    def cases(self, count=300, seed=7):
        rnd = random.Random(seed)
        for n in range(1, count):
            case = tool.make_tremove(rnd, n)
            if case["spec"] is not None:
                yield case

    def test_removal_matches_an_ordered_map(self):
        for case in self.cases():
            before = tree_entries(tool.instantiate(case["spec"], [0]))
            _, (option, root, height, length), _, _ = model_run(case)
            after = tree_entries(root)
            want = dict(before)
            value = want.pop(case["key"], None)
            self.assertEqual(sorted(want.items()), after)
            self.assertEqual(option, value)
            self.assertEqual(length, len(after))
            if not case.get("underfull"):
                check_shape(self, root, height)

    def test_every_rebalance_kind_occurs(self):
        seen = set()
        for case in self.cases(900, 3):
            seen.update(model_run(case)[3])
        self.assertTrue({"leaf", "inner", "merge-left", "merge-right", "steal-left", "steal-right", "pop-root"} <= seen)

    def test_merge_frees_the_right_node_with_its_size(self):
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        spec = ([20], [(20, 20)], [leaf([1, 2, 3, 4, 5]), leaf([30, 31, 32, 33, 34])])
        case = dict(spec=spec, height=1, key=3, total=11)
        root, (option, new_root, height, length), log, events = model_run(case)
        self.assertEqual(option, (3, 3))
        self.assertEqual(events, ["leaf", "merge-right", "pop-root"])
        self.assertEqual(height, 0)
        self.assertEqual(length, 10)
        self.assertEqual(log[0][0], "dealloc")
        self.assertEqual(log[0][2], tool.LEAF_SIZE)
        self.assertEqual(log[1][2], tool.INNER_SIZE)
        self.assertEqual(new_root.keys, [1, 2, 4, 5, 20, 30, 31, 32, 33, 34])

    def test_steal_moves_one_entry_through_the_separator(self):
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        spec = ([20], [(20, 20)], [leaf([1, 2, 3, 4, 5, 6, 7]), leaf([30, 31, 32, 33, 34])])
        case = dict(spec=spec, height=1, key=33, total=13)
        root, (option, new_root, height, length), log, events = model_run(case)
        self.assertEqual(events, ["leaf", "steal-left"])
        self.assertEqual(new_root.keys, [7])
        self.assertEqual(new_root.kids[1].keys, [20, 30, 31, 32, 34])
        self.assertEqual(log, [])

    def test_inner_key_is_replaced_by_its_predecessor(self):
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        spec = ([20], [(20, 20)], [leaf([1, 2, 3, 4, 5, 6]), leaf([30, 31, 32, 33, 34, 35])])
        case = dict(spec=spec, height=1, key=20, total=13)
        root, (option, new_root, height, length), log, events = model_run(case)
        self.assertEqual(option, (20, 20))
        self.assertEqual(new_root.keys, [6])
        self.assertEqual(new_root.kids[0].keys, [1, 2, 3, 4, 5])

    def test_missing_key_changes_nothing(self):
        for case in self.cases(120):
            if case["key"] in {k for k, _ in tree_entries(tool.instantiate(case["spec"], [0]))}:
                continue
            root, (option, new_root, height, length), log, events = model_run(case)
            self.assertIsNone(option)
            self.assertEqual((events, log, length), ([], [], case["total"]))

    def test_empty_map_is_a_miss(self):
        self.assertEqual(tool.tremove_model(None, 0, 0, 5, [], []), (None, None, 0, 0))

    def test_view_comparison_sees_a_wrong_merge_condition(self):
        # negative control: a merge threshold of 10 instead of 11 leaves a different shape for sibling length 6
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        spec = ([20], [(20, 20)], [leaf([1, 2, 3, 4, 5]), leaf([30, 31, 32, 33, 34, 35])])
        case = dict(spec=spec, height=1, key=3, total=12)
        good = model_run(case)[3]
        saved = tool.CAPACITY
        tool.CAPACITY = 10
        try:
            bad = model_run(case)[3]
        finally:
            tool.CAPACITY = saved
        self.assertNotEqual(good, bad)

    def test_view_of_model_matches_node_layout(self):
        case = next(self.cases())
        root = tool.instantiate(case["spec"], [0])
        view = tool.model_view(root, case["height"])
        self.assertEqual(view[0], tool.TBASE)
        self.assertEqual(view[1], 0)
        self.assertEqual(len(view[3]), len(root.keys))


class TreeShapeTests(unittest.TestCase):
    def reference(self, case):
        root = tool.instantiate(case["spec"], [0])
        before = dict(tree_entries(root))
        _, (option, new_root, height, length), _, events = model_run(case)
        want = dict(before)
        value = want.pop(case["key"], None)
        self.assertEqual(sorted(want.items()), tree_entries(new_root))
        self.assertEqual(option, value)
        return events, height

    def test_ancestor_generator_reaches_ancestor_repairs(self):
        rnd = random.Random(2)
        long_chains = 0
        for _ in range(120):
            case = tool.make_ancestor(rnd)
            events, _ = self.reference(case)
            long_chains += len(events) > 2
        self.assertGreater(long_chains, 10)

    def test_deep_generator_matches_reference_and_keeps_height(self):
        rnd = random.Random(4)
        for index in range(60):
            case = tool.make_deep(rnd, index)
            events, height = self.reference(case)
            self.assertIn(height, (case["height"], case["height"] - 1))

    def test_position_of_inner_removal_is_the_leftmost_leaf_after_the_slot(self):
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        spec = ([20], [(20, 20)], [leaf([1, 2, 3, 4, 5, 6]), leaf([30, 31, 32, 33, 34, 35])])
        root = tool.instantiate(spec, [0])
        node, level, idx = tool.locate(root, 1, 20)
        key, old, pos, emptied = tool.remove_at(node, level, idx, [], [])
        self.assertEqual((key, old, emptied), (20, (20, (20, 20)), False))
        self.assertEqual((pos[0], pos[1], pos[2]), (root.kids[1], 0, 0))

    def test_underfull_steal_count_is_five_minus_length(self):
        leaf = lambda keys: (keys, [(k, k) for k in keys], [])
        # inner node with two entries (three leaves of five) loses one entry through a leaf merge; its right sibling has 11
        a = ([10, 20], [(10, 0), (20, 0)], [leaf(list(range(1, 6))), leaf(list(range(11, 16))), leaf(list(range(21, 26)))])
        sib = (list(range(1000, 1011)), [(k, 0) for k in range(1000, 1011)], [leaf([600 + k * 10 + i for i in range(5)]) for k in range(12)])
        root = ([500], [(500, 0)], [a, sib])
        case = dict(spec=root, height=2, key=12, total=0)
        node = tool.instantiate(root, [0])
        log, events = [], []
        tool.tremove_model(node, 2, 99, 12, log, events)
        self.assertEqual(node.kids[1].keys[:2], [1004, 1005])
        self.assertEqual(events[:2], ["leaf", "merge-left"])
        self.assertIn("steal-right", events)
        self.assertEqual(len(node.kids[0].keys), 5)
        self.assertEqual(node.keys, [1003])


class GrowTests(unittest.TestCase):
    def case(self, **kw):
        base = dict(cap=0, ptr=8, length=0, add=1, align=8, elem=8)
        base.update(kw)
        return base

    def test_minimum_capacity_classes(self):
        self.assertEqual(tool.grow_model(self.case(elem=1))[0], 8)
        self.assertEqual(tool.grow_model(self.case(elem=1024))[0], 4)
        self.assertEqual(tool.grow_model(self.case(elem=1025))[0], 1)

    def test_doubling_and_required(self):
        self.assertEqual(tool.grow_model(self.case(cap=10, length=10, ptr=tool.GROW_PTR))[0], 20)
        self.assertEqual(tool.grow_model(self.case(cap=3, length=3, add=40, ptr=tool.GROW_PTR))[0], 43)
        self.assertEqual(tool.grow_model(self.case(cap=0, add=0))[0], 4)

    def test_zero_sized_element_and_length_overflow_are_capacity_errors(self):
        self.assertEqual(tool.grow_model(self.case(elem=0))[0], "capacity-overflow")
        self.assertEqual(tool.grow_model(self.case(length=tool.M64, add=1))[0], "capacity-overflow")

    def test_size_limit_is_isize_max_minus_alignment(self):
        top = tool.ISIZE_TOP
        self.assertEqual(tool.grow_model(self.case(elem=1, add=top - 8))[0], "alloc-error")
        self.assertEqual(tool.grow_model(self.case(elem=1, add=top - 7))[0], "capacity-overflow")

    def test_allocator_choice_by_alignment(self):
        self.assertEqual(tool.grow_model(self.case(align=8))[2], [("alloc", 32)])
        self.assertEqual(tool.grow_model(self.case(align=32))[2], [("alloc-aligned", 32, 5)])
        self.assertEqual(tool.grow_model(self.case(align=1, elem=1))[2], [("alloc", 8)])
        self.assertEqual(tool.grow_model(self.case(cap=4, length=4, ptr=tool.GROW_PTR, align=64))[2], [("realloc-aligned", 64, 6)])

    def test_wrong_floor_is_detected(self):
        # negative control: a floor of 4 for one-byte elements disagrees with the model
        self.assertNotEqual(tool.grow_model(self.case(elem=1))[0], 4)


class HarnessTests(unittest.TestCase):
    def test_scope_excludes_tree_arm_instructions(self):
        self.assertFalse(tool.in_scope(0x4DDBFB7))       # remove: tree arm call
        self.assertTrue(tool.in_scope(0x4DDBFDE))        # remove: ring search call
        self.assertFalse(tool.in_scope(0x4DD6219))       # upsert: tree conversion call
        self.assertTrue(tool.in_scope(0x4DD62D9))        # upsert: ring search call
        self.assertTrue(tool.in_scope(0x580DC90))        # ring copy: whole body

    def test_equivalent_reason_distinguishes_unreached_from_open(self):
        patch = (0x4DD657C, 1, 2, "x", [])
        self.assertIn("no case executes", tool.equivalent_reason(patch, set()))
        self.assertIn("OPEN after 7", tool.equivalent_reason(patch, {0x4DD657C}, 7))

    def test_cases_are_deterministic_and_cover_shapes(self):
        a = [tool.make_case(random.Random(5), n, "remove") for n in range(50)]
        b = [tool.make_case(random.Random(5), n, "remove") for n in range(50)]
        self.assertEqual(a, b)
        routes = {tool.route(c, "remove") for c in (tool.make_case(random.Random(9), n, "remove") for n in range(400))}
        self.assertTrue({"miss", "tail-shift-flat", "head-shift-flat"} <= routes)

    def test_layout_rows_are_well_formed(self):
        for row in tool.LAYOUT:
            self.assertEqual(len(row), 4)
            self.assertGreater(row[2], 0)


class AncestorRepairTests(unittest.TestCase):
    def cases(self, count=60, seed=3):
        rnd = random.Random(seed)
        for n in range(count):
            yield tool.make_tremove_a3(rnd, n)

    def test_height_three_cases_match_an_ordered_map_and_climb_two_levels(self):
        seen = set()
        for case in self.cases():
            self.assertEqual(case["height"], 3)
            before = tree_entries(tool.instantiate(case["spec"], [0]))
            _, (option, root, height, length), _, events = model_run(case)
            want = dict(before)
            value = want.pop(case["key"], None)
            self.assertEqual(sorted(want.items()), tree_entries(root))
            self.assertEqual(option, value)
            seen.update(events)
        self.assertTrue({"merge-left", "steal-left", "steal-right"} & seen)

    def test_node_addresses_are_spread_over_low_bytes(self):
        case = next(self.cases(1))
        root = tool.instantiate(case["spec"], [0])
        low = set()
        stack = [root]
        while stack:
            node = stack.pop()
            low.add(node.addr & 0xFF)
            stack.extend(node.kids)
        self.assertGreater(len(low), 3)
        self.assertEqual(len({n for n in low if n % 16}), 0)

    def test_mutants_the_height_three_cases_separate_are_detected(self):
        image = tool.load_image()
        wanted = {0x4D1A013, 0x4C963F3}
        mutants = [p for p in tool.mutant_list(image) if p[0] in wanted]
        self.assertEqual(len(mutants), 2)
        rnd = random.Random(3)
        cases = [tool.make_tremove_a3(rnd, n) for n in range(80)]
        for patch in mutants:
            machine = tool.Machine(image, {patch[0] + patch[1]: patch[2]})
            machine.step_limit = tool.MUTANT_STEPS
            self.assertTrue(any(tool.compare(image, machine, c, "tremove")[0] for c in cases), hex(patch[0]))

    def test_unmutated_bytes_agree_with_the_model_on_height_three(self):
        image = tool.load_image()
        machine = tool.Machine(image)
        for case in self.cases(25, 11):
            self.assertFalse(tool.compare(image, machine, case, "tremove")[0])

    def test_wrong_model_is_rejected(self):
        image = tool.load_image()
        machine = tool.Machine(image)
        case = next(self.cases(1))
        case = dict(case, key=case["key"] + 1)
        original = tool.tremove_model
        try:
            tool.tremove_model = lambda *a, **k: (_ for _ in ()).throw(AssertionError("stub"))
            with self.assertRaises(AssertionError):
                tool.compare(image, machine, case, "tremove")
        finally:
            tool.tremove_model = original

    def test_documented_equivalents_cover_only_known_instructions(self):
        for va in (0x4D33C7A, 0x4D19FEE, 0x4D1A342, 0x4D1A47A, 0x4D1A47E, 0x4CA165A, 0x4CA1888):
            self.assertIn(va, tool.EQUIVALENT)
            self.assertTrue(tool.EQUIVALENT[va])


if __name__ == "__main__":
    unittest.main()
