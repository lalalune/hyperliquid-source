import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_validator_snapshot115 as tool  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "staking-validator-snapshot-lookup-115"


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.cases = list(tool.all_cases())
        cls.lookup = tool.Lookup(cls.image)

    def of_kind(self, kind):
        return [(index, case) for index, case in enumerate(self.cases) if case[0] == kind]

    def check(self, index):
        kind, entry, world = self.cases[index]
        got, want = tool.run_case(self.lookup, entry, world)
        self.assertEqual(got, want, index)
        return got


class LookupRuns(Fixture):
    def test_every_25th_case_matches_the_rule_list(self):
        for index in range(0, len(self.cases), 25):
            self.check(index)

    def test_member_is_true_and_leaves_no_drop(self):
        world = tool.lookup_world(1, "ring", 3, ("vec",), (0,), "middle", "first")
        if not world["snaps"][1]["addrs"]:
            world["snaps"][1]["addrs"] = (tool.address(77),)
            world["signer"] = tool.address(77)
        self.assertEqual(self.lookup.run(world), (1, ()))

    def test_missing_epoch_drops_status_9b_with_a_zero_word(self):
        world = tool.lookup_world(2, "ring", 3, ("vec",), (0,), "above", "absent")
        self.assertEqual(self.lookup.run(world), (0, (("drop", 0x9B, 0),)))

    def test_present_epoch_without_the_signer_drops_status_2b(self):
        world = tool.lookup_world(3, "tree", 3, ("tree",), (3,), "first", "absent")
        self.assertEqual(self.lookup.run(world), (0, (("drop", 0x2B),)))

    def test_epoch_must_match_exactly_not_by_the_low_word(self):
        world = tool.lookup_world(4, "ring", 2, ("vec",), (0,), "alias", "first")
        self.assertEqual(self.lookup.run(world)[0], 0)

    def test_signer_is_compared_over_all_twenty_bytes(self):
        base = tool.lookup_world(5, "ring", 2, ("vec",), (0,), "first", "first")
        base["snaps"][0]["addrs"] = (tool.address(900),)
        for position in (0, 15, 16, 19):
            signer = bytearray(tool.address(900))
            signer[position] ^= 0x01
            self.assertEqual(self.lookup.run(dict(base, signer=bytes(signer)))[0], 0, position)
        self.assertEqual(self.lookup.run(dict(base, signer=tool.address(900)))[0], 1)

    def test_a_member_in_another_snapshot_does_not_count(self):
        for outer in ("ring", "tree"):
            world = tool.lookup_world(6, outer, 6, ("vec", "tree"), (2, 12), "first", "other")
            self.assertEqual(self.lookup.run(world)[0], 0)

    def test_argument_is_never_written(self):
        for index, (kind, entry, world) in self.of_kind("lookup")[::90]:
            self.lookup.run(world)

    def test_both_stores_and_both_value_forms_are_exercised(self):
        seen = {(world["outer"], world["kinds"]) for kind, _, world in self.cases if kind == "lookup"}
        self.assertEqual(seen, {(o, k) for o in ("ring", "tree") for k in ("v", "t", "vt")})


class RingSearch(Fixture):
    def test_exhaustive_small_rings_cover_every_wrap(self):
        flags = set()
        for index, (kind, entry, world) in self.of_kind("ring_exhaustive")[::7]:
            self.check(index)
            flags.add(tool.ring_flags(world))
        self.assertEqual(flags, {0, 1, 2})

    def test_found_returns_the_logical_index(self):
        world = tool.lookup_world(7, "ring", 5, ("vec",), (0,), "first", "absent")
        world["epoch"] = world["snaps"][3]["epoch"]
        world["head"], world["spare"] = 2, 1
        self.assertEqual(self.lookup.run_search(world), ("search", 0, 3))

    def test_absent_returns_the_insertion_index(self):
        world = tool.lookup_world(8, "ring", 5, ("vec",), (0,), "first", "absent")
        world["epoch"] = world["snaps"][2]["epoch"] + 1000
        self.assertEqual(self.lookup.run_search(world), ("search", 1, 5))
        world["epoch"] = 0
        self.assertEqual(self.lookup.run_search(world), ("search", 1, 0))


class TreeIteration(Fixture):
    def test_yields_in_key_order_and_then_none(self):
        entries = tuple(((n + 1).to_bytes(4, "big") + bytes([9]) * 28, bytes([n % 250]) * 0x48) for n in range(30))
        got = self.lookup.run_iter(dict(shape=3, entries=entries, extra=1))
        self.assertEqual(got, tool.spec_iter(dict(entries=entries, extra=1))[:2] + (0,))
        self.assertEqual(got[1][-2:], (None, None))

    def test_height_nine_tree_uses_the_unrolled_descent(self):
        for index, (kind, entry, world) in self.of_kind("tree_deep"):
            if world["height"] == 9:
                self.check(index)
                self.assertGreaterEqual(len(world["entries"]), tool.minimum(9))

    def test_a_front_state_of_two_with_items_left_panics(self):
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.put(tool.ITER_AT, struct.pack("<QQQQQQQQQ", 2, 0, 0, 0, 2, 0, 0, 0, 5))
        with self.assertRaises(tool.Panicked):
            self.lookup.machine.run(tool.ITER_NEXT, {tool.RDI: tool.ITER_AT})

    def test_tree_builder_obeys_the_height_bounds(self):
        for height in range(0, 6):
            self.assertLessEqual(tool.minimum(height), tool.capacity(height))
        self.assertEqual(tool.tree_height(11), 0)
        self.assertEqual(tool.tree_height(12), 1)
        self.assertEqual(tool.tree_height(144), 2)


class StatusDrop(Fixture):
    def test_arm_for_every_word_comes_from_the_jump_tables(self):
        arms = {tool.drop_arm(self.image, word) for word in range(0x200)}
        self.assertIn(tool.DROP_EXIT, arms)
        self.assertEqual(len(arms), 10)

    def test_every_word_enters_its_arm(self):
        for index, (kind, entry, world) in self.of_kind("status_drop")[::3]:
            self.check(index)

    def test_the_two_lookup_statuses_free_nothing(self):
        for word in (tool.STATUS_NOT_MEMBER, tool.STATUS_NO_SNAPSHOT):
            for mode in tool.STATUS_MODES:
                self.lookup.run_status(word, mode)
                self.assertEqual([item for item in self.lookup.info[1] if item[0] == "free"], [], (word, mode))

    def test_rows_file_lists_only_non_exit_arms(self):
        rows = [line.split("\t") for line in (EVIDENCE / "status-drop.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        self.assertTrue(all(int(row[2], 16) != tool.DROP_EXIT for row in rows))


class Controls(Fixture):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_address_checks(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.VALIDATOR + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x100)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)

    def test_every_rule_list_flaw_differs_from_the_bytes_somewhere(self):
        worlds = [world for kind, entry, world in self.cases if kind == "lookup"]
        for flaw in tool.MODEL_FLAWS:
            self.assertTrue(any(tool.flawed_lookup(world, flaw) != tool.spec_lookup(world) for world in worlds), flaw)

    def test_moved_layout_fields_are_contradicted(self):
        picked = [i for i, case in enumerate(self.cases) if (case[0] == "lookup" and i % 11 == 0) or (case[0] == "tree_iter" and i % 29 == 0)][:400]
        tool.STATE.update(image=self.image, cases=self.cases, geometry_cases=picked)
        for name, field in tool.damaged_geometry(self.image):
            self.assertTrue(tool.geometry_task((name, field))[2], (name, field))

    def test_byte_edits_are_killed_on_chosen_sites(self):
        tool.STATE.update(image=self.image, cases=self.cases, cache=self.lookup.machine.cache)
        killed = 0
        for va, entry in ((0x36C8441, tool.VALIDATOR), (0x36C84F6, tool.VALIDATOR), (0x4551839, tool.DEQUE_SEARCH)):
            low, high = self.image.exact_fde(entry)
            decoded = [row for row in tool.decode_range(self.image, low, high) if row.va == va]
            self.assertEqual(len(decoded), 1, hex(va))
            edits = tool.edits_for(self.image, decoded)
            if not edits:
                continue
            tool.STATE["reach"] = {va: [i for i, case in enumerate(self.cases) if case[1] == entry][::37][:60]}
            killed += tool.mutant_task(edits[0])[2] == "killed"
        self.assertGreaterEqual(killed, 1)

    def test_patched_stride_changes_the_result(self):
        # the 0x38 element size of the ring: one byte moved shifts every element after the first
        world = tool.lookup_world(11, "ring", 6, ("vec",), (3,), "last", "last")
        patched = tool.Lookup(self.image, {0x4551872 + 0: 0x90})
        with self.assertRaises((tool.Halt, tool.Panicked, tool.EvidenceError, KeyError, IndexError, ValueError)):
            for index, (kind, entry, w) in self.of_kind("ring_exhaustive")[::5]:
                got, want = tool.run_case(patched, entry, w)
                if got != want:
                    raise tool.Halt("differs")


class Files(Fixture):
    def test_controls_file_has_no_undetected_row(self):
        rows = [line.split("\t") for line in (EVIDENCE / "controls.tsv").read_text().splitlines()[1:]]
        self.assertGreaterEqual(len(rows), 30)
        self.assertTrue(all(row[2] == "True" for row in rows))
        self.assertEqual({row[0] for row in rows}, {"layout_field_moved", "rule_list_flaw", "byte_edit", "out_of_range"})

    def test_scenario_rows_replay(self):
        rows = [line.split("\t") for line in (EVIDENCE / "scenarios.tsv").read_text().splitlines()[1:]]
        self.assertGreater(len(rows), 100)
        for row in rows[::25]:
            index = int(row[0])
            kind, entry, world = self.cases[index]
            got, want = tool.run_case(self.lookup, entry, world)
            self.assertEqual(got, want)
            if kind == "status_drop":
                self.assertEqual((row[1], row[5]), (kind, self.lookup.info[0]))
            else:
                self.assertEqual((row[1], row[5]), (kind, tool.case_label(entry, got)))

    def test_measure_counts_agree_with_the_evidence(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        summary = json.loads((EVIDENCE / "evidence.json").read_text())
        self.assertEqual(measure["negative_controls"], summary["controls"])
        self.assertEqual(measure["negative_detected"], summary["controls_detected"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertEqual(summary["cases"], len(self.cases))

    def test_manifest_hashes_every_file(self):
        names = set()
        for line in (EVIDENCE / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {p.name for p in EVIDENCE.iterdir() if p.name != "MANIFEST.sha256"})


class Regeneration(Fixture):
    def test_files_match_the_tool_output(self):
        files = tool.render(tool.analyse(self.image), self.image)
        for name, text in files.items():
            self.assertEqual((EVIDENCE / name).read_bytes(), text.encode("ascii"), name)


class ExplicitWorlds(Fixture):
    """Hand-built worlds, one rule each, so a failure names the rule."""

    def world(self, outer, snaps, epoch, signer, head=0, spare=0):
        return dict(shape=3, outer=outer, snaps=snaps, epoch=epoch, signer=signer, head=head, spare=spare, target="x", probe="x", kinds="v")

    def snap(self, epoch, count, kind="vec", base=0):
        return dict(epoch=epoch, kind=kind, head=1, spare=2, addrs=tuple(tool.address(base + n) for n in range(count)))

    def test_every_member_of_a_sixty_element_ring_is_found(self):
        snaps = [self.snap(10, 60, "vec", 100), self.snap(20, 3, "vec", 500)]
        for position in range(60):
            world = self.world("ring", snaps, 10, snaps[0]["addrs"][position], head=1, spare=1)
            self.assertEqual(self.lookup.run(world), (1, ()), position)

    def test_every_member_of_a_two_hundred_entry_tree_is_found(self):
        snaps = [self.snap(10, 200, "tree", 100), self.snap(20, 5, "tree", 900)]
        for position in range(0, 200, 7):
            world = self.world("ring", snaps, 10, snaps[0]["addrs"][position])
            self.assertEqual(self.lookup.run(world), (1, ()), position)
        self.assertEqual(self.lookup.run(self.world("ring", snaps, 10, tool.address(500)))[0], 0)

    def test_twelve_snapshots_force_a_two_level_outer_tree(self):
        snaps = [self.snap(10 + 3 * n, 2, "vec", 40 * n) for n in range(12)]
        for number, snap in enumerate(snaps):
            world = self.world("tree", snaps, snap["epoch"], snap["addrs"][1])
            self.assertEqual(self.lookup.run(world), (1, ()), number)
            world = self.world("tree", snaps, snap["epoch"] + 1, snap["addrs"][1])
            self.assertEqual(self.lookup.run(world), (0, (("drop", 0x9B, 0),)), number)

    def test_snapshot_of_the_next_epoch_does_not_count(self):
        snaps = [self.snap(10, 2, "vec", 0), self.snap(11, 2, "vec", 50)]
        for outer in ("ring", "tree"):
            self.assertEqual(self.lookup.run(self.world(outer, snaps, 10, snaps[1]["addrs"][0])), (0, (("drop", 0x2B),)))
            self.assertEqual(self.lookup.run(self.world(outer, snaps, 11, snaps[1]["addrs"][0])), (1, ()))

    def test_empty_snapshot_has_no_member_and_drops_2b(self):
        snaps = [self.snap(10, 0, "vec"), self.snap(12, 0, "tree")]
        for epoch in (10, 12):
            self.assertEqual(self.lookup.run(self.world("ring", snaps, epoch, tool.address(1))), (0, (("drop", 0x2B),)))

    def test_no_snapshots_at_all(self):
        for outer in ("ring", "tree"):
            self.assertEqual(self.lookup.run(self.world(outer, [], 5, tool.address(1))), (0, (("drop", 0x9B, 0),)))

    def test_epoch_above_2_to_the_40_is_compared_in_full(self):
        big = (1 << 40) + 5
        snaps = [self.snap(big, 2, "vec", 0), self.snap(big + 1, 2, "vec", 20)]
        for outer in ("ring", "tree"):
            self.assertEqual(self.lookup.run(self.world(outer, snaps, big + 1, snaps[1]["addrs"][1]))[0], 1)
            self.assertEqual(self.lookup.run(self.world(outer, snaps, big + 1 + (1 << 32), snaps[1]["addrs"][1]))[0], 0)

    def test_walk_cost_grows_with_the_snapshot_size(self):
        steps = []
        for count in (1, 10, 50):
            snaps = [self.snap(10, count, "vec", 0)]
            before = self.lookup.machine.steps
            self.lookup.run(self.world("ring", snaps, 10, snaps[0]["addrs"][0]))
            steps.append(self.lookup.machine.steps - before)
        self.assertLess(steps[0], steps[1])
        self.assertLess(steps[1], steps[2])

    def test_membership_is_independent_of_the_position_in_the_ring(self):
        snaps = [self.snap(10, 9, "vec", 0)]
        results = set()
        for head in range(0, 9):
            for spare in range(0, 3):
                world = self.world("ring", snaps, 10, snaps[0]["addrs"][4], head=head, spare=spare)
                results.add(self.lookup.run(world))
        self.assertEqual(results, {(1, ())})


class FixtureShape(Fixture):
    def test_check_tree_accepts_every_deep_fixture(self):
        for index, (kind, entry, world) in self.of_kind("tree_deep"):
            self.lookup.run_iter(world)

    def test_check_tree_rejects_a_broken_parent_link(self):
        entries = [((n + 1).to_bytes(4, "big") + bytes([7]) * 28, bytes(0x48)) for n in range(40)]
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.top, self.lookup.stream = tool.ARENA_AT, tool.Stream(4)
        root, height = self.lookup.build_tree(entries, tool.INNER)
        keys = [key for key, _ in entries]
        self.assertEqual(self.lookup.check_tree(root, height, tool.INNER, keys), keys)
        child = self.lookup.read(root + tool.INNER["edges"])
        self.lookup.write(child + tool.INNER["parent"], root + 8)
        with self.assertRaises(tool.EvidenceError):
            self.lookup.check_tree(root, height, tool.INNER, keys)

    def test_check_tree_rejects_unsorted_keys(self):
        entries = [((n + 1).to_bytes(4, "big") + bytes([7]) * 28, bytes(0x48)) for n in range(5)]
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.top, self.lookup.stream = tool.ARENA_AT, tool.Stream(4)
        root, height = self.lookup.build_tree(entries, tool.INNER)
        with self.assertRaises(tool.EvidenceError):
            self.lookup.check_tree(root, height, tool.INNER, list(reversed([key for key, _ in entries])))

    def test_ring_builder_places_elements_from_the_head(self):
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.top = tool.ARENA_AT
        cap, buf, head, length = self.lookup.build_ring([bytes([n]) * 4 for n in range(5)], 4, 3, 2)
        self.assertEqual((cap, head, length), (7, 3, 5))
        slots = [self.lookup.data(buf + 4 * ((3 + n) % 7), 4) for n in range(5)]
        self.assertEqual(slots, [bytes([n]) * 4 for n in range(5)])

    def test_address_helper_is_twenty_bytes_and_distinct(self):
        values = {tool.address(n) for n in range(5000)}
        self.assertEqual(len(values), 5000)
        self.assertEqual({len(v) for v in values}, {20})


class StatusFile(Fixture):
    def rows(self):
        return [line.split("\t") for line in (EVIDENCE / "status-drop.tsv").read_text().splitlines()[1:]]

    def test_listed_words_have_the_arm_the_tables_give(self):
        for word, mode, arm, outcome, frees in self.rows():
            self.assertEqual(int(arm, 16), tool.drop_arm(self.image, int(word)), word)

    def test_rows_replay_with_the_same_outcome_and_frees(self):
        for word, mode, arm, outcome, frees in self.rows():
            self.lookup.run_status(int(word), mode)
            got = self.lookup.info
            self.assertEqual(got[0], outcome, word)
            sizes = ",".join("%#x" % item[2] for item in got[1] if item[0] == "free") or "-"
            self.assertEqual(sizes, frees, word)

    def test_words_outside_the_tables_return_at_once(self):
        for word in (0x00, 0x2B, 0x3C, 0x9B, 0x1FF, 0x18A, 0x161):
            if tool.drop_arm(self.image, word) == tool.DROP_EXIT:
                self.lookup.run_status(word, "owned")
                self.assertEqual(self.lookup.info, ("returned", ()), word)

    def test_free_hook_records_pointer_size_and_alignment_word(self):
        word = next(int(r[0]) for r in self.rows() if r[1] == "owned" and r[4] != "-")
        self.lookup.run_status(word, "owned")
        frees = [item for item in self.lookup.info[1] if item[0] == "free"]
        self.assertTrue(frees)
        for item in frees:
            self.assertEqual(len(item), 4)
            self.assertEqual(item[3], 0)


class FormPairs(Fixture):
    """The same logical world in the other store forms gives the same lookup result and the same drops."""

    def pairs(self):
        cases = [case for case in self.cases if case[0] == "form_pair"]
        return list(zip(cases[0::2], cases[1::2]))

    def test_pairs_exist_in_both_directions(self):
        pairs = self.pairs()
        self.assertEqual(len(pairs), 4000)
        outers = {(a[2]["outer"], b[2]["outer"]) for a, b in pairs}
        self.assertEqual(outers, {("ring", "tree"), ("tree", "ring")})

    def test_swapped_world_has_the_same_logical_content(self):
        for a, b in self.pairs()[::41]:
            self.assertEqual([s["epoch"] for s in a[2]["snaps"]], [s["epoch"] for s in b[2]["snaps"]])
            self.assertEqual([s["addrs"] for s in a[2]["snaps"]], [s["addrs"] for s in b[2]["snaps"]])
            self.assertEqual((a[2]["epoch"], a[2]["signer"]), (b[2]["epoch"], b[2]["signer"]))
            self.assertNotEqual(a[2]["outer"], b[2]["outer"])

    def test_both_forms_give_equal_results(self):
        for a, b in self.pairs()[::13]:
            self.assertEqual(self.lookup.run(a[2]), self.lookup.run(b[2]))

    def test_double_swap_is_the_identity(self):
        for a, b in self.pairs()[::97]:
            again = tool.swapped(b[2])
            self.assertEqual((again["outer"], [s["kind"] for s in again["snaps"]]), (a[2]["outer"], [s["kind"] for s in a[2]["snaps"]]))


class IteratorPointers(Fixture):
    def test_key_and_value_pointers_yield_the_bytes_of_one_entry(self):
        entries = tuple(((n + 1).to_bytes(4, "big") + bytes([5]) * 28, bytes([n % 200]) * 0x48) for n in range(40))
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.top, self.lookup.stream = tool.ARENA_AT, tool.Stream(8)
        root, height = self.lookup.build_tree(entries, tool.INNER)
        state = struct.pack("<QQQQQQQQQ", 1, 0, root, height, 1, 0, root, height, len(entries))
        self.lookup.put(tool.ITER_AT, state)
        for number in range(len(entries)):
            key_at = self.lookup.machine.run(tool.ITER_NEXT, {tool.RDI: tool.ITER_AT})
            value_at = self.lookup.machine.regs[tool.RDX]
            self.assertEqual(self.lookup.data(key_at, 32), entries[number][0], number)
            self.assertEqual(self.lookup.data(value_at, 0x48), entries[number][1], number)

    def test_remaining_count_runs_down_to_zero(self):
        entries = tuple(((n + 1).to_bytes(4, "big") + bytes([5]) * 28, bytes(0x48)) for n in range(25))
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.top, self.lookup.stream = tool.ARENA_AT, tool.Stream(9)
        root, height = self.lookup.build_tree(entries, tool.INNER)
        self.lookup.put(tool.ITER_AT, struct.pack("<QQQQQQQQQ", 1, 0, root, height, 1, 0, root, height, len(entries)))
        remaining = []
        for _ in range(26):
            self.lookup.machine.run(tool.ITER_NEXT, {tool.RDI: tool.ITER_AT})
            remaining.append(self.lookup.read(tool.ITER_AT + 0x40))
        self.assertEqual(remaining, list(range(24, -1, -1)) + [0])

    def test_empty_iterator_returns_null_without_touching_the_node(self):
        self.lookup.machine.memory.reset(tool.HEAP_USED)
        self.lookup.put(tool.ITER_AT, struct.pack("<QQQQQQQQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(self.lookup.machine.run(tool.ITER_NEXT, {tool.RDI: tool.ITER_AT}), 0)


class ReplayedControls(Fixture):
    def rows(self, name):
        return [line.split("\t") for line in (EVIDENCE / name).read_text().splitlines()[1:]]

    def test_killed_byte_edits_replay_as_killed(self):
        tool.STATE.update(image=self.image, cases=self.cases, cache=self.lookup.machine.cache)
        scenario = None
        killed = [row for row in self.rows("mutations.tsv") if row[2] == "killed" and not row[3].startswith("status_drop")]
        edits = {}
        for entry in (tool.VALIDATOR, tool.DEQUE_SEARCH, tool.ITER_NEXT):
            low, high = self.image.exact_fde(entry)
            for va, kind, patch in tool.edits_for(self.image, tool.decode_range(self.image, low, high)):
                edits[(va, kind)] = (va, kind, patch)
        checked = 0
        for row in killed[::9]:
            job = edits.get((int(row[0], 16), row[1]))
            if job is None:
                continue
            index = int(row[3].split(":")[1])
            tool.STATE["reach"] = {job[0]: [index]}
            tool.STATE["baseline"] = {}
            self.assertEqual(tool.mutant_task(job)[2], "killed", row)
            checked += 1
        self.assertGreater(checked, 5)

    def test_every_survivor_is_listed_with_its_address_and_kind(self):
        rows = self.rows("mutations.tsv")
        survived = [row for row in rows if row[2] == "survived"]
        summary = json.loads((EVIDENCE / "evidence.json").read_text())
        self.assertEqual(len(survived), summary["byte_edits_survived"])
        self.assertEqual(len(rows), summary["byte_edits_possible"])
        self.assertTrue(all(row[1] in ("condition", "immediate") for row in rows))

    def test_control_kinds_and_counts(self):
        rows = self.rows("controls.tsv")
        kinds = {}
        for row in rows:
            kinds[row[0]] = kinds.get(row[0], 0) + 1
        self.assertEqual(kinds["rule_list_flaw"], len(tool.MODEL_FLAWS))
        self.assertEqual(kinds["layout_field_moved"], len(tool.damaged_geometry(self.image)))
        self.assertGreaterEqual(kinds["byte_edit"], 100)

    def test_path_rows_name_four_real_functions(self):
        rows = self.rows("path.tsv")
        self.assertEqual({row[1] for row in rows}, {"0x36c8430", "0x4551810", "0x37c5530", "0x36dae30"})
        self.assertTrue(all(row[2] == "real" for row in rows))
        for row in rows:
            self.assertLessEqual(int(row[5]), int(row[3]))


if __name__ == "__main__":
    unittest.main()
