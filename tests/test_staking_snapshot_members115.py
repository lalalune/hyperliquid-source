import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_snapshot_members115 as tool  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "staking-snapshot-members-115"
SHARED = {}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SHARED:
            image = tool.load_image()
            SHARED.update(image=image, cases=list(tool.all_cases()), lookup=tool.Members(image))
        cls.image, cls.cases, cls.lookup = SHARED["image"], SHARED["cases"], SHARED["lookup"]

    def check(self, index):
        kind, entry, world = self.cases[index]
        got, want = tool.run_case(self.lookup, entry, world)
        self.assertEqual(got, want, index)
        return got

    def world(self, outer="ring", kinds=("vec",), count=3, sizes=(4,), target="first", probe="first", serial=11):
        return tool.member_world(serial, outer, count, kinds, sizes, target, probe)


class CaseSet(Fixture):
    def test_case_counts_by_kind(self):
        kinds = {}
        for case in self.cases:
            kinds[case[0]] = kinds.get(case[0], 0) + 1
        self.assertEqual(kinds["by_address"], 4368)
        self.assertEqual(kinds["by_key"], 4368)
        self.assertEqual(kinds["form_pair_address"] + kinds["form_pair_key"], 6000)
        self.assertEqual(kinds["key_search_exhaustive"], 1617)
        self.assertEqual(kinds["key_search"], 1500)
        self.assertEqual(kinds["tree_height"], 12)
        self.assertEqual(len(self.cases), 17865)

    def test_every_37th_case_matches_the_rule_list(self):
        for index in range(0, len(self.cases), 37):
            self.check(index)

    def test_every_status_word_is_reached_by_both_queries(self):
        seen = set()
        for index in range(0, len(self.cases), 5):
            kind, entry, world = self.cases[index]
            if entry in (tool.BY_ADDRESS, tool.BY_KEY):
                got = self.check(index)
                seen.add((entry, got[1]))
        self.assertEqual(seen, {(tool.BY_ADDRESS, 0x1A2), (tool.BY_ADDRESS, 0x2B), (tool.BY_ADDRESS, 0x9B),
                                (tool.BY_KEY, 0x1A2), (tool.BY_KEY, 0x98), (tool.BY_KEY, 0x9B)})

    def test_cases_are_deterministic(self):
        again = list(tool.all_cases())
        self.assertEqual(len(again), len(self.cases))
        for index in range(0, len(again), 211):
            self.assertEqual(again[index], self.cases[index])


class ByAddress(Fixture):
    def test_hit_returns_the_key_of_the_entry(self):
        world = self.world(probe="middle")
        snap = tool.snapshot_of(world)
        key, addr = snap["entries"][len(snap["entries"]) // 2]
        got = self.lookup.run_by_address(world)
        self.assertEqual(got, ("query", 0x1A2, key, ()))

    def test_duplicate_address_returns_the_last_key(self):
        world = self.world(count=1, sizes=(5,), target="first", probe="first", serial=3)
        snap = world["snaps"][0]
        entries = list(snap["entries"])
        entries[3] = (entries[3][0], entries[0][1])
        snap["entries"] = tuple(entries)
        world["signer"] = entries[0][1]
        got = self.lookup.run_by_address(world)
        self.assertEqual(got[2], entries[3][0])
        self.assertNotEqual(got[2], entries[0][0])

    def test_duplicate_address_in_a_tree_snapshot_also_returns_the_last_key(self):
        world = self.world(outer="tree", kinds=("tree",), count=1, sizes=(13,), probe="first", serial=4)
        snap = world["snaps"][0]
        entries = list(snap["entries"])
        entries[12] = (entries[12][0], entries[1][1])
        snap["entries"] = tuple(entries)
        world["signer"] = entries[1][1]
        got = self.lookup.run_by_address(world)
        self.assertEqual(got[2], entries[12][0])

    def test_missing_epoch_is_9b_with_a_zero_word_and_no_drop(self):
        world = self.world(target="above", probe="first")
        self.assertEqual(self.lookup.run_by_address(world), ("query", 0x9B, 0, ()))

    def test_present_epoch_without_the_address_is_2b_and_writes_only_the_word(self):
        world = self.world(target="first", probe="absent")
        self.assertEqual(self.lookup.run_by_address(world), ("query", 0x2B, None, ()))

    def test_address_is_compared_over_all_twenty_bytes(self):
        for probe in ("near_first", "near_mid", "near_16", "near_last"):
            world = self.world(count=2, sizes=(6,), target="first", probe=probe, serial=21)
            got = self.lookup.run_by_address(world)
            self.assertEqual(got[1], 0x2B, probe)

    def test_epoch_alias_in_the_high_word_is_not_a_match(self):
        world = self.world(count=2, sizes=(3,), target="alias", probe="first")
        self.assertEqual(self.lookup.run_by_address(world)[1], 0x9B)

    def test_address_of_another_snapshot_is_not_a_member(self):
        world = self.world(count=3, sizes=(4,), target="first", probe="other", serial=29)
        snap = tool.snapshot_of(world)
        if world["signer"] not in [a for _, a in snap["entries"]]:
            self.assertEqual(self.lookup.run_by_address(world)[1], 0x2B)

    def test_empty_snapshot_has_no_member(self):
        world = self.world(count=1, sizes=(0,), target="first", probe="absent")
        self.assertEqual(self.lookup.run_by_address(world)[1], 0x2B)


class ByKey(Fixture):
    def test_hit_returns_the_address_and_drops_a_0x98_record_once(self):
        world = self.world(probe="last")
        snap = tool.snapshot_of(world)
        got = self.lookup.run_by_key(world)
        self.assertEqual(got, ("query", 0x1A2, snap["entries"][-1][1], (("drop", 0x98),)))

    def test_tree_snapshot_hit_has_the_same_shape(self):
        world = self.world(outer="tree", kinds=("tree",), sizes=(30,), probe="middle", serial=17)
        snap = tool.snapshot_of(world)
        got = self.lookup.run_by_key(world)
        self.assertEqual(got, ("query", 0x1A2, snap["entries"][len(snap["entries"]) // 2][1], (("drop", 0x98),)))

    def test_absent_key_is_0x98_alone(self):
        for probe in ("gap_low", "gap_mid", "gap_high", "absent"):
            world = self.world(count=2, sizes=(6,), probe=probe, serial=23)
            self.assertEqual(self.lookup.run_by_key(world), ("query", 0x98, None, ()), probe)

    def test_key_is_compared_over_all_thirty_two_bytes(self):
        for probe in ("near_first", "near_mid", "near_16", "near_last"):
            for outer, kinds in (("ring", ("vec",)), ("tree", ("tree",))):
                world = self.world(outer=outer, kinds=kinds, count=2, sizes=(9,), probe=probe, serial=31)
                self.assertEqual(self.lookup.run_by_key(world)[1], 0x98, (probe, outer))

    def test_missing_epoch_is_9b_with_no_drop(self):
        world = self.world(target="below", probe="first")
        self.assertEqual(self.lookup.run_by_key(world), ("query", 0x9B, 0, ()))

    def test_same_key_in_two_snapshots_answers_from_the_requested_epoch(self):
        world = self.world(count=3, sizes=(5,), target="last", probe="first", serial=41)
        first = tool.snapshot_of(world)
        got = self.lookup.run_by_key(world)
        other = world["snaps"][0]
        self.assertEqual(first["entries"][0][0], other["entries"][0][0])
        self.assertNotEqual(first["entries"][0][1], other["entries"][0][1])
        self.assertEqual(got[2], first["entries"][0][1])


class KeySearch(Fixture):
    def test_hit_gives_the_logical_index_through_a_wrapped_ring(self):
        world = tool.key_search_world(5, 7, 2, 5, 2 * 3)
        self.assertEqual(self.lookup.run_key_search(world), ("key_search", 0, 2))

    def test_miss_gives_the_insertion_index(self):
        world = tool.key_search_world(5, 7, 1, 3, 2 * 3 + 1)
        self.assertEqual(self.lookup.run_key_search(world), ("key_search", 1, 3))

    def test_below_all_and_above_all(self):
        low = tool.key_search_world(6, 5, 0, 0, 1)
        high = tool.key_search_world(6, 5, 0, 0, 2 * 5 + 1 - 0)
        self.assertEqual(self.lookup.run_key_search(low), ("key_search", 1, 0))
        self.assertEqual(self.lookup.run_key_search(dict(high, key=tool.entry_key(6, 99))), ("key_search", 1, 5))

    def test_single_element_ring(self):
        world = tool.key_search_world(7, 1, 3, 2, 2)
        self.assertEqual(self.lookup.run_key_search(world), ("key_search", 0, 0))

    def test_key_differing_in_the_last_byte_is_a_miss(self):
        world = tool.key_search_world(8, 6, 0, 0, 4)
        key = bytearray(world["key"])
        key[31] ^= 1
        got = self.lookup.run_key_search(dict(world, key=bytes(key)))
        self.assertEqual(got[1], 1)

    def test_memcmp_stub_returns_the_byte_difference(self):
        class Box:
            pass
        machine = self.lookup.machine
        machine.memory.reset(tool.HEAP_USED)
        self.lookup.put(tool.KEY_AT, bytes([1, 2, 3]))
        self.lookup.put(tool.KEY_AT + 0x40, bytes([1, 2, 5]))
        machine.regs[tool.RDI], machine.regs[tool.RSI], machine.regs[tool.RDX] = tool.KEY_AT, tool.KEY_AT + 0x40, 3
        tool.memcmp_stub(machine)
        self.assertEqual(machine.regs[tool.RAX], (-2) & tool.MASK[8])
        machine.regs[tool.RDX] = 2
        tool.memcmp_stub(machine)
        self.assertEqual(machine.regs[tool.RAX], 0)


class Fixtures(Fixture):
    def test_entry_keys_sort_in_rank_order_and_are_32_bytes(self):
        keys = [tool.entry_key(3, 2 * (n + 1)) for n in range(300)]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual({len(key) for key in keys}, {32})

    def test_snapshot_entries_are_sorted_with_unique_keys(self):
        for index in range(0, len(self.cases), 301):
            kind, entry, world = self.cases[index]
            for snap in world.get("snaps", ()):
                keys = [key for key, _ in snap["entries"]]
                self.assertEqual(keys, sorted(set(keys)))

    def test_swapped_world_keeps_the_logical_content(self):
        base = self.world(outer="ring", kinds=("vec", "tree"), count=4, sizes=(3, 12))
        other = tool.swapped_world(base)
        self.assertEqual([s["entries"] for s in base["snaps"]], [s["entries"] for s in other["snaps"]])
        self.assertNotEqual(base["outer"], other["outer"])
        self.assertEqual(self.lookup.run_by_address(base)[1:3], self.lookup.run_by_address(other)[1:3])
        self.assertEqual(self.lookup.run_by_key(base)[1:3], self.lookup.run_by_key(other)[1:3])

    def test_query_never_writes_its_store(self):
        for outer, kinds in (("ring", ("vec",)), ("tree", ("tree",))):
            world = self.world(outer=outer, kinds=kinds, count=3, sizes=(7,), probe="last")
            self.lookup.run_by_address(world)
            self.lookup.run_by_key(world)

    def test_output_overrun_is_noticed(self):
        world = self.world(probe="first")
        self.lookup.start(world)
        self.lookup.write(tool.OUT_AT, 0x1A2, 2)
        self.lookup.write(tool.OUT_AT + 0x30, 7, 1)
        self.lookup.width = 20
        with self.assertRaises(tool.Halt):
            self.lookup.read_out()


class Controls(Fixture):
    def rows(self, name):
        return [line.split("\t") for line in (EVIDENCE / name).read_text().splitlines()[1:]]

    def test_every_rule_list_flaw_is_detected_by_some_case(self):
        for flaw, entries in tool.FLAWS:
            for entry in entries:
                found = False
                for kind, ent, world in self.cases:
                    if ent == entry and tool.flawed(world, entry, flaw) != tool.spec_for(world, entry):
                        found = True
                        break
                self.assertTrue(found, flaw)

    def test_search_flaws_are_detected(self):
        for flaw in tool.SEARCH_FLAWS:
            self.assertTrue(any(ent == tool.KEY_SEARCH and tool.flawed_search(world, flaw) != tool.spec_key_search(world)
                                for kind, ent, world in self.cases), flaw)

    def test_a_flaw_name_that_does_nothing_is_not_detected(self):
        kind, entry, world = self.cases[10]
        self.assertEqual(tool.flawed(world, entry, "no_such_flaw"), tool.spec_for(world, entry))

    def test_killed_byte_edits_replay_as_killed(self):
        tool.STATE.update(image=self.image, cases=self.cases, cache=self.lookup.machine.cache)
        edits = {}
        for entry in (tool.BY_ADDRESS, tool.BY_KEY, tool.KEY_SEARCH):
            low, high = self.image.exact_fde(entry)
            for va, kind, patch in tool.edits_for(self.image, tool.decode_range(self.image, low, high)):
                edits[(va, kind)] = (va, kind, patch)
        killed = [row for row in self.rows("mutations.tsv") if row[2] == "killed"]
        checked = 0
        for row in killed[::6]:
            job = edits.get((int(row[0], 16), row[1]))
            if job is None:
                continue
            tool.STATE["reach"] = {job[0]: [int(row[3].split(":")[1])]}
            self.assertEqual(tool.mutant_task(job)[2], "killed", row)
            checked += 1
        self.assertGreater(checked, 10)

    def test_survivors_are_listed(self):
        rows = self.rows("mutations.tsv")
        summary = json.loads((EVIDENCE / "evidence.json").read_text())
        self.assertEqual(len([r for r in rows if r[2] == "survived"]), summary["byte_edits_survived"])
        self.assertEqual(len(rows), summary["byte_edits_possible"])

    def test_measure_file_agrees_with_the_controls_file(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        rows = self.rows("controls.tsv")
        self.assertEqual(measure["negative_controls"], len(rows))
        self.assertEqual(measure["negative_detected"], len([r for r in rows if r[2] == "True"]))
        self.assertEqual(measure["cases"], len(self.cases))
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])

    def test_control_kinds(self):
        kinds = {}
        for row in self.rows("controls.tsv"):
            kinds[row[0]] = kinds.get(row[0], 0) + 1
        self.assertEqual(kinds["rule_list_flaw"], sum(len(e) for _, e in tool.FLAWS) + len(tool.SEARCH_FLAWS))
        self.assertEqual(kinds["layout_field_moved"], len(tool.damaged_geometry()))
        self.assertGreaterEqual(kinds["byte_edit"], 150)

    def test_path_rows_name_six_real_functions(self):
        rows = self.rows("path.tsv")
        self.assertEqual({row[1] for row in rows}, {"0x36ca5b0", "0x36ca940", "0x4559a60", "0x4551810", "0x37c5530", "0x36dae30"})
        for row in rows:
            self.assertEqual(row[2], "real")
            self.assertLessEqual(int(row[5]), int(row[3]))

    def test_range_controls_all_fire(self):
        for name, detected in tool.range_controls(self.image):
            self.assertTrue(detected, name)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)


if __name__ == "__main__":
    unittest.main()
