import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_admission_gate115 as tool  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "staking-admission-gate-115"


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.table = tool.read_table(cls.image)
        cls.listed = tool.read_listed(cls.image)
        cls.cases = list(tool.all_cases(cls.table, cls.listed))
        cls.gate = tool.Gate(cls.image)

    def run_one(self, gate, index):
        kind, entry, world = self.cases[index]
        return tool.run_case(gate, entry, world, self.table)


class ClassTable(Fixture):
    def test_table_comes_from_the_bytes(self):
        start = self.image.offset(tool.CLASS_TABLE)
        self.assertEqual(self.table, list(self.image.blob[start:start + tool.CLASS_COUNT]))
        self.assertEqual(sorted(set(self.table)), [0, 1, 2, 3, 4])
        self.assertEqual(self.table[tool.RAW_NICHE_INDEX], 1)

    def test_getter_matches_the_rule_on_every_word(self):
        sweep = tool.class_sweep(self.gate, self.table)
        self.assertEqual(len(sweep), tool.RAW_BASE + tool.CLASS_COUNT + 4)
        self.assertEqual(sweep[0], (0, 1))
        self.assertEqual(sweep[tool.RAW_BASE - 1], (tool.RAW_BASE - 1, 1))
        self.assertEqual(sweep[tool.RAW_BASE], (tool.RAW_BASE, self.table[0]))

    def test_every_damaged_table_byte_is_seen(self):
        tool.STATE.update(table=self.table, sweep=tool.class_sweep(self.gate, self.table))
        for index in range(tool.CLASS_COUNT):
            self.assertTrue(tool.damage_task(index)[1], index)

    def test_word_far_outside_the_table_is_refused(self):
        with self.assertRaises(tool.Halt):
            self.gate.run_class(0x7000000000000000)


class GateRuns(Fixture):
    def test_every_43rd_case_matches_the_rule_list(self):
        for index in range(0, len(self.cases), 43):
            got, want = self.run_one(self.gate, index)
            self.assertEqual(got, want, index)

    def test_statuses_and_payloads(self):
        signer = tool.sig(5)
        for entry in tool.GATES:
            world = tool.blank_world(tool.RAW_BASE + 56, signer)
            out, log, compares = self.gate.run(world, entry)
            self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_REFUSED)
            self.assertEqual(out[2:], bytes([tool.OUT_FILL]) * (tool.OUT_SIZE - 2))
            world = tool.blank_world(tool.RAW_BASE + 1, signer)
            out, log, compares = self.gate.run(world, entry)
            self.assertEqual((struct.unpack_from("<H", out)[0], out[2:22]), (tool.STATUS_OK, signer))

    def test_listed_signer_passes_only_class_one(self):
        signer = tool.sig(6)
        for entry in tool.GATES:
            for tag, want in ((tool.RAW_BASE + 20, tool.STATUS_OK), (tool.RAW_BASE + 25, tool.STATUS_NOT_VALIDATOR)):
                world = tool.blank_world(tag, signer, 3)
                world["locks"] = {"chain3": (0, (signer,)), "other": (0, ())}
                out, log, compares = self.gate.run(world, entry)
                self.assertEqual(struct.unpack_from("<H", out)[0], want, (hex(entry), hex(tag)))

    def test_chain_byte_three_selects_the_first_set(self):
        signer = tool.sig(7)
        world = tool.blank_world(tool.RAW_BASE + 20, signer, 2)
        world["locks"] = {"chain3": (0, (signer,)), "other": (0, ())}
        out, _, _ = self.gate.run(world, tool.GATES[0])
        self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_NOT_VALIDATOR)

    def test_lazy_lock_runs_its_once_before_the_search(self):
        signer = tool.sig(8)
        world = tool.blank_world(tool.RAW_BASE + 20, signer, 0)
        world["locks"] = {"chain3": (0, ()), "other": (1, (signer,))}
        out, log, _ = self.gate.run(world, tool.GATES[1])
        self.assertEqual(log, (("validator", tool.tag4(signer)), ("once", "other")))
        self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_OK)

    def test_unknown_user_keeps_the_signer_as_payload(self):
        signer = tool.sig(9)
        world = tool.blank_world(tool.RAW_BASE, signer)
        out, log, _ = self.gate.run(world, tool.GATES[0])
        self.assertEqual((struct.unpack_from("<H", out)[0], out[2:22]), (tool.STATUS_UNKNOWN_USER, signer))
        self.assertEqual(log[0], ("user_get", tool.tag4(signer)))

    def test_length_zero_second_map_never_reads_its_key(self):
        signer = tool.sig(10)
        world = tool.blank_world(tool.RAW_BASE, signer)
        world["second"] = (0, frozenset([signer]), signer)
        out, log, _ = self.gate.run(world, tool.GATES[0])
        self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_UNKNOWN_USER)

    def test_btree_walk_counts_key_compares(self):
        keys = tuple(bytes([0x40 + (n >> 4)]) + bytes(17) + bytes([n & 255, 2 * n & 255]) for n in range(40))
        for target in (keys[0], keys[17], keys[39]):
            world = tool.blank_world(tool.RAW_BASE + 20, target, 0)
            world["locks"] = {"chain3": (0, ()), "other": (0, keys)}
            out, _, compares = self.gate.run(world, tool.GATES[0])
            found, want = tool.tree_search(keys, target)
            self.assertTrue(found)
            self.assertEqual(compares, want)
            self.assertGreater(compares, 0)


class Controls(Fixture):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_address_checks(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.GATES[0] + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x100)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)

    def test_every_rule_list_flaw_differs_from_the_bytes_somewhere(self):
        for flaw in tool.MODEL_FLAWS:
            hit = any(tool.flawed_gate(entry, world, self.table, flaw) != tool.spec_gate(entry, world, self.table) for _, entry, world in self.cases)
            self.assertTrue(hit, flaw)

    def test_byte_edits_are_killed_on_chosen_sites(self):
        tool.STATE.update(image=self.image, table=self.table, cases=self.cases, cache=self.gate.machine.cache)
        sites = ((0x2BDB26E, tool.GATES[0]), (0x2BDB2B6, tool.GATES[0]), (0x4D907F7, tool.GATES[1]), (0x4D90836, tool.GATES[1]))
        killed = 0
        for va, entry in sites:
            low, high = self.image.exact_fde(entry)
            decoded = [row for row in tool.decode_range(self.image, low, high) if row.va == va]
            self.assertEqual(len(decoded), 1, hex(va))
            edits = tool.edits_for(self.image, decoded)
            self.assertEqual(len(edits), 1, hex(va))
            tool.STATE["reach"] = {va: [i for i, case in enumerate(self.cases) if case[1] == entry][::13]}
            killed += tool.mutant_task(edits[0])[2] == "killed"
        self.assertEqual(killed, len(sites))

    def test_patched_tag_threshold_changes_the_result(self):
        # the sub $0x86 immediate of the class getter: moving it by one shifts every raw word
        patch = {tool.CLASS_GETTER + 5: 0x87}
        shifted = tool.Gate(self.image, patch)
        words = [shifted.run_class(word) for word in range(tool.RAW_BASE, tool.RAW_BASE + 8)]
        self.assertNotEqual(words, self.table[:8])


class StageAndSearch(Fixture):
    def user_worlds(self):
        for kind, entry, world in self.cases:
            if kind == "user_inline" and entry == tool.GATES[0]:
                yield world

    def test_outlined_helper_agrees_with_the_inline_stage(self):
        helper = 0x55FEDB0
        for number, world in enumerate(self.user_worlds()):
            if number % 9:
                continue
            out, _, _ = self.gate.run(world, tool.GATES[0])
            self.gate.prepare(world, tool.GATES[0])
            self.gate.machine.run(helper, {tool.RDI: tool.OUT_AT, tool.RSI: tool.EX_AT, tool.RDX: tool.SIGNER_AT})
            again = self.gate.data(tool.OUT_AT, 22)
            self.assertEqual(again, out[:22], number)

    def test_outlined_failure_copies_untouched_stack(self):
        world = tool.blank_world(tool.RAW_BASE, tool.sig(3))
        out, _, _ = self.gate.run(world, tool.GATES[1])
        self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_UNKNOWN_USER)
        self.assertEqual(out[2:22], tool.sig(3))
        self.assertEqual(out[22:0x70], bytes([tool.STACK_MARK_BYTE]) * (0x70 - 22))
        self.assertEqual(out[0x70:], bytes([tool.OUT_FILL]) * (tool.OUT_SIZE - 0x70))

    def test_outlined_success_leaves_the_rest_of_the_record(self):
        signer = tool.sig(4)
        world = tool.blank_world(tool.RAW_BASE, signer)
        world["users"] = [(signer, bytes(range(1, 21)))]
        out, log, _ = self.gate.run(world, tool.GATES[1])
        self.assertEqual((struct.unpack_from("<H", out)[0], out[2:22]), (tool.STATUS_OK, bytes(range(1, 21))))
        self.assertEqual(out[22:], bytes([tool.OUT_FILL]) * (tool.OUT_SIZE - 22))
        self.assertEqual(log, (("user_get", tool.tag4(signer)),))

    def test_search_record_names_flag_height_index_and_node(self):
        keys = tuple(bytes(18) + bytes([n >> 8, n & 255]) for n in range(1, 41))
        for probe, want_flag in ((keys[0], 0), (keys[20], 0), (keys[39], 0), (bytes(20), 1), (b"\xff" * 20, 1), (keys[5][:19] + b"\x7f", 1)):
            world = dict(keys=keys, key=probe)
            got = self.gate.run_search(world)
            self.assertEqual(got, tool.spec_search(world))
            self.assertEqual(got[3], want_flag)
            self.assertLessEqual(got[5], got[6])

    def test_search_over_a_tall_set_descends_once(self):
        keys = tuple(bytes(18) + bytes([n >> 8, n & 255]) for n in range(1, 101))
        root, height = tool.layout(keys)
        self.assertEqual(height, 1)
        got = self.gate.run_search(dict(keys=keys, key=keys[99]))
        self.assertEqual((got[3], got[4]), (0, 0))
        got = self.gate.run_search(dict(keys=keys, key=sorted(keys)[0]))
        self.assertEqual(got[3], 0)

    def test_search_cases_cover_found_and_absent(self):
        labels = {tool.case_label(self.gate.run_search(world)) for kind, entry, world in self.cases if kind == "btree_direct"}
        self.assertEqual(labels, {"found", "absent"})

    def test_scope_table_is_inside_the_fdes(self):
        for target in tool.SCOPE:
            low, high = self.image.exact_fde(target)
            self.assertEqual(low, target)
            self.assertGreater(high - low, 0)
        self.assertEqual(sum(1 for role in tool.SCOPE.values() if role[1] == "real"), 5)

    def test_listed_addresses_are_consecutive_rows(self):
        self.assertEqual(tool.OTHER_LISTED_AT[1] - tool.OTHER_LISTED_AT[0], 20)
        self.assertEqual(tool.OTHER_LISTED_AT[2] - tool.OTHER_LISTED_AT[1], 20)
        self.assertEqual(len(set(self.listed)), 3)


class EveryWord(Fixture):
    def test_every_table_word_has_the_class_status_in_both_gates(self):
        signer = tool.sig(11)
        want = {0: tool.STATUS_NOT_VALIDATOR, 1: tool.STATUS_NOT_VALIDATOR, 2: tool.STATUS_OK, 3: tool.STATUS_UNKNOWN_USER, 4: tool.STATUS_REFUSED}
        for entry in tool.GATES:
            for index in range(tool.CLASS_COUNT):
                world = tool.blank_world(tool.RAW_BASE + index, signer)
                out, _, _ = self.gate.run(world, entry)
                self.assertEqual(struct.unpack_from("<H", out)[0], want[self.table[index]], (hex(entry), index))

    def test_validator_wins_over_every_class_but_refusal(self):
        signer = tool.sig(12)
        for entry in tool.GATES:
            for index in range(tool.CLASS_COUNT):
                world = tool.blank_world(tool.RAW_BASE + index, signer)
                world["validators"] = frozenset([signer])
                out, log, _ = self.gate.run(world, entry)
                status = struct.unpack_from("<H", out)[0]
                if self.table[index] == 4:
                    self.assertEqual(status, tool.STATUS_REFUSED)
                elif self.table[index] in (0, 1):
                    self.assertEqual((status, log), (tool.STATUS_OK, (("validator", tool.tag4(signer)),)))
                else:
                    self.assertEqual(log[:1] != (("validator", tool.tag4(signer)),), True)

    def test_empty_once_set_fails_after_the_once_call(self):
        signer = tool.sig(13)
        for entry in tool.GATES:
            world = tool.blank_world(tool.RAW_BASE + 20, signer, 3)
            world["locks"] = {"chain3": (1, ()), "other": (0, (signer,))}
            out, log, compares = self.gate.run(world, entry)
            self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_NOT_VALIDATOR)
            self.assertEqual(log, (("validator", tool.tag4(signer)), ("once", "chain3")))
            self.assertEqual(compares, 0)

    def test_selected_set_height_is_the_one_searched(self):
        tall = tuple(bytes([0x40 + (n >> 4)]) + bytes(17) + bytes([n & 255, 2 * n & 255]) for n in range(40))
        short = tuple(bytes([0x60]) + bytes(17) + bytes([n, 1]) for n in range(3))
        for chain, names in ((3, ("chain3", "other")), (0, ("other", "chain3"))):
            world = tool.blank_world(tool.RAW_BASE + 20, tall[39], chain)
            world["locks"] = {names[0]: (0, tall), names[1]: (0, short)}
            for entry in tool.GATES:
                out, _, _ = self.gate.run(world, entry)
                self.assertEqual(struct.unpack_from("<H", out)[0], tool.STATUS_OK, (chain, hex(entry)))

    def test_scenario_rows_replay(self):
        rows = [line.split("\t") for line in (EVIDENCE / "scenarios.tsv").read_text().splitlines()[1:]]
        self.assertGreater(len(rows), 2000)
        for row in rows[::40]:
            index = int(row[0])
            kind, entry, world = self.cases[index]
            got, want = tool.run_case(self.gate, entry, world, self.table)
            self.assertEqual(got, want)
            self.assertEqual((row[1], tool.case_label(got), int(row[8])), (kind, row[6], got[2]))

    def test_controls_file_has_no_undetected_row(self):
        rows = [line.split("\t") for line in (EVIDENCE / "controls.tsv").read_text().splitlines()[1:]]
        self.assertEqual(len(rows), 216)
        self.assertTrue(all(row[2] == "True" for row in rows))
        kinds = {row[0] for row in rows}
        self.assertEqual(kinds, {"table_byte_damaged", "rule_list_flaw", "byte_edit", "out_of_range"})


class Regeneration(Fixture):
    def test_files_match_the_tool_output(self):
        files = tool.render(tool.analyse(self.image), self.image)
        for name, text in files.items():
            self.assertEqual((EVIDENCE / name).read_bytes(), text.encode("ascii"), name)
        manifest = (EVIDENCE / "MANIFEST.sha256").read_text().splitlines()
        for line in manifest:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest, name)

    def test_measure_counts_agree_with_the_evidence(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        summary = json.loads((EVIDENCE / "evidence.json").read_text())
        self.assertEqual(measure["negative_controls"], summary["controls"])
        self.assertEqual(measure["negative_detected"], summary["controls_detected"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertEqual(summary["byte_edits_survived"], 0)


if __name__ == "__main__":
    unittest.main()
