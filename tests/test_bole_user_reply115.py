import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_user_reply115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-004-bole-user-reply-115"
E14 = tool.E14
TOP = tool.TOP
# Files that do not depend on the number of pseudo-random vectors; the regeneration test rebuilds these with a short vector run.
STABLE = ("function-rows.tsv", "table-entries.tsv", "slots.tsv", "call-sites.tsv", "constants.tsv", "reply-samples.tsv", "outcomes.tsv",
          "model-variants.tsv", "structural-controls.tsv", "rust-vectors.tsv", "unreached-rows.tsv")


class UserReplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harnesses = {False: tool.Harness(cls.image), True: tool.Harness(cls.image)}
        cls.cases = tool.named_cases()
        cls.rows = tool.decode_range(cls.image, tool.ENTRY, tool.BODY_END)
        cls.regenerated = None

    def run_plain(self, case):
        layout, before, after, events, statics, panicked = self.harnesses[tool.injected(case)].run(case)
        words = struct.unpack_from("<5Q", after, tool.OUT - tool.HEAP_BASE)
        return words, after, events, panicked

    def reply(self, case):
        words, after, events, panicked = self.run_plain(case)
        self.assertFalse(panicked)
        self.assertEqual(words[0], tool.VTABLE)
        data = after[tool.ALLOCS - tool.HEAP_BASE:tool.ALLOCS - tool.HEAP_BASE + tool.REPLY_SIZE]
        self.assertTrue(all(not any(data[index * 32:index * 32 + 24]) for index in range(4)))
        return [int.from_bytes(data[index * 32 + 24:index * 32 + 32], "big") for index in range(4)]

    @staticmethod
    def codes(events):
        return [event for event in events if event[0] in ("fmt_a", "fmt_b")]

    # ----- identity of the input and the function -----

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "hl-node"
            path.write_bytes(b"\x7fELF" + bytes(100))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)

    def test_function_extent_and_decode(self):
        self.assertEqual(self.image.exact_fde(tool.ENTRY), (0x38E5D00, 0x38E64AC))
        self.assertEqual(len(self.rows), 361)
        self.assertEqual(self.rows[0].va, tool.ENTRY)
        self.assertEqual(self.rows[-1].op, "ud2")
        self.assertEqual(self.rows[-1].next, tool.BODY_END)
        for target in (tool.ENTRY + 1, tool.ENTRY - 1, tool.BODY_END):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(target)
        for start, end, name in tool.FUNCTIONS[1:]:
            rows = tool.decode_range(self.image, start, end)
            self.assertEqual((rows[0].va, rows[-1].next), (start, end), name)

    def test_table_entry_is_address_0811(self):
        rows = tool.table_rows(self.image)
        self.assertEqual(tool.TABLE_SLOT, 0x646E738)
        self.assertEqual(rows[1], ("0x646e738", "00" * 18 + "0811", "0x38e5d00"))
        self.assertEqual([row[1][-4:] for row in rows], ["0810", "0811", "0812"])
        self.assertEqual(self.image.relative()[0x646E738], 0x38E5D00)

    def test_only_the_table_slot_refers_to_the_body(self):
        base, text = self.image.text_bytes()
        hits = []
        for opcode in (b"\xe8", b"\xe9"):
            at = text.find(opcode)
            while 0 <= at <= len(text) - 5:
                if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == tool.ENTRY:
                    hits.append(base + at)
                at = text.find(opcode, at + 1)
        self.assertEqual(hits, [])
        self.assertEqual([slot for slot, addend in self.image.relative().items() if addend == tool.ENTRY], [tool.TABLE_SLOT])

    def test_slots_resolve_through_relocations(self):
        relative = self.image.relative()
        for slot, target in tool.SLOT_TARGETS.items():
            self.assertEqual(relative[slot], target, hex(slot))
        self.assertEqual(relative[tool.SLOT_USERS], tool.USERS)
        self.assertEqual(relative[tool.LAZY], tool.LAZY_INIT)
        rows = {row[0]: row for row in tool.slot_rows(self.image)}
        self.assertEqual(rows["0x64df480"], ("0x64df480", "R_X86_64_RELATIVE", "0x6355830"))
        self.assertEqual(rows["0x64e6498"][2], "0x369a210")
        self.assertEqual(rows["0x64dfb50"], ("0x64dfb50", "R_X86_64_GLOB_DAT", "memcmp"))
        self.assertEqual(rows["0x64fb8e8"][2], "3")
        sites = tool.site_rows({name: tool.decode_range(self.image, start, end) for start, end, name in tool.FUNCTIONS})
        slot_sites = {site[3] for site in sites if site[2] == "slot"}
        self.assertIn("0x64e6498", slot_sites)
        self.assertIn("0x64dfaf8", slot_sites)

    # ----- the bytes against the rule list -----

    def test_every_named_case_agrees_with_the_rule_list(self):
        self.assertEqual(len(self.cases), 699)
        self.assertEqual(len({case.name for case in self.cases}), len(self.cases))
        for case in self.cases:
            self.assertIsNone(tool.compare(self.harnesses[tool.injected(case)], case), case.name)

    def test_vectors_agree_with_the_rule_list(self):
        count = injected = 0
        for case in tool.vector_cases(500):
            self.assertIsNone(tool.compare(self.harnesses[tool.injected(case)], case), case.name)
            count += 1
            injected += tool.injected(case)
        self.assertEqual(count, 500)
        self.assertGreater(injected, 5)
        # the stream is deterministic: the same seed gives the same first vector
        first = [case.name for case in tool.vector_cases(3)]
        self.assertEqual(first, ["vector 0", "vector 1", "vector 2"])

    def test_every_wrong_reading_is_refused_by_a_real_disagreement(self):
        sample = self.cases + list(tool.vector_cases(400, seed=0x77))
        self.assertEqual(len(tool.VARIANTS), 39)
        self.assertEqual(len(tool.VARIANTS), len(set(tool.VARIANTS)))
        # variant_counts raises if the rule list raises under any variant, so every count is of real disagreements
        counts = tool.variant_counts(self.harnesses, sample)
        for name in tool.VARIANTS:
            self.assertGreater(counts[name][0], 0, name)
        # each reading the review found crash-only now disagrees on cases where the wrong reading reads fixture bytes, not a fault
        for name in ("user_ring_no_len", "user_ring_no_wrap", "umap_ring_no_len", "tag2_from_tag1"):
            self.assertGreater(counts[name][0] - counts[name][2], 0, name)
        # the unmodified reading is accepted on the same sample, without exceptions
        for case in sample:
            self.assertIsNone(tool.compare(self.harnesses[tool.injected(case)], case), case.name)

    def test_rule_list_does_not_raise_under_any_variant(self):
        for case in self.cases:
            layout = tool.Layout(case)
            for name in tool.VARIANTS:
                tool.spec(case, layout, frozenset((name,)))

    def test_structural_controls(self):
        rows = tool.structural_controls(self.image, self.harnesses[False], self.cases)
        self.assertEqual(len(rows), 14)
        kinds = [row[0] for row in rows]
        self.assertEqual((kinds.count("identification"), kinds.count("target bytes"), kinds.count("comparator self-test")), (8, 2, 4))
        self.assertTrue(all(outcome == "detected" for _, _, outcome in rows), rows)
        # the comparator accepts the untampered comparison that the self-tests corrupt
        probe = next(case for case in self.cases if case.name == "first half: index 1.5")
        self.assertIsNone(tool.judge(self.harnesses[False].run(probe), probe))

    def test_selected_byte_edits_are_noticed(self):
        kill = [case for case in self.cases if not tool.injected(case)]
        edits = {}
        for start, end, name in tool.FUNCTIONS:
            rows = tool.decode_range(self.image, start, end)
            edits[name] = {(va, kind): patch for va, kind, patch in tool.edits_for(self.image, rows, {row.va for row in rows})}
        # the input length limit (immediate and branch), the per-byte shift, and the first branch edit of each callee
        picks = [((0x38E5D14, "immediate"), "body"), ((0x38E5D1B, "condition"), "body"), ((0x38E5D23, "immediate"), "body")]
        for name in ("pairs", "users", "tree_search"):
            picks.append((next(key for key in edits[name] if key[1] == "condition"), name))
        self.assertEqual(len(picks), 6)
        for key, name in picks:
            patch = edits[name][key]
            self.assertEqual(len(patch), 1)
            harness = tool.Harness(self.image, patch)
            harness.machine.step_limit = 20000
            self.assertIsNotNone(tool.first_failure(harness, kill), "%s %#x" % (name, key[0]))
        # an unedited run with the same step limit passes
        control = tool.Harness(self.image)
        control.machine.step_limit = 20000
        self.assertIsNone(tool.first_failure(control, kill[:200]))

    def test_surviving_edits_are_classified_with_reasons(self):
        self.assertEqual(len(tool.EQUIVALENT), 11)
        self.assertEqual(len(tool.STUB_DEPENDENT), 8)
        self.assertEqual(set(tool.EQUIVALENT) & set(tool.STUB_DEPENDENT), set())
        existing = {}
        for start, end, name in tool.FUNCTIONS:
            rows = tool.decode_range(self.image, start, end)
            for va, kind, patch in tool.edits_for(self.image, rows, {row.va for row in rows}):
                existing[(va, kind)] = (name, patch)
        for table in (tool.EQUIVALENT, tool.STUB_DEPENDENT):
            for key, reason in table.items():
                self.assertIn(key, existing, "%#x %s is not an edit of the four functions" % key)
                self.assertGreater(len(reason.strip()), 60, key)
        for key in tool.STUB_DEPENDENT:
            self.assertRegex(tool.STUB_DEPENDENT[key], r"0x(46de430|3d57b80|4556410|38f9750|64e9570)")
        # the review's counterexample: these flag-read edits read v10 at rsp+0x20, and a consistent case kills them
        consistent = [case for case in self.cases if not tool.injected(case)]
        for va in (0x46DF1DF, 0x46DF29F):
            self.assertNotIn((va, "displacement"), tool.EQUIVALENT)
            self.assertNotIn((va, "displacement"), tool.STUB_DEPENDENT)
            harness = tool.Harness(self.image, existing[(va, "displacement")][1])
            harness.machine.step_limit = 20000
            self.assertIsNotNone(tool.first_failure(harness, consistent), hex(va))
        committed = [line.split("\t") for line in (WORK / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        outcomes = {}
        for row in committed:
            outcomes[row[3]] = outcomes.get(row[3], 0) + 1
            key = (int(row[1], 16), row[2])
            if row[3] == "equivalent":
                self.assertEqual(row[4], tool.EQUIVALENT[key])
            elif row[3] == "stub_dependent":
                self.assertEqual(row[4], tool.STUB_DEPENDENT[key])
            else:
                self.assertEqual(row[3], "killed", row)
        self.assertEqual(outcomes.get("equivalent"), 11)
        self.assertEqual(outcomes.get("stub_dependent"), 8)
        self.assertEqual(sum(outcomes.values()), 400)

    # ----- properties of the bytes, stated without the rule list -----

    def test_gas_boundaries(self):
        whole = 1000 + 33 * 32 + 33 * 128
        words, _, events, _ = self.run_plain(tool.Case("exact", gas=whole))
        self.assertEqual((words[0], words[4]), (tool.VTABLE, whole))
        words, _, events, _ = self.run_plain(tool.Case("short", gas=whole - 1))
        self.assertEqual((words[0], words[1]), (0, 0x8000000000000001))
        self.assertEqual(events[-1], ("bytes_drop", 128))
        first = 1000 + 33 * 32
        words, _, events, _ = self.run_plain(tool.Case("first charge exactly", gas=first))
        self.assertEqual((words[0], words[1], events[-1]), (0, 0x8000000000000001, ("bytes_drop", 128)))
        words, _, events, _ = self.run_plain(tool.Case("one below the first charge", gas=first - 1))
        self.assertEqual((words[0], words[1], events), (0, 0x8000000000000001, []))
        words, _, events, _ = self.run_plain(tool.Case("too long", input_len=2001, gas=TOP))
        self.assertEqual((words[0], words[1], events), (0, 0x8000000000000001, []))
        words, _, events, _ = self.run_plain(tool.Case("longest", input_len=2000, gas=TOP))
        self.assertEqual((words[0], words[4]), (tool.VTABLE, 1000 + 33 * 2000 + 33 * 128))

    def test_refused_parse_gives_the_text(self):
        words, after, events, panicked = self.run_plain(tool.Case("bad", parse=("err", 4)))
        self.assertFalse(panicked)
        self.assertEqual(words[:4], (0, 13, tool.ALLOCS, 13))
        self.assertEqual(after[tool.ALLOCS - tool.HEAP_BASE:tool.ALLOCS - tool.HEAP_BASE + 13], b"Invalid input")
        self.assertEqual(tool.TEXT, b"Invalid input")
        self.assertEqual([event[0] for event in events], ["parse", "drop_parse", "alloc"])
        self.assertEqual(events[-1], ("alloc", 13))

    def test_refusal_codes(self):
        _, _, events, _ = self.run_plain(tool.Case("count", parse=("ok", 9), count=9, keys=[9]))
        self.assertEqual(events[1:], [("fmt_a", 0xFA, 9, 0), ("drop_code",)])
        _, _, events, _ = self.run_plain(tool.Case("token above count", parse=("ok", 12), count=9, keys=[12]))
        self.assertEqual(events[1:], [("fmt_a", 0xFA, 12, 0), ("drop_code",)])
        _, _, events, _ = self.run_plain(tool.Case("token just below count", parse=("ok", 8), count=9, keys=[8], umap_keys=[8]))
        self.assertEqual(self.codes(events), [])
        _, _, events, _ = self.run_plain(tool.Case("token missing", parse=("ok", 9), keys=[7, 11]))
        self.assertEqual(events[1:], [("fmt_a", 0xF1, 0, 0), ("drop_code",)])
        words, _, events, _ = self.run_plain(tool.Case("user entry missing", user_keys=[]))
        self.assertEqual(self.codes(events), [("fmt_b", 0xF1, 0)])
        self.assertEqual(words[0], 0)
        self.assertEqual(words[1:4], tool.fmt_words(0xF1, 0))
        _, _, events, _ = self.run_plain(tool.Case("token absent from the key's map", umap_keys=[8]))
        self.assertEqual(self.codes(events), [("fmt_b", 0xF1, 0)])

    def test_reply_words_of_a_worked_example(self):
        value = (0x0102030405060708, 7 * 10 ** 14 + 123, 0x1112131415161718, 9 * 10 ** 13 + 5)
        rec = (3 * 10 ** 13 + 5, 25 * 10 ** 13 + 77)
        expected = [value[0], value[1] * rec[0] // E14, value[2], value[3] * rec[1] // E14]
        # by hand: (7e14+123)(3e13+5) = 2.1e28 + 7.19e15 + 615, over 1e14 is 210000000000071.9; the second is 225000000000081.8
        self.assertEqual(expected[1], 210000000000071)
        self.assertEqual(expected[3], 225000000000081)
        for product in (value[1] * rec[0], value[3] * rec[1]):
            self.assertLess(product >> 64, E14)
        self.assertEqual(self.reply(tool.Case("worked", value=value, rec=rec)), expected)

    def test_tag_clears_both_words_when_the_high_half_reaches_the_guard(self):
        value = (111, 1 << 63, 222, 5 * E14)
        rec = (2 * E14, E14)
        self.assertEqual((value[1] * rec[0]) >> 64, E14)  # exactly at the guard: cleared
        self.assertEqual(self.reply(tool.Case("first cleared", value=value, rec=rec)), [0, 0, 222, 5 * E14])
        below = (111, (1 << 63) - 1, 222, 5 * E14)
        self.assertLess((below[1] * rec[0]) >> 64, E14)
        self.assertEqual(self.reply(tool.Case("first kept", value=below, rec=rec)), [111, below[1] * rec[0] // E14 & TOP, 222, 5 * E14])
        value = (111, 5 * E14, 222, 1 << 63)
        self.assertEqual(self.reply(tool.Case("second cleared", value=value, rec=(E14, 2 * E14))), [111, 5 * E14, 0, 0])
        value = (111, TOP, 222, TOP)
        self.assertEqual(self.reply(tool.Case("both cleared", value=value, rec=(TOP, TOP))), [0, 0, 0, 0])

    def test_pair_value_is_floored_not_ceiled(self):
        # 99 * (1e12 + 1) / 1e14 = 0.99000000000099: floor 0, ceiling 1
        value = (1, 99, 2, 10 ** 14 + 1)
        rec = (10 ** 12 + 1, E14 - 1)
        words = self.reply(tool.Case("floor", value=value, rec=rec))
        self.assertEqual(words, [1, 0, 2, (10 ** 14 + 1) * (E14 - 1) // E14])
        self.assertEqual(words[3], 99999999999999)  # (1e14+1)(1e14-1) = 1e28-1: floor 1e14-1, ceiling 1e14
        # exact multiples are not bumped
        self.assertEqual(self.reply(tool.Case("exact", value=(0, 3 * E14, 0, 0), rec=(E14, E14)))[1], 3 * E14)
        # the divide requests carry the exact product and 1e14
        _, _, events, _ = self.run_plain(tool.Case("events", value=value, rec=rec))
        self.assertEqual([event for event in events if event[0] == "div"], [("div", 99 * rec[0], E14), ("div", value[3] * rec[1], E14)])

    def test_missing_user_key_falls_to_the_empty_default(self):
        words, after, events, panicked = self.run_plain(tool.Case("missing", user_keys=[]))
        self.assertEqual(self.codes(events), [("fmt_b", 0xF1, 0)])
        self.assertEqual(words[0], 0)
        # the default map is the lazy static: it is searched at its address, and the once runs when its state is nonzero
        self.assertIn(("lookup_umap", 7, tool.LAZY), events)
        self.assertNotIn(("once",), events)
        _, _, events, _ = self.run_plain(tool.Case("missing before the once", user_keys=[], once=3))
        self.assertEqual(events.count(("once",)), 1)
        self.assertLess(events.index(("once",)), events.index(("lookup_umap", 7, tool.LAZY)))
        self.assertEqual(self.codes(events), [("fmt_b", 0xF1, 0)])
        # a present key never searches the lazy default
        _, _, events, _ = self.run_plain(tool.Case("present"))
        self.assertTrue(all(event[0] != "lookup_umap" or event[2] != tool.LAZY for event in events))

    def test_ring_search_flags(self):
        ring = [5, 9, 14, 20, 33, 41]

        def events(answers):
            return self.run_plain(tool.Case("ring", parse=("ok", 14), keys=ring, store=("ring", 8, 5), umap_keys=[14], tok_answers=answers))[2]
        self.assertEqual(self.codes(events([(2, 2), (0, 2), (0, 2)])), [("fmt_a", 0xF1, 0, 0)])  # first answer: any non-zero word refuses
        self.assertEqual(self.codes(events([(0, 2), (0, 2), (0, 2)])), [])
        self.assertEqual(self.codes(events([(0, 2), (1, 2), (0, 2)])), [])  # a missed first half drops the pair, the reply still follows
        self.assertEqual(events([(0, 2), (1, 2), (0, 2)])[-1][0], "bytes")

    def test_instruction_coverage(self):
        for case in self.cases:
            self.harnesses[tool.injected(case)].run(case)
        plain = set(self.harnesses[False].machine.seen)
        every = plain | set(self.harnesses[True].machine.seen)
        listed = [line.split("\t") for line in (WORK / "unreached-rows.tsv").read_text(encoding="ascii").splitlines()[1:]]
        never = {int(row[2], 16) for row in listed if row[0] == "not reached by any case"}
        injected_only = {int(row[2], 16) for row in listed if row[0] == "reached only with injected answers"}
        self.assertEqual(len(never), 4)
        self.assertEqual(len(injected_only), 13)  # the three allocation-failure paths, the multiply-overflow saturation, two half misses
        self.assertTrue(all(row[4] != "UNEXPLAINED" and row[4] for row in listed))
        missing = set()
        for start, end, name in tool.FUNCTIONS:
            for row in tool.decode_range(self.image, start, end):
                if row.op not in ("int3", "nop") and row.va not in every:
                    missing.add(row.va)
        self.assertEqual(missing, never)
        self.assertEqual(never, {0x38E63DB, 0x35BF4B4, 0x35BF4EB, 0x35BF4F0})
        for va in injected_only:
            self.assertIn(va, every)

    # ----- committed evidence -----

    def test_manifest_matches_committed_files(self):
        path = WORK / "MANIFEST.sha256"
        listed = {}
        for line in path.read_text().splitlines():
            digest, name = line.split("  ")
            self.assertNotIn(name, listed)
            listed[name] = digest
        packet = sorted(p.name for p in WORK.iterdir() if p.is_file() and p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), packet)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_committed_summary_is_consistent(self):
        summary = json.loads((WORK / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["named_cases"], len(self.cases))
        self.assertEqual(summary["model_variants"], len(tool.VARIANTS))
        self.assertEqual(summary["table"], {"slot": "0x646e738", "address_bytes": "00" * 18 + "0811"})
        mutations = summary["mutations"]
        self.assertEqual(mutations["total"], mutations["killed"] + mutations["equivalent"] + mutations["stub_dependent"])
        self.assertEqual((mutations["equivalent"], mutations["stub_dependent"]), (len(tool.EQUIVALENT), len(tool.STUB_DEPENDENT)))
        measure = json.loads((WORK / "measure.json").read_text())
        self.assertEqual(measure["cases"], summary["named_cases"] + summary["vector_cases"])
        self.assertEqual(measure["mismatches"], 0)
        self.assertEqual(measure["variants"], measure["variants_detected"])
        self.assertEqual(measure["structural_controls"], measure["structural_detected"])
        self.assertEqual(measure["comparator_self_tests"], measure["comparator_self_tests_detected"])
        self.assertEqual(measure["byte_edits"], measure["byte_edits_killed"] + measure["byte_edits_equivalent"] + measure["byte_edits_stub_dependent"])
        self.assertNotIn("negative_controls", measure)
        named_injected = sum(1 for case in self.cases if tool.injected(case))
        self.assertEqual(summary["named_cases_with_injected_answers"], named_injected)
        self.assertTrue(all(tool.injected(case) for case in self.cases if case.fail_alloc is not None or case.once not in (0, 3)))

    def test_committed_evidence_is_regenerated(self):
        files = tool.render(tool.analyse(self.image, vectors=1500, mutate=False))
        for name in STABLE:
            self.assertEqual(files[name], (WORK / name).read_text(encoding="ascii"), name)
        short = files["vector-outcomes.tsv"].splitlines()
        committed = (WORK / "vector-outcomes.tsv").read_text(encoding="ascii").splitlines()
        # every tenth vector is kept, so the short run is a prefix of the committed list
        self.assertEqual(len(short), 1 + 150)
        self.assertEqual(short, committed[:len(short)])
        self.assertGreater(len(committed), len(short))
        self.assertNotIn("mutations.tsv", files)


if __name__ == "__main__":
    unittest.main()
