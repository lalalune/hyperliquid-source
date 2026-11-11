import collections
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_validator_reference115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "staking-validator-reference-115"


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.table = tool.bind(cls.image)
        cls.cases = list(tool.all_cases(cls.table))
        tool.STATE.update(image=cls.image, cases=cls.cases, table=cls.table)
        cls.ref = tool.Ref(cls.image)

    def run_each(self, indices):
        seen = collections.Counter()
        for index in indices:
            case = self.cases[index]
            got, want = tool.run_case(self.ref, case)
            self.assertEqual(got, want, "case %d %s %s" % (index, case["body"], case["label"]))
            seen[tool.outcome_label(case, got)] += 1
        return seen

    def test_digest_is_checked(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_dispatch_table_read_from_bytes(self):
        kinds = {variant: row[1:] for variant, row in self.table.items()}
        for variant in (0, 1, 4):
            self.assertEqual(kinds[variant], ("ok", None))
        self.assertEqual(kinds[2], ("index", 0x50))
        for variant in (3, 7, 9):
            self.assertEqual(kinds[variant], ("index", 0x20))
        self.assertEqual(kinds[5], ("mapped", 0x48))
        self.assertEqual(kinds[8], ("index", 0x60))
        self.assertEqual(kinds[10], ("scan", None))
        for variant in (6, 11, 12, 13, 14, 15):
            self.assertEqual(kinds[variant], ("index", 0x08))

    def test_damaged_table_entry_is_refused(self):
        blob = bytearray(self.image.blob)
        struct.pack_into("<i", blob, self.image.offset(tool.TABLE_AT + 4), 0x1234)
        with self.assertRaises(tool.EvidenceError):
            tool.dispatch_table(self.image, blob)

    def test_three_bodies_have_one_size(self):
        rows = tool.body_rows(self.image)
        self.assertEqual({name: len(rows[name]) for name in rows}, {"base": 181, "copy_a": 181, "copy_b": 181})
        for name, entry, _ in tool.BODIES:
            start, end = self.image.exact_fde(entry)
            self.assertEqual(end - start, tool.BODY_SIZE)

    def test_message_pointer_per_body(self):
        self.assertEqual(tool.TEXTS["base"], (0x60E77E, 0x26))
        self.assertEqual(tool.TEXTS["copy_a"], (0x92A398, 0x26))
        self.assertEqual(tool.TEXTS["copy_b"], (0x92A398, 0x26))

    def test_store_offset_differs_in_one_copy(self):
        self.assertEqual({name: store for name, _, store in tool.BODIES}, {"base": 0x3F08, "copy_a": 0x4A78, "copy_b": 0x3F08})

    def test_sampled_cases_match_the_rule_list(self):
        seen = self.run_each(range(0, len(self.cases), 29))
        for label in ("ret:0x1a2", "ret:0xef", "ret:0xee", "ret:0xfa", "ret:0x154", "ret:0x66"):
            self.assertIn(label, seen)

    def test_panic_and_allocation_failure_are_reached(self):
        wanted = {"panic:mapped": False, "alloc_error:index": False, "alloc_error:mapped": False}
        for index, case in enumerate(self.cases):
            label = case["label"]
            if label in ("map_past_rows", "match", "map_hit") and (label == "map_past_rows" or case["alloc_fail"]):
                got = self.run_each([index])
                for key in got:
                    if key in wanted:
                        wanted[key] = True
            if all(wanted.values()):
                break
        self.assertTrue(all(wanted.values()), wanted)

    def test_every_variant_and_body_has_cases(self):
        pairs = {(case["body"], case["variant"]) for case in self.cases}
        self.assertEqual(len(pairs), 3 * tool.TABLE_ENTRIES)

    def test_index_read_from_the_variant_field_only(self):
        case = next(c for c in self.cases if c["arm"] == "index" and c["label"] == "match" and c["field"] == 0x20)
        got, want = tool.run_case(self.ref, case)
        self.assertEqual(got, want)
        moved = dict(case, field=0x50)
        self.assertNotEqual(tool.Ref(self.image).execute(moved), tool.spec(moved))

    def test_zero_signer_never_authorizes(self):
        case = next(c for c in self.cases if c["label"] == "zero_match" and c["arm"] == "index")
        got, _ = tool.run_case(self.ref, case)
        self.assertEqual(struct.unpack_from("<H", got[2], 0)[0], tool.CODE_DENIED)

    def test_scan_requires_the_active_flag(self):
        case = next(c for c in self.cases if c["label"] == "scan_flag2_only")
        got, _ = tool.run_case(self.ref, case)
        self.assertEqual(struct.unpack_from("<H", got[2], 0)[0], tool.CODE_UNKNOWN)

    def test_map_cap_edges(self):
        edge = next(c for c in self.cases if c["label"] == "map_cap_edge")
        over = next(c for c in self.cases if c["label"] == "map_cap_over")
        for case, code in ((edge, None), (over, tool.CODE_CAP)):
            got, want = tool.run_case(self.ref, case)
            self.assertEqual(got, want)
            if code is not None:
                self.assertEqual(struct.unpack_from("<H", got[2], 0)[0], code)

    def test_decoy_store_is_never_read(self):
        case = next(c for c in self.cases if c["arm"] == "index" and c["label"] == "match" and tool.spec(c) != tool.spec(c, "decoy_store"))
        for body in tool.BODIES:
            moved = dict(case, body=body[0], entry=body[1], store=body[2], other_store=next(b[2] for b in tool.BODIES if b[2] != body[2]))
            self.assertEqual(tool.Ref(self.image).execute(moved), tool.spec(moved))

    def test_every_planted_rule_flaw_is_detected(self):
        for flaw in tool.FLAWS:
            name, detected, where = tool.flaw_task(flaw)
            self.assertTrue(detected, flaw)

    def test_byte_edits_are_killed(self):
        rows = tool.body_rows(self.image)
        picks = tool.edits_for(self.image, rows["base"])
        jobs = [(va, kind, patch, "base") for va, kind, patch in picks[:6]]
        tool.STATE.update(by_body={"base": self.cases[:2000:23]}, cache={})
        killed = [tool.mutant_task(job)[3] for job in jobs]
        self.assertEqual(killed.count("killed"), len(jobs))

    def test_unedited_bytes_survive_their_own_check(self):
        tool.STATE.update(by_body={"base": self.cases[:2000:23]}, cache={})
        va, kind, body, status, where = tool.mutant_task((0x2C58950, "none", {}, "base"))
        self.assertEqual(status, "survived")

    def test_damaged_dispatch_rule_is_detected(self):
        tool.STATE.update(subset=self.cases[::7])
        variant, other, detected, where = tool.table_task((8, 3))
        self.assertTrue(detected)
        variant, other, detected, where = tool.table_task((5, 3))
        self.assertTrue(detected)

    def test_range_controls_all_detected(self):
        rows = tool.range_controls(self.image)
        self.assertGreaterEqual(len(rows), 6)
        for name, detected, where in rows:
            self.assertTrue(detected, name)

    def test_machine_halts_instead_of_looping(self):
        ref = tool.Ref(self.image)
        ref.machine.step_limit = 9
        with self.assertRaises(tool.Halt):
            ref.execute(self.cases[5])

    def test_spec_is_deterministic(self):
        again = list(tool.all_cases(self.table))
        self.assertEqual(len(again), len(self.cases))
        self.assertEqual([tool.spec(c) for c in again[:300]], [tool.spec(c) for c in self.cases[:300]])

    def test_source_has_no_server_paths(self):
        text = pathlib.Path(tool.__file__).read_text()
        for prefix in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc"):
            self.assertNotIn("/" + prefix + "/", text)

    def test_committed_measure_matches_claims(self):
        self.assertTrue(FOLDER.exists())
        measure = json.loads((FOLDER / "measure.json").read_text())
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        self.assertEqual(measure["negative_detected"], measure["negative_controls"])
        self.assertEqual(measure["edits_survived"], 0)


if __name__ == "__main__":
    unittest.main()
