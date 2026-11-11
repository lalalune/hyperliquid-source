import collections
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_validator_nested_key115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "staking-validator-nested-key-115"


class NestedKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        tool.bind(cls.image)
        cls.cases = list(tool.all_cases())
        tool.STATE.update(image=cls.image, cases=cls.cases)
        cls.gate = tool.Gate(cls.image)

    def run_each(self, indices):
        seen = collections.Counter()
        for index in indices:
            case = self.cases[index]
            got, want = tool.run_case(self.gate, case)
            self.assertEqual(got, want, "case %d %s %s" % (index, case["body"], case["label"]))
            seen[tool.outcome_label(case, got)] += 1
        return seen

    def first(self, prefix, **fields):
        return next(c for c in self.cases if c["label"].startswith(prefix) and all(c[k] == v for k, v in fields.items()))

    def code(self, case):
        got, want = tool.run_case(self.gate, case)
        self.assertEqual(got, want)
        return struct.unpack_from("<H", got[2], 0)[0]

    def test_digest_is_checked(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_three_bodies_have_one_size(self):
        rows = tool.body_rows(self.image)
        self.assertEqual(len({len(rows[name]) for name in rows}), 1)
        for name, entry, _ in tool.BODIES:
            start, end = self.image.exact_fde(entry)
            self.assertEqual(end - start, tool.BODY_SIZE)

    def test_call_targets_read_from_bytes(self):
        self.assertEqual(tool.TARGETS["base"], (0x4716CC0, 0x45584B0, 0x2BFD360))
        self.assertEqual(tool.TARGETS["copy_a"][:2], (0x4716CC0, 0x45584B0))
        self.assertNotEqual(tool.TARGETS["copy_a"][2], tool.TARGETS["base"][2])
        self.assertNotEqual(tool.TARGETS["copy_b"][2], tool.TARGETS["copy_a"][2])
        self.assertEqual(set(tool.PANICS.values()), {0x64768D8})

    def test_store_offset_differs_in_one_copy(self):
        self.assertEqual({name: store for name, _, store in tool.BODIES}, {"base": 0x3F08, "copy_a": 0x3F08, "copy_b": 0x4A78})

    def test_sampled_cases_match_the_rule_list(self):
        seen = self.run_each(range(0, len(self.cases), 61))
        for label in ("ret:0x1a2:built", "ret:0xef", "ret:0x170", "ret:0x55:built", "panic"):
            self.assertIn(label, seen)

    def test_member_needs_inactive_row_and_outsider_needs_matching_active_row(self):
        denied = self.first("gate_outsider_flag0_same")
        self.assertEqual(self.code(denied), tool.CODE_DENIED)
        passes = self.first("gate_outsider_flag1_same")
        self.assertNotEqual(self.code(passes), tool.CODE_DENIED)
        near = self.first("gate_outsider_flag1_near")
        self.assertEqual(self.code(near), tool.CODE_DENIED)

    def test_zero_signer_takes_the_member_path(self):
        zero_inactive = self.first("gate_zero_flag0_same")
        self.assertNotEqual(self.code(zero_inactive), tool.CODE_DENIED)
        zero_active = self.first("gate_zero_flag1_same")
        self.assertEqual(self.code(zero_active), tool.CODE_DENIED)

    def test_row_index_out_of_range_panics_after_the_lookup(self):
        case = self.first("bounds_len")
        got, want = tool.run_case(self.gate, case)
        self.assertEqual(got[0], "panic")
        self.assertEqual(got, want)

    def test_key_absent_from_the_row_set(self):
        case = self.first("deep_miss12_between")
        self.assertEqual(self.code(case), tool.CODE_ABSENT)

    def test_tag_other_than_one_hides_the_set(self):
        case = self.first("deep_tag0_decoy_tree")
        self.assertEqual(self.code(case), tool.CODE_ABSENT)

    def test_builder_arguments_use_the_sentinel_rule(self):
        for sentinel in (1, 0):
            case = next(c for c in self.cases if c["label"].startswith("deep_has") and c["e80"] == 1 and (c["e88"] == c["index"]) == bool(sentinel)
                        and tool.spec(c)[3] and tool.spec(c)[3][-1][0] in ("build", "free"))
            got, want = tool.run_case(self.gate, case)
            build = next(item for item in got[3] if item[0] == "build")
            fields = build[2][5]
            self.assertEqual(fields[20], 0x22 if sentinel else 0x20)
            self.assertEqual(fields[32:40], b"\x22" * 8 if sentinel else struct.pack(">Q", case["index"]))

    def test_decoy_store_is_never_read(self):
        case = next(c for c in self.cases if c["label"].startswith("gate_world_flag0_same") and tool.spec(c) != tool.spec(c, "decoy_store"))
        for body in tool.BODIES:
            moved = dict(case, body=body[0], entry=body[1], store=body[2], other_store=next(b[2] for b in tool.BODIES if b[2] != body[2]))
            self.assertEqual(tool.Gate(self.image).execute(moved), tool.spec(moved))

    def test_every_planted_rule_flaw_is_detected(self):
        for flaw in tool.FLAWS:
            name, detected, where = tool.flaw_task(flaw)
            self.assertTrue(detected, flaw)

    def test_byte_edits_are_killed(self):
        rows = tool.body_rows(self.image)
        by_kind = collections.defaultdict(list)
        for va, kind, patch in tool.edits_for(self.image, rows["base"]):
            by_kind[kind].append((va, kind, patch, "base"))
        jobs = tool.round_robin_edits(by_kind)[:6]
        tool.STATE.update(by_body={"base": [c for c in self.cases[::9] if c["body"] == "base"]}, cache={})
        killed = [tool.mutant_task(job)[3] for job in jobs]
        self.assertEqual(killed.count("killed"), len(jobs))

    def test_unedited_bytes_survive_their_own_check(self):
        tool.STATE.update(by_body={"base": self.cases[:6192:7]}, cache={})
        va, kind, body, status, where = tool.mutant_task((0x2C58320, "none", {}, "base"))
        self.assertEqual(status, "survived")

    def test_range_controls_all_detected(self):
        rows = tool.range_controls(self.image)
        self.assertGreaterEqual(len(rows), 8)
        for name, detected, where in rows:
            self.assertTrue(detected, name)

    def test_machine_halts_instead_of_looping(self):
        gate = tool.Gate(self.image)
        gate.machine.step_limit = 9
        with self.assertRaises(tool.Halt):
            gate.execute(self.cases[5])

    def test_spec_is_deterministic(self):
        again = list(tool.all_cases())
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
