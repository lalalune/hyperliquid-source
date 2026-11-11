import collections
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import staking_membership_request115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "staking-membership-request-115"


class RequestBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.sites = tool.bind(cls.image)
        cls.cases = list(tool.all_cases())
        tool.STATE.update(image=cls.image, cases=cls.cases)
        cls.ref = tool.Fwd(cls.image)

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

    def test_sites_are_read_from_bytes(self):
        self.assertEqual({name: site["store"] for name, site in self.sites.items()}, {"base": 0x3F08, "copy_a": 0x4A78, "copy_b": 0x3F08})
        self.assertEqual({name: site["cells"] for name, site in self.sites.items()},
                         {"base": (0x7D0, 0x7C8), "copy_a": (0x1340, 0x1338), "copy_b": (0x7D0, 0x7C8)})
        for site in self.sites.values():
            self.assertEqual((site["message"], site["length"], site["vtable"], site["location"]), (0x7D3212, 0x2B, 0x648C5F8, 0x648B990))
            self.assertEqual(site["place"], ("l1/src/dex_registry/clearinghouses.rs", 11, 29))

    def test_three_bodies_have_one_size(self):
        for _, entry in tool.BODIES:
            start, end = self.image.exact_fde(entry)
            self.assertEqual(end - start, tool.BODY_SIZE)
        rows = tool.body_rows(self.image)
        self.assertEqual({len(rows[name]) for name in rows}, {134})

    def test_sampled_cases_match_the_rule_list(self):
        seen = self.run_each(range(0, len(self.cases), 97))
        for label in ("ret:flag0", "ret:flag1", "panic:expect"):
            self.assertIn(label, seen)

    def test_missing_cell_ends_in_the_expect_failure(self):
        case = next(c for c in self.cases if c["s7d0"] == 0 and c["body"] == "copy_a")
        got = tool.Fwd(self.image).execute(case)
        self.assertEqual(got[0], "panic")
        self.assertEqual(got[1], (tool.UNWRAP_SLOT, 0x7D3212, 0x2B, 0x648C5F8, 0x648B990))
        self.assertEqual(got, tool.spec(case))

    def test_zero_address_is_never_flagged_but_a_tail_only_address_is(self):
        zero = next(c for c in self.cases if c["signer"] == bytes(20) and c["s7d0"] and c["body"] == "base")
        self.assertEqual(tool.outcome_label(zero, tool.spec(zero)), "ret:flag0")
        tail = next(c for c in self.cases if c["signer"][:16] == bytes(16) and any(c["signer"]) and c["s7d0"] and c["body"] == "base")
        got = tool.Fwd(self.image).execute(tail)
        self.assertEqual(tool.outcome_label(tail, got), "ret:flag1")

    def test_pair_comes_from_the_state_only_when_the_tag_is_two(self):
        base = next(c for c in self.cases if c["tag"] == 2 and c["s80"] == 1 and c["s7d0"] and c["body"] == "base")
        got = tool.Fwd(self.image).execute(base)
        request = got[2][-1][3]
        self.assertEqual(struct.unpack_from("<QQ", request, 0x28), (0, base["s88"]))
        other = next(c for c in self.cases if c["tag"] == 0 and c["s7d0"] and c["body"] == "base")
        request = tool.Fwd(self.image).execute(other)[2][-1][3]
        self.assertEqual(struct.unpack_from("<QQ", request, 0x28), (other["w0"], other["w1"]))

    def test_every_planted_wrong_rule_is_detected(self):
        for flaw in tool.FLAWS:
            self.assertTrue(tool.flaw_task(flaw)[1], flaw)

    def test_decoy_offset_changes_the_outcome(self):
        case = next(c for c in self.cases if c["body"] == "copy_a" and tool.spec(c) != tool.spec(c, "decoy_store"))
        moved = dict(case, store=case["other_store"])
        try:
            got = tool.Fwd(self.image).execute(moved)
        except (tool.Halt, tool.Panicked):
            return
        self.assertNotEqual(got, tool.spec(case))

    def test_damaged_site_bytes_are_refused_or_read_differently(self):
        for job in tool.damage_jobs(self.image):
            self.assertTrue(tool.damage_task(job)[2], job)

    def test_address_that_is_not_a_body_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.body_code(self.image, 0x2C54DE1)
        with self.assertRaises(tool.EvidenceError):
            tool.body_code(self.image, 0x2C54DE0 + 0x10)

    def test_stuck_machine_is_reported(self):
        ref = tool.Fwd(self.image)
        ref.machine.step_limit = 12
        with self.assertRaises(tool.Halt):
            ref.execute(self.cases[0])

    def test_flipped_condition_is_caught(self):
        case = next(c for c in self.cases if c["s7d0"] and c["tag"] == 2 and c["s80"] == 1 and c["body"] == "base" and c["signer"] != bytes(20))
        self.assertEqual(tool.Fwd(self.image).execute(case), tool.spec(case))
        flipped = self.image.blob[self.image.offset(0x2C54E8D)] ^ 1
        patched = tool.Fwd(self.image, {0x2C54E8D: flipped})
        self.assertNotEqual(patched.execute(case), tool.spec(case))

    def test_committed_evidence_agrees_with_itself(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        rows = [line.split("\t") for line in (FOLDER / "controls.tsv").read_text().splitlines()[1:]]
        killed = sum(1 for r in rows if r[0] == "edit" and r[2] == "killed")
        counted = [r for r in rows if r[0] != "edit"]
        self.assertEqual(measure["negative_controls"], len(counted) + killed)
        self.assertEqual(measure["negative_detected"], sum(1 for r in counted if r[2] == "detected") + killed)
        groups = [line.split("\t") for line in (FOLDER / "groups.tsv").read_text().splitlines()[1:]]
        self.assertEqual(measure["cases"], sum(int(r[2]) for r in groups))
        self.assertEqual(measure["cases"], len(self.cases))


if __name__ == "__main__":
    unittest.main()
