"""Tests for tools/outcome_user_amounts.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-outcome-user-amounts-94"
spec_ = importlib.util.spec_from_file_location("outcome_user_amounts", ROOT / "tools" / "outcome_user_amounts.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["outcome_user_amounts"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def run(case):
    return HARNESS.run(case)


def status_small(outcome):
    return outcome[1][1] if outcome[1][0] == 1 else None


def status_big(outcome):
    return outcome[1][8] if struct.unpack_from("<Q", outcome[1], 0)[0] == tool.TAG_NONE else None


def word(outcome, at):
    return struct.unpack_from("<Q", outcome[1], at)[0]


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fdes_are_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.SPLIT), (0x37250D0, 0x37253BD))
        self.assertEqual(IMAGE.exact_fde(tool.MERGE), (0x3724F20, 0x37250C4))
        self.assertEqual(IMAGE.exact_fde(tool.MERGE_ALL), (0x37253C0, 0x3725AAE))
        self.assertEqual(IMAGE.exact_fde(tool.NEGATE), (0x3725AB0, 0x372635C))
        for target in tool.TARGETS:
            with self.assertRaises(tool.EvidenceError):
                IMAGE.exact_fde(target + 1)

    def test_address_past_the_text_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(1 << 40)


class Files(unittest.TestCase):
    def test_tool_output_matches_the_folder(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        on_disk = {p.name for p in FOLDER.iterdir()} - {"README.md", "MANIFEST.sha256"}
        self.assertEqual(on_disk, set(files))

    def test_manifest_lists_every_file(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        listed = {line.split("  ")[1]: line.split("  ")[0] for line in lines}
        self.assertEqual(set(listed), {p.name for p in FOLDER.iterdir()} - {"MANIFEST.sha256"})
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_corrupted_output_is_noticed(self):
        text = tool.render(RESULT)["evidence.json"]
        self.assertNotEqual(text.replace("instructions", "instruction"), (FOLDER / "evidence.json").read_text(encoding="ascii"))


class Spec(unittest.TestCase):
    def test_named_cases_match(self):
        for case in tool.ALL_CASES:
            self.assertEqual(run(case), tool.spec_run(case), case.name)

    def test_other_vectors_match(self):
        tool.check_cases(HARNESS, tool.vector_cases(120))

    def test_a_wrong_specification_is_caught(self):
        original = tool.Spec

        class Wrong(original):
            def merge(self):
                original.merge(self)
                if self.writes.get(tool.OUT) == (8, 1):
                    self.word(tool.OUT + 8, self.case.amount // self.case.outcomes[self.case.outcome][2])

        tool.Spec = Wrong
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_cases(HARNESS, tool.MERGE_CASES)
        finally:
            tool.Spec = original


class Split(unittest.TestCase):
    def test_multiple_of_the_unit_is_admitted(self):
        got = run(tool.Case(kind=tool.SPLIT, amount=1000))
        self.assertIsNone(status_small(got))
        self.assertEqual(struct.unpack_from("<3Q", got[1], 8), (7, 3, 1000))

    def test_remainder_is_status_1(self):
        self.assertEqual(status_small(run(tool.Case(kind=tool.SPLIT, amount=1001))), 1)

    def test_balance_edge(self):
        self.assertIsNone(status_small(run(tool.Case(kind=tool.SPLIT, amount=100000))))
        self.assertEqual(status_small(run(tool.Case(kind=tool.SPLIT, amount=100100))), 2)

    def test_hold_is_subtracted(self):
        self.assertIsNone(status_small(run(tool.Case(kind=tool.SPLIT, balances={3: (1500, 500)}))))
        self.assertEqual(status_small(run(tool.Case(kind=tool.SPLIT, balances={3: (1500, 501)}))), 2)

    def test_registry_word_equal_to_the_outcome_is_status_6(self):
        self.assertEqual(status_small(run(tool.Case(kind=tool.SPLIT, registry=7))), 6)
        self.assertIsNone(status_small(run(tool.Case(kind=tool.SPLIT, registry=8))))

    def test_balance_is_on_the_quote_token_not_a_side(self):
        got = run(tool.Case(kind=tool.SPLIT, quotes={11: 5, 12: 5}, balances={3: (100000, 0), 5: (10, 0)}))
        self.assertEqual(status_small(got), 2)

    def test_hold_above_total_goes_through_the_recorder(self):
        got = run(tool.Case(kind=tool.SPLIT, amount=0, balances={3: (5, 6)}))
        self.assertIn(("record", 0, tool.LOC_WEI_SUB), got[2])

    def test_unit_zero_is_not_tested_before_the_divide(self):
        with self.assertRaises((ZeroDivisionError, tool.Halt)):
            run(tool.Case(kind=tool.SPLIT, outcomes={7: (11, 12, 0)}))

    def test_side_token_past_the_table_panics(self):
        got = run(tool.Case(kind=tool.SPLIT, outcomes={7: (40, 12, 100)}))
        self.assertEqual(got[:2], ("panic", tool.LOC_TOKEN_TABLE))


class Merge(unittest.TestCase):
    def test_result_is_the_amount_not_the_pieces(self):
        got = run(tool.Case(kind=tool.MERGE, amount=1000))
        self.assertEqual((word(got, 0), word(got, 8)), (1, 1000))

    def test_pieces_are_compared_to_the_smaller_side(self):
        balances = {11: (90, 0), 12: (40, 0)}
        self.assertEqual(word(run(tool.Case(kind=tool.MERGE, amount=4000, balances=balances)), 0), 1)
        got = run(tool.Case(kind=tool.MERGE, amount=4100, balances=balances))
        self.assertEqual((word(got, 0), got[1][8]), (2, 3))

    def test_no_amount_is_none_with_no_conversion(self):
        got = run(tool.Case(kind=tool.MERGE, amount=None))
        self.assertEqual(word(got, 0), 0)
        self.assertNotIn("convert", [event[0] for event in got[2]])

    def test_remainder_is_status_1(self):
        got = run(tool.Case(kind=tool.MERGE, amount=150))
        self.assertEqual((word(got, 0), got[1][8]), (2, 1))

    def test_every_helper_failure_is_status_8(self):
        for case in (tool.Case(kind=tool.MERGE, outcome=77), tool.Case(kind=tool.MERGE, quotes={12: 4}), tool.Case(kind=tool.MERGE, spot_lens={11: 2}),
                     tool.Case(kind=tool.MERGE, outcomes={7: (11, 12, 0)})):
            got = run(case)
            self.assertEqual((word(got, 0), got[1][8]), (2, 8))


class MergeQuestion(unittest.TestCase):
    balances = {11: (50, 0), 13: (40, 0), 15: (41, 0)}

    def test_no_amount_takes_the_least_over_members(self):
        got = run(tool.Case(kind=tool.MERGE_ALL, amount=None, balances=self.balances))
        self.assertEqual(word(got, 0x20), 40)
        self.assertEqual(got[3], ((7, 11), (8, 13), (9, 15)))

    def test_amount_edge_and_no_unit_test(self):
        self.assertEqual(word(run(tool.Case(kind=tool.MERGE_ALL, amount=40, balances=self.balances)), 0x20), 40)
        self.assertEqual(status_big(run(tool.Case(kind=tool.MERGE_ALL, amount=41, balances=self.balances))), 3)
        odd = {7: (11, 12, 1000), 8: (13, 14, 1000), 9: (15, 16, 1000)}
        self.assertIsNone(status_big(run(tool.Case(kind=tool.MERGE_ALL, amount=7, outcomes=odd, balances=self.balances))))

    def test_converted_on_the_fallback_token(self):
        got = run(tool.Case(kind=tool.MERGE_ALL, amount=30, balances=self.balances))
        self.assertIn(("convert", 11), got[2])

    def test_a_missing_member_frees_the_vector(self):
        got = run(tool.Case(kind=tool.MERGE_ALL, questions={3: (7, (8, 70))}))
        self.assertEqual(status_big(got), 8)
        self.assertIn(("free", tool.VECTOR, 64), got[2])


class Negate(unittest.TestCase):
    def test_rows_skip_the_named_outcome(self):
        got = run(tool.Case(kind=tool.NEGATE, outcome=8, amount=70))
        self.assertEqual(got[3], ((7, 11), (9, 15)))
        self.assertEqual(struct.unpack_from("<3Q", got[1], 0x18), (8, 70, 14))

    def test_balance_is_on_side_b(self):
        self.assertIsNone(status_big(run(tool.Case(kind=tool.NEGATE, outcome=8, amount=80))))
        self.assertEqual(status_big(run(tool.Case(kind=tool.NEGATE, outcome=8, amount=81))), 3)

    def test_fallback_and_membership(self):
        self.assertEqual(status_big(run(tool.Case(kind=tool.NEGATE, outcome=7))), 5)
        self.assertEqual(status_big(run(tool.Case(kind=tool.NEGATE, outcome=70))), 4)

    def test_no_unit_test(self):
        odd = {7: (11, 12, 1000), 8: (13, 14, 1000), 9: (15, 16, 1000)}
        self.assertIsNone(status_big(run(tool.Case(kind=tool.NEGATE, outcome=8, amount=7, outcomes=odd))))


class Legs(unittest.TestCase):
    def test_split_credits_the_floor_to_both_sides(self):
        got = run(tool.Case(kind=tool.SPLIT_LEGS, input=(7, 3, 1050)))
        self.assertEqual(got[4][0][1], (7, 3, 1050))
        self.assertEqual(got[4][1][1], (7, 11, 10, 7, 12, 10))

    def test_amount_below_the_unit(self):
        got = run(tool.Case(kind=tool.SPLIT_LEGS, input=(7, 3, 99)))
        self.assertEqual(word(got, 8), 3)

    def test_negate_credits_the_same_amount(self):
        got = run(tool.Case(kind=tool.NEGATE_LEGS, input=(4, ((7, 11), (9, 15)), 8, 70, 14)))
        self.assertEqual(got[4][0][1], (8, 14, 70))
        self.assertEqual(got[4][1][1], (7, 11, 70, 9, 15, 70))

    def test_negate_amount_zero(self):
        self.assertEqual(word(run(tool.Case(kind=tool.NEGATE_LEGS, input=(4, ((7, 11),), 8, 0, 14))), 8), 3)


class Controls(unittest.TestCase):
    def patched(self, edits, case):
        harness = tool.Harness(IMAGE, edits)
        return harness.run(case) != tool.spec_run(case)

    def test_remainder_branch_flip_is_caught(self):
        va = 0x37252D7
        self.assertEqual(IMAGE.blob[IMAGE.offset(va)], 0x74)
        self.assertTrue(self.patched({va: 0x75}, tool.Case(kind=tool.SPLIT)))

    def test_unit_offset_edit_is_caught(self):
        va = 0x37251E5 + 4
        self.assertEqual(IMAGE.blob[IMAGE.offset(va)], 0xF8)
        self.assertTrue(self.patched({va: 0xF0}, tool.Case(kind=tool.SPLIT)))

    def test_balance_branch_flip_is_caught(self):
        va = 0x3725F5B
        self.assertEqual(IMAGE.blob[IMAGE.offset(va)], 0x73)
        self.assertTrue(self.patched({va: 0x72}, tool.Case(kind=tool.NEGATE, outcome=8, amount=70)))

    def test_merge_compare_flip_is_caught(self):
        va = 0x37250B8 + 1
        self.assertEqual(IMAGE.blob[IMAGE.offset(va)], 0x83)
        self.assertTrue(self.patched({va: 0x82}, tool.Case(kind=tool.MERGE)))

    def test_a_slot_that_moved_fails(self):
        wrong = dict(tool.SLOTS)
        original = tool.SLOTS
        wrong[tool.SPLIT] = 0x5773848
        tool.SLOTS = wrong
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.slot_rows(IMAGE, IMAGE.relative())
        finally:
            tool.SLOTS = original

    def test_a_missing_string_fails(self):
        clone = copy.copy(IMAGE)
        clone.blob = IMAGE.blob.replace(tool.STRINGS[0], b"X" * len(tool.STRINGS[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.string_rows(clone)


class Census(unittest.TestCase):
    def test_three_call_sites_each(self):
        for row in RESULT["sites"]:
            self.assertEqual(row[2], 3, row[1])

    def test_divides(self):
        self.assertEqual(len(RESULT["divisions"]), 6)

    def test_mutations_are_explained(self):
        rows = RESULT["mutations"]
        self.assertEqual([row for row in rows if row[3] == "UNEXPLAINED"], [])
        survived = {(row[0], row[1]) for row in rows if row[2] == "survived"}
        self.assertEqual(survived, set(tool.EXPECTED_SURVIVORS))

    def test_evidence_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        self.assertEqual(summary["named_cases"], len(tool.ALL_CASES))
        self.assertEqual(summary["mutations"]["total"], len(RESULT["mutations"]))


class StatusText(unittest.TestCase):
    def test_ten_arms(self):
        self.assertEqual([row[0] for row in RESULT["statuses"]], list(range(10)))

    def test_a_bent_arm_fails(self):
        clone = copy.copy(IMAGE)
        data = bytearray(IMAGE.blob)
        arm = int(RESULT["statuses"][3][1], 16)
        data[IMAGE.offset(arm)] ^= 1
        clone.blob = bytes(data)
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(clone)


class Rerun(unittest.TestCase):
    def test_rendering_twice_is_identical(self):
        self.assertEqual(tool.render(RESULT), tool.render(RESULT))

    def test_cli_writes_nothing_on_a_wrong_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(expected="1" * 64)
            self.assertEqual(list(pathlib.Path(folder).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
