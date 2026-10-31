"""Tests for tools/outcome_leg_pricing.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-outcome-leg-pricing-94"
spec_ = importlib.util.spec_from_file_location("outcome_leg_pricing", ROOT / "tools" / "outcome_leg_pricing.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["outcome_leg_pricing"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
FIRST = None
SECOND = None
RESULT = None


def setUpModule():
    global IMAGE, FIRST, SECOND, RESULT
    IMAGE = tool.load_image()
    FIRST = tool.Harness(IMAGE, 0)
    SECOND = tool.Harness(IMAGE, 1)
    RESULT = tool.analyse(IMAGE)


def edited(edits):
    """A copy of the image with file bytes replaced at virtual addresses."""
    clone = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    for va, value in edits.items():
        data[IMAGE.offset(va)] = value
    clone.blob = bytes(data)
    return clone


def byte_at(va):
    return IMAGE.blob[IMAGE.offset(va)]


def legs(outcome):
    return [event for event in outcome[2] if event[0] == "leg"]


def word(row, at):
    return struct.unpack_from("<Q", row, at)[0]


def named(text):
    return next(case for case in tool.NAMED if case.name == text)


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fde_is_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.TARGETS[0]), (0x4D17FA0, 0x4D18DBA))
        self.assertEqual(IMAGE.exact_fde(tool.TARGETS[1]), (0x4D18DC0, 0x4D19BDA))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.TARGETS[0] + 1)

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

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = {p.name for p in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        self.assertEqual({row.split("  ")[1] for row in rows}, names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_output_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            target = pathlib.Path(folder) / "out"
            original = tool.analyse
            tool.analyse = lambda image: RESULT
            try:
                self.assertEqual(tool.main(["--out", str(target)]), 0)
            finally:
                tool.analyse = original
            self.assertTrue((target / "evidence.json").is_file())


class Anchors(unittest.TestCase):
    def test_copies_differ_in_one_displacement(self):
        total, differ, calls = RESULT["copy"]
        self.assertEqual(total, 711)
        self.assertEqual(len(differ), 1)
        self.assertEqual(differ[0][:2], (0x4D18B00, 0x4D19920))
        self.assertEqual(struct.unpack("<i", bytes.fromhex(differ[0][2])[3:7])[0], 0x1372)
        self.assertEqual(struct.unpack("<i", bytes.fromhex(differ[0][3])[3:7])[0], 0x8F2)

    def test_copy_diff_sees_an_edit(self):
        at = 0x4D18BE4 + 7
        self.assertEqual(len(tool.copy_diff(edited({at: byte_at(at) ^ 8}))[1]), 2)

    def test_one_direct_caller_each(self):
        self.assertEqual(tool.direct_to(IMAGE, tool.TARGETS[0]), [0x4C34C4C])
        self.assertEqual(tool.direct_to(IMAGE, tool.TARGETS[1]), [0x4C34ABC])

    def test_bound_census(self):
        self.assertEqual(RESULT["census"], ["0x4d18a21", "0x4d19841"])
        self.assertEqual([row[2] for row in RESULT["appliers"]], [0, 0])

    def test_bound_census_sees_a_planted_word(self):
        at = 0x432A990 + 0x10
        planted = dict(zip(range(at, at + 8), struct.pack("<Q", tool.MAX_SAFE)))
        self.assertEqual(tool.bound_in(edited(planted), tool.APPLIERS)[0][2], 1)

    def test_constants_by_bytes(self):
        rows = {row[1]: row[2] for row in RESULT["constants"]}
        self.assertEqual(rows["1.0"], struct.pack("<d", 1.0).hex())
        self.assertEqual(rows["-1.0"], struct.pack("<d", -1.0).hex())
        self.assertEqual(rows["2^64"], struct.pack("<d", 2.0 ** 64).hex())
        self.assertEqual(len(RESULT["constants"]), 8)

    def test_locations(self):
        rows = {row[0]: row[1:] for row in RESULT["locations"]}
        self.assertEqual(rows["0x56f21f0"][0], "l1/src/spot_meta.rs")
        self.assertEqual(rows["0x5714c10"][0], "l1/src/qtys/mod.rs")

    def test_a_row_outside_the_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.Harness(tool.load_image(), 0).image.exact_fde(0x10)

    def test_unreached_rows_are_the_second_bounds_and_landing_pads(self):
        self.assertEqual(min(RESULT["unreached"]), 0x4D18D26)
        self.assertFalse([va for va in RESULT["unreached"] if not 0x4D18D26 <= va < 0x4D18DBA])


class Decisions(unittest.TestCase):
    def test_named_cases_match(self):
        self.assertEqual(RESULT["outcomes"], [tool.spec_run(case) for case in RESULT["named"]])

    def test_copies_agree(self):
        for case in tool.NAMED:
            self.assertEqual(FIRST.run(case), SECOND.run(case), case.name)

    def test_flag_field_reads_the_copy_offset(self):
        case = named("flag byte differs")
        for harness in (FIRST, SECOND):
            self.assertIn(("flagged", case.flag, case.state_words[0], case.state_words[1]), harness.run(case)[2])

    def test_vector_count(self):
        self.assertEqual(RESULT["vector_count"], 800)

    def test_three_legs_price_a_third(self):
        rows = FIRST.run(tool.Case())[3]
        self.assertEqual([word(row, 0x1F8) for row in rows], [33333333, 33333333, 23333333])

    def test_row_fields(self):
        row = FIRST.run(tool.Case())[3][0]
        self.assertEqual(word(row, 0x1F0), 11)
        self.assertEqual(word(row, 0x238), 33333333)
        self.assertEqual(word(row, 0x200), 3000)
        self.assertEqual(word(row, 0x208), 33333333 * 3000)
        self.assertEqual(row[0x240], tool.ROW_TAG)

    def test_parent_leg_is_not_counted_and_costs_nothing(self):
        outcome = FIRST.run(named("leg token equals the parent word: cost 0, not counted"))
        self.assertEqual([word(row, 0x1F8) for row in outcome[3]], [100000000])
        self.assertEqual(legs(outcome)[0][6], 0)

    def test_bound_is_inclusive(self):
        self.assertEqual(len(FIRST.run(named("product exactly the bound: admitted"))[3]), 1)
        self.assertEqual(len(FIRST.run(named("product bound with px 1: admitted"))[3]), 1)

    def test_above_the_bound_skips_without_error(self):
        for text in ("product bound plus one, odd: refused", "product 2^64 exactly: low word 0, refused by overflow", "product above 2^64 with low word small",
                     "px 3 and quote 2^62: above the bound"):
            outcome = FIRST.run(named(text))
            self.assertEqual(outcome[:2], ("value", tool.SUCCESS), text)
            self.assertEqual(outcome[3], ())
            self.assertEqual(legs(outcome)[0][6], 0, text)

    def test_side_word_two_skips(self):
        self.assertEqual(FIRST.run(named("side word 2: no row, leg cost 0"))[3], ())

    def test_status_codes(self):
        self.assertEqual(FIRST.run(named("empty map field: status 4"))[1], 4)
        self.assertEqual(FIRST.run(named("unknown id: status 4"))[1], 4)
        self.assertEqual(FIRST.run(named("sides with different parents: status 15"))[1], 0xF)
        self.assertEqual(FIRST.run(named("side A token vector length 2: status 0"))[1], 0)

    def test_first_pass_failure_writes_nothing(self):
        outcome = FIRST.run(named("unknown id in the second list after the first"))
        self.assertEqual(outcome[1], 4)
        self.assertEqual(len(legs(outcome)), 1)

    def test_unwrap_panic_only_with_a_record(self):
        self.assertEqual(FIRST.run(named("amount 2^63 panics in list 0"))[:2], ("panic", tool.LOC_UNWRAP))
        for text in ("amount 2^63 in list 1 only: no conversion", "amount 2^63 with no counted legs: no conversion", "amount 2^63 with word 2: no conversion"):
            self.assertEqual(FIRST.run(named(text))[0], "value", text)

    def test_share_of_forty_nine(self):
        self.assertEqual(tool.share_amount(49, 49), 0)
        self.assertEqual(tool.share_amount(48, 48), 1)
        self.assertIn((49, 1, 49, 0), RESULT["even"])

    def test_word_two_gives_no_final(self):
        self.assertFalse([event for event in FIRST.run(named("option words 2: no record, no final"))[2] if event[0] == "final"])

    def test_factor_is_not_plain_one_over_n(self):
        self.assertEqual(tool.leg_factor(1), 1.0)
        self.assertEqual(tool.leg_factor(2), 0.5)
        self.assertNotEqual(tool.leg_factor(3), 1.0 / 3.0)
        census = RESULT["factor_census"]
        self.assertEqual(census["first_other"], (2560, 39062, 39063))
        self.assertEqual(census["other_price"], 2)

    def test_reference_rows(self):
        self.assertEqual([row[3] for row in RESULT["reference"]], ["ok", "ok", "status_18", "status_18", "status_18"])

    def test_pieces_cover_every_pattern(self):
        for rows in (RESULT["amount"], RESULT["px"]):
            self.assertEqual(rows[0][0], 0)
            self.assertEqual(rows[-1][1], tool.MAX_U64)
            for left, right in zip(rows, rows[1:]):
                self.assertEqual(left[1] + 1, right[0])

    def test_spec_edges(self):
        self.assertEqual(tool.spec_px_tail(float("nan")), 1)
        self.assertEqual(tool.spec_px_tail(math.inf), 1)
        self.assertEqual(tool.spec_px_tail(2.0 ** 64), tool.MAX_U64)
        self.assertEqual(tool.spec_px_tail(0.4), 1)
        self.assertEqual(tool.spec_amount_tail(2.0 ** 63), tool.MAX_I64)
        self.assertEqual(tool.spec_amount_tail(math.inf), 0)
        self.assertEqual(tool.spec_round(0.5), 1.0)
        self.assertEqual(tool.spec_round(-0.5), -1.0)
        self.assertEqual(tool.spec_round(2.5), 3.0)


class Corruption(unittest.TestCase):
    def fails(self, patch):
        harness = tool.Harness(IMAGE, 0, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        return tool.first_failure(harness, list(tool.NAMED)) is not None

    def test_unedited_image_passes_under_the_mutant_limit(self):
        self.assertFalse(self.fails({}))

    def test_bound_constant_changed(self):
        at = 0x4D18A21 + 2
        self.assertEqual(byte_at(at), 0xFE)
        self.assertTrue(self.fails({at: 0xFD}))

    def test_seta_changed(self):
        at = 0x4D18A2E + 1
        self.assertEqual(byte_at(at), 0x97)
        self.assertTrue(self.fails({at: 0x93}))

    def test_extra_one_dropped(self):
        at = 0x4D18450 + 4
        self.assertTrue(self.fails({at: byte_at(at) ^ 8}))

    def test_divide_turned_into_multiply(self):
        at = 0x4D18298 + 2
        self.assertEqual(byte_at(at), 0x5E)
        self.assertTrue(self.fails({at: 0x59}))

    def test_row_tag_changed(self):
        at = 0x4D18BE4 + 7
        self.assertEqual(byte_at(at), tool.ROW_TAG)
        self.assertTrue(self.fails({at: tool.ROW_TAG ^ 1}))

    def test_changed_constant_is_seen(self):
        clone = edited({0x20A730 + 6: byte_at(0x20A730 + 6) ^ 0x10})
        self.assertIsNotNone(tool.first_failure(tool.Harness(clone, 0), list(tool.NAMED)))

    def test_write_past_the_row_is_caught(self):
        self.assertTrue(self.fails({0x4D18C2C + 1: byte_at(0x4D18C2C + 1) ^ 1}))

    def test_mutation_summary(self):
        rows = RESULT.get("mutations")
        self.assertTrue(rows)
        survived = [row for row in rows if row[2] == "survived"]
        self.assertEqual(len(survived), len(tool.EXPECTED_SURVIVORS))
        self.assertFalse([row for row in rows if row[3] == "UNEXPLAINED"])

    def test_unexplained_survivor_fails_the_tool(self):
        original = tool.run_mutants
        tool.run_mutants = lambda image, rows, seen: [(1, "x", "survived", "UNEXPLAINED")]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.analyse(IMAGE)
        finally:
            tool.run_mutants = original

    def test_step_limit_below_a_case_fails_the_control(self):
        original = tool.MUTANT_STEP_LIMIT
        tool.MUTANT_STEP_LIMIT = 50
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.run_mutants(IMAGE, [], set())
        finally:
            tool.MUTANT_STEP_LIMIT = original


if __name__ == "__main__":
    unittest.main()
