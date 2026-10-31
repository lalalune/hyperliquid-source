"""Tests for tools/outcome_deploy_mark.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-outcome-deploy-mark-94"
spec_ = importlib.util.spec_from_file_location("outcome_deploy_mark", ROOT / "tools" / "outcome_deploy_mark.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["outcome_deploy_mark"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
SECOND = 0x4D6C760


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    HARNESS = tool.Traced(IMAGE)


def edited(image, edits):
    """A copy of the image with file bytes replaced at virtual addresses."""
    clone = copy.copy(image)
    data = bytearray(image.blob)
    for va, value in edits.items():
        data[image.offset(va)] = value
    clone.blob = bytes(data)
    return clone


def byte_at(va):
    return IMAGE.blob[IMAGE.offset(va)]


def row_at(va):
    base = IMAGE.offset(va)

    def read(at, count):
        return IMAGE.blob[base + at - va:base + at - va + count]

    return tool.decode(read, va)


def flipped(va):
    """A patch that inverts the condition of the jcc at va."""
    row = row_at(va)
    at = row.size - 5 if row.size >= 6 else 0
    return {va + at: byte_at(va + at) ^ 1}


def deploy(case, entry=SECOND):
    return HARNESS.run_deploy(entry, case), tool.spec_deploy(case, entry)


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_last_byte_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(IMAGE.blob[:-1] + bytes([IMAGE.blob[-1] ^ 1]))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_never_resolves(self):
        section = IMAGE.named[".bss"]
        self.assertEqual(section["type"], 8)
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(section["address"] + 16)

    def test_fde_bounds(self):
        self.assertEqual(IMAGE.exact_fde(0x274C9F0), (0x274C9F0, 0x274DAF5))
        self.assertEqual(IMAGE.exact_fde(SECOND), (SECOND, 0x4D6D563))
        self.assertEqual(IMAGE.exact_fde(0x4D6D570), (0x4D6D570, 0x4D6E373))
        self.assertEqual(IMAGE.exact_fde(tool.SIDE_BUILDER), (tool.SIDE_BUILDER, 0x3C01892))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(SECOND + 1)
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)


class StaticFacts(unittest.TestCase):
    def test_two_later_copies_differ_only_in_state_offsets(self):
        count, rows = tool.copies_match(IMAGE)
        self.assertEqual(count, 620)
        self.assertEqual([row[0] for row in rows], [661, 1087, 1176, 1439, 1528])
        for _, _, left, _, right in rows:
            self.assertEqual((left[4], right[4]) in ((0x8B8, 0x1338), (0x3390, 0x3E10), (0x3388, 0x3E08)), True)

    def test_changed_copy_is_found(self):
        site = 0x4D6C9ED + 0xE10
        row = row_at(site)
        _, rows = tool.copies_match(edited(IMAGE, {site + row.imm_at: byte_at(site + row.imm_at) ^ 1}))
        self.assertEqual(len(rows), 6)
        self.assertIn(0x4D6C9ED - SECOND, [item[0] for item in rows])

    def test_six_sites(self):
        rows = tool.site_rows(IMAGE)
        self.assertEqual(len(rows), 6)
        self.assertEqual([row[1] for row in rows], ["primary", "linked"] * 3)
        for row in rows:
            self.assertEqual(row[2] + 44, row[4])
            self.assertTrue(0 < row[5] - row[4] < 0xB0)

    def test_head_shape_refuses_a_moved_constant(self):
        at = 0x4D6CB65 - 44 + 9 + 3
        with self.assertRaises(tool.EvidenceError):
            tool.head_shape(edited(IMAGE, {at: byte_at(at) ^ 1}), 0x4D6CB65)

    def test_head_shape_refuses_another_opcode(self):
        at = 0x4D6CB65 - 44 + 26
        with self.assertRaises(tool.EvidenceError):
            tool.head_shape(edited(IMAGE, {at: 0x90}), 0x4D6CB65)

    def test_constants_pinned(self):
        self.assertEqual(len(tool.constant_rows(IMAGE)), 8)
        at = 0x20A940
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(edited(IMAGE, {at + 7: byte_at(at + 7) ^ 1}))

    def test_texts_pinned(self):
        self.assertEqual(len(tool.text_rows(IMAGE)), 7)
        at = tool.TEXTS["limit"][0]
        with self.assertRaises(tool.EvidenceError):
            tool.text_rows(edited(IMAGE, {at: byte_at(at) ^ 1}))

    def test_tag_texts(self):
        self.assertEqual(tool.tag_text(IMAGE, tool.FAILED), "Invalid input")
        self.assertEqual(tool.tag_text(IMAGE, tool.INVALID_TOKEN), "Invalid token")
        self.assertEqual(tool.tag_text(IMAGE, tool.INVALID_QUOTE), "Invalid quote token")

    def test_every_value_store_is_the_builder_constant(self):
        at = 0x3C01853
        self.assertEqual(IMAGE.blob[IMAGE.offset(at):IMAGE.offset(at) + 4], b"\x49\xc7\x47\x20")
        self.assertEqual(struct.unpack_from("<I", IMAGE.blob, IMAGE.offset(at) + 4)[0], tool.WHOLE_UNIT)

    def test_builder_has_two_callers_in_the_validator(self):
        sites = tool.direct_calls(IMAGE, {tool.SIDE_BUILDER})[tool.SIDE_BUILDER]
        self.assertEqual(sites, [0x3728E88, 0x3728EA9])
        self.assertEqual({IMAGE.fde(site)[0] for site in sites}, {tool.VALIDATOR})

    def test_each_copy_has_two_direct_callers(self):
        sites = tool.direct_calls(IMAGE, set(tool.COPIES))
        self.assertEqual([len(sites[entry]) for entry in tool.COPIES], [2, 2, 2])

    def test_scan_needs_the_exact_slot(self):
        self.assertEqual(tool.slot_calls(IMAGE, tool.SLOT_LOOKUP + 1), [])
        self.assertEqual(len(tool.slot_calls(IMAGE, tool.SLOT_RESOLVER)), 3)


class MarkFormula(unittest.TestCase):
    def test_named_values(self):
        for value, mark in ((0, 1), (1, 1), (2, 1), (3, 2), (100, 50), (101, 51), (10 ** 8, 5 * 10 ** 7),
                            ((1 << 53) + 1, 1 << 52), (tool.U64_MAX, 1 << 63)):
            self.assertEqual(tool.spec_mark(value), mark)

    def test_closed_form_on_vectors(self):
        for value in tool.value_vectors(200):
            self.assertEqual(tool.spec_mark(value), tool.closed_mark(value))

    def test_tail_edges(self):
        for bits, want in ((0, 1), (1, 1), (tool.to_bits(1.0), 1), (tool.to_bits(1.5), 1), (tool.to_bits(2.0), 2),
                           (tool.to_bits(2.0 ** 63), 1 << 63), (tool.to_bits(2.0 ** 64), tool.U64_MAX), (1 << 63, 1),
                           (0x7FF0000000000000, 1), (0x7FF8000000000000, 1), (0xBFF0000000000000, 1)):
            self.assertEqual(HARNESS.run_tail(SECOND, 0, bits)[1], want)
            self.assertEqual(tool.spec_tail(tool.to_float(bits)), want)

    def test_head_equals_half_of_the_correctly_rounded_value(self):
        for value in (0, 1, 3, 10 ** 8, (1 << 53) + 1, (1 << 53) + 3, (1 << 63) + (1 << 10), tool.U64_MAX):
            self.assertEqual(tool.run_head(HARNESS, 0x4D6CB65, value), tool.to_bits(float(value) * 0.5))

    def test_head_control_with_another_half(self):
        harness = tool.Harness(IMAGE, None, {0x20A940: tool.to_bits(0.25)})
        self.assertNotEqual(tool.run_head(harness, 0x4D6CB65, 8), tool.to_bits(4.0))

    def test_head_control_with_a_broken_exponent_word(self):
        harness = tool.Harness(IMAGE, None, {0x202EA0: tool.to_bits(2.0 ** 53)})
        self.assertNotEqual(tool.run_head(harness, 0x4D6CB65, 1 << 40), tool.to_bits(2.0 ** 39))

    def test_tail_control_flips_the_floor(self):
        # adc $0 becomes sbb $0: the floor at 1 is gone, so this must not match.
        harness = tool.Traced(IMAGE, {0x4D6CBF4: 0x48, 0x4D6CBF4 + 2: 0xD9})
        self.assertNotEqual(harness.run_tail(SECOND, 0, 0)[1], 1)

    def test_refinement_sees_a_moved_bound(self):
        harness = tool.Traced(IMAGE, None, {0x20A510: tool.to_bits(2.0 ** 62)})
        with self.assertRaises(tool.EvidenceError):
            tool.refine_tail(harness, SECOND, 0)

    def test_one_site_whole_domain(self):
        rows, runs = tool.refine_tail(HARNESS, 0x4D6D570, 1)
        self.assertEqual(len(rows), 14)
        self.assertGreater(runs, 100)
        covered = sum(hi - lo + 1 for lo, hi, _, _, _ in rows)
        self.assertEqual(covered, 1 << 64)


class DeployRuns(unittest.TestCase):
    def test_every_named_case_in_every_copy(self):
        for name, case in tool.deploy_cases():
            for entry in tool.COPIES:
                got, want = deploy(case, entry)
                self.assertEqual(got, want, (name, hex(entry)))

    def test_default_value_gives_five_times_ten_to_seven(self):
        got, _ = deploy(tool.Deploy())
        self.assertEqual(got["marks"], {4: 50000000, 5: 50000000})
        self.assertEqual(got["out"], ("tag", tool.OK, 41))

    def test_any_side_failure_ends_in_0x140(self):
        got, _ = deploy(tool.Deploy(pairs={4: (7, 11), 5: (8, 12)}))
        self.assertEqual(got["out"], ("tag", tool.FAILED, None))
        self.assertIn(("drop", tool.INVALID_TOKEN), got["events"])
        self.assertEqual(got["dirty"], 1)

    def test_first_side_stays_stored_when_the_second_fails(self):
        got, _ = deploy(tool.Deploy(values={4: 8, 5: None}))
        self.assertEqual(got["marks"], {4: 4})
        self.assertEqual(got["out"][1], tool.FAILED)

    def test_zero_user_skips_the_set(self):
        got, _ = deploy(tool.Deploy(resolve_fail=True, user=bytes(20)))
        self.assertFalse([e for e in got["events"] if e[0] == "insert"])

    def test_new_side_passes_text_one_point_zero_twice(self):
        case = tool.Deploy(lists={3: [5]}, deployed={2: ("ok", 6)}, values={5: 2, 6: 4})
        got, want = deploy(case)
        self.assertEqual(got, want)
        self.assertEqual([e[0] for e in got["events"]].count("liquidity"), 1)

    def test_control_flipped_quote_branch(self):
        harness = tool.Harness(IMAGE, flipped(0x4D6CB0C))
        case = tool.Deploy()
        self.assertNotEqual(harness.run_deploy(SECOND, case), tool.spec_deploy(case, SECOND))

    def test_control_wrong_field_offset(self):
        store = tool.find_store(IMAGE, 0x4D6CB65)
        row = row_at(store)
        harness = tool.Harness(IMAGE, {store + row.size - 1: 0x70})
        with self.assertRaises(tool.Halt):
            harness.run_deploy(SECOND, tool.Deploy())

    def test_store_is_not_found_past_a_broken_row(self):
        with self.assertRaises(tool.EvidenceError):
            tool.find_store(IMAGE, 0x4D6CB65 + 0x400)

    def test_wrong_decimal_exponent_is_refused(self):
        at = 0x4D6CE4F + 1
        harness = tool.Harness(IMAGE, {at: byte_at(at) ^ 1})
        with self.assertRaises(tool.Halt):
            harness.run_deploy(SECOND, tool.Deploy(lists={3: [5]}, deployed={2: ("ok", 6)}))


class SideRuns(unittest.TestCase):
    def test_every_named_case(self):
        for name, side in tool.side_cases():
            self.assertEqual(HARNESS.run_side(side), tool.spec_side(side), name)

    def test_accepted_value_is_ten_to_eight(self):
        self.assertEqual(HARNESS.run_side(tool.Side())["words"][3], 100000000)

    def test_limit_edge(self):
        self.assertEqual(HARNESS.run_side(tool.Side(name_length=100))["tag"], tool.OK)
        self.assertEqual(HARNESS.run_side(tool.Side(name_length=101))["tag"], tool.LENGTH)

    def test_balance_must_be_exactly_max(self):
        self.assertEqual(HARNESS.run_side(tool.Side(balance=(tool.U64_MAX, 0)))["tag"], tool.OK)
        self.assertEqual(HARNESS.run_side(tool.Side(balance=(tool.U64_MAX - 1, 0)))["tag"], tool.TEXT)

    def test_control_constant_changed(self):
        at = 0x3C01853 + 4
        harness = tool.Harness(IMAGE, {at: byte_at(at) ^ 1})
        self.assertNotEqual(harness.run_side(tool.Side()), tool.spec_side(tool.Side()))


class ValidatorRuns(unittest.TestCase):
    def test_every_named_case(self):
        for name, case in tool.validate_cases():
            self.assertEqual(HARNESS.run_validate(case), tool.spec_validate(case), name)

    def test_record_carries_the_value_on_both_sides(self):
        got = HARNESS.run_validate(tool.Validate())
        self.assertEqual(got[:2], ("record", 40))
        words = got[2]
        self.assertEqual((words[4], words[5], words[9], words[10], words[17]), (100000000, 7, 100000000, 8, 1000))
        self.assertEqual(got[3], [])

    def test_limit_edge(self):
        self.assertEqual(HARNESS.run_validate(tool.Validate(counter=19999))[0], "record")
        self.assertEqual(HARNESS.run_validate(tool.Validate(counter=20000))[0], "error")

    def test_control_limit_changed(self):
        at = row_at(0x37292ED)
        harness = tool.Harness(IMAGE, {0x37292ED + at.imm_at: byte_at(0x37292ED + at.imm_at) ^ 1})
        case = tool.Validate(counter=19999)
        self.assertNotEqual(harness.run_validate(case), tool.spec_validate(case))


class LookupRuns(unittest.TestCase):
    def test_every_named_case(self):
        for name, case in tool.lookup_cases():
            self.assertEqual(HARNESS.run_lookup(case), tool.spec_lookup(case), name)

    def test_field_offsets(self):
        self.assertEqual(HARNESS.run_lookup(tool.Lookup()), ("value", 111))
        self.assertEqual(HARNESS.run_lookup(tool.Lookup(token=8)), ("value", 222))

    def test_control_second_side_offset(self):
        harness = tool.Harness(IMAGE, flipped(0x372B687))
        case = tool.Lookup(token=9)
        self.assertNotEqual(harness.run_lookup(case), tool.spec_lookup(case))


class Reference(unittest.TestCase):
    def test_two_word_form_is_the_conversion_of_one_word(self):
        for value in tool.value_vectors(100):
            self.assertEqual(tool.reference_formula(value & tool.MASK[4], value >> 32 << 32), tool.spec_mark(value))

    def test_two_word_form_needs_the_lanes(self):
        self.assertNotEqual(tool.reference_formula(100000000, 100000000), tool.spec_mark(100000000))


class Packet(unittest.TestCase):
    def test_manifest_matches(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual([line.split("  ")[1] for line in lines], names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_rendered_files_match(self):
        import json
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(sorted(summary["tail_pieces"].values()), [14] * 6)
        self.assertEqual(summary["mutations"]["survived"], len(tool.EXPECTED_SURVIVORS))


if __name__ == "__main__":
    unittest.main()
