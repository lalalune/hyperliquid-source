"""Tests for tools/order_anchor_band.py: real node #94 bytes with corruption controls."""

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
FOLDER = ROOT / "research" / "work-items" / "RE-004-order-anchor-band-94"
spec_ = importlib.util.spec_from_file_location("order_anchor_band", ROOT / "tools" / "order_anchor_band.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["order_anchor_band"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)


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
        self.assertEqual(IMAGE.exact_fde(tool.SPOT_GATE), (0x372F240, 0x372F3BB))
        self.assertEqual(IMAGE.exact_fde(tool.PERP_GATE), (0x3713DB0, 0x3713E93))
        self.assertEqual(IMAGE.exact_fde(tool.CAP_HELPER), (0x372B4B0, 0x372B6AF))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.SPOT_GATE + 1)


class Paths(unittest.TestCase):
    def test_paths_match_the_claim(self):
        self.assertEqual(len(tool.prove_paths(IMAGE)), 10)

    def assert_rejected(self, patches=None, image=None):
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(image or IMAGE, patches)

    def test_first_compare_flipped(self):
        self.assert_rejected({0x372F30F + 1: byte_at(0x372F30F + 1) ^ 1})

    def test_inclusive_upper_made_strict(self):
        self.assert_rejected({0x3713E7D: 0x77})

    def test_above_zero_flipped(self):
        self.assert_rejected({0x372F32B: byte_at(0x372F32B) ^ 1})

    def test_payload_scale_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x20A960 + 6: 0x5A}))

    def test_minus_one_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x20A278 + 6: 0xE0}))

    def test_one_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x20A730 + 6: 0xE0}))

    def test_sign_mask_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x202ED0: 0xFE}))

    def test_exponent_word_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x203E80 + 3: 0x44}))

    def test_offset_word_changed(self):
        self.assert_rejected(image=edited(IMAGE, {0x202EA0 + 15: 0x46}))

    def test_stack_slot_is_the_distance(self):
        rows = tool.prove_paths(IMAGE)
        self.assertTrue(all("P" in row[3] for row in rows))
        self.assertEqual({row[5] for row in rows}, {"", "(P*100.0)"})


class Spec(unittest.TestCase):
    def test_lower_edge_is_strict(self):
        self.assertFalse(tool.band_admits(50, 100, 0.5))
        self.assertTrue(tool.band_admits(51, 100, 0.5))

    def test_upper_edge_is_inclusive(self):
        self.assertTrue(tool.band_admits(200, 100, 0.5))
        self.assertFalse(tool.band_admits(201, 100, 0.5))

    def test_upper_is_the_inverse_of_the_lower_keep(self):
        self.assertEqual(tool.band_edges(10 ** 8, 0.75)[1], 4 * 10 ** 8)
        self.assertEqual(tool.band_edges(10 ** 8, 0.75)[0], 25000001)

    def test_zero_reference_fails(self):
        for a in (0, 1, tool.MASK[8]):
            self.assertFalse(tool.band_admits(a, 0, 0.5))

    def test_nan_distance_fails(self):
        self.assertFalse(tool.band_admits(5, 5, math.nan))

    def test_distance_above_one_is_symmetric_only(self):
        self.assertTrue(tool.band_admits(299, 100, 2.0))
        self.assertFalse(tool.band_admits(300, 100, 2.0))

    def test_rounding_moves_a_lower_edge(self):
        self.assertEqual(tool.band_edges(10 ** 8, 0.8)[0], 20000001)
        self.assertEqual(tool.exact_edges(10 ** 8, 0.8)[0], 20000000)

    def test_edges_are_tight(self):
        for b in (5, 999, 10 ** 8):
            for p in tool.EDGE_DISTANCES:
                first, last = tool.band_edges(b, p)
                self.assertTrue(tool.band_admits(first, b, p))
                self.assertTrue(tool.band_admits(last, b, p))
                self.assertFalse(first > 0 and tool.band_admits(first - 1, b, p))
                self.assertFalse(tool.band_admits(last + 1, b, p))
                for a in (first, (first + b) // 2, b, (b + last) // 2, last):
                    self.assertTrue(tool.band_admits(a, b, p))

    def test_edge_search_rejects_a_reference_outside(self):
        with self.assertRaises(tool.EvidenceError):
            tool.band_edges(100, -1.0)


class Runs(unittest.TestCase):
    def test_named_cases(self):
        for name, case in tool.named_cases():
            with self.subTest(name):
                self.assertEqual(HARNESS.run_case(case), tool.spec(case))

    def test_u64_conversion_rounds_to_nearest(self):
        for a in (2 ** 53 + 1, 2 ** 53 + 3, 2 ** 63 + 1024, 2 ** 63 + 1025, 2 ** 64 - 1):
            case = tool.Case(a=a, b=a, p=1e-300)
            self.assertEqual(HARNESS.run_case(case)[1], tool.TAG_OK)

    def test_rcx_is_unused_by_the_spot_gate(self):
        self.assertEqual(HARNESS.run_case(tool.Case())[1], tool.TAG_OK)

    def test_helper_results(self):
        for name, case in tool.named_cases():
            if case.cls >= 2:
                with self.subTest(name):
                    self.assertEqual(HARNESS.run_helper(case), tool.helper_spec(case))

    def test_helper_bound_panics(self):
        got = HARNESS.run_helper(tool.Case(index=5, count=3))
        self.assertEqual(got, tool.helper_spec(tool.Case(index=5, count=3)))

    def test_helper_second_side_reads_its_own_word(self):
        self.assertEqual(HARNESS.run_helper(tool.Case(side=1, value=77)), ("ok", 77))

    def test_failure_payload_is_percent(self):
        got = HARNESS.run_case(tool.Case(a=1, b=100, p=0.25))
        self.assertEqual(got[2], tool.to_bits(25.0))

    def test_spec_wrong_side_is_caught(self):
        case = tool.Case(a=201, b=100, p=0.5)
        self.assertNotEqual(HARNESS.run_case(case)[1], tool.TAG_OK)


class Mutants(unittest.TestCase):
    def failure(self, patch, sets=None):
        harness = tool.Harness(IMAGE, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        return tool.first_failure(harness, sets or tool.named_cases())

    def test_unpatched_passes(self):
        self.assertIsNone(self.failure({}))

    def test_tag_changed(self):
        self.assertIsNotNone(self.failure({0x372F34F + 3: 0x60}))

    def test_bias_changed(self):
        self.assertIsNotNone(self.failure({0x372F37B + 2: 0xE9}))

    def test_perp_exempt_ignored(self):
        self.assertIsNotNone(self.failure({0x3713DD3: 0x74}))

    def test_helper_side_value_offset(self):
        self.assertIsNotNone(self.failure({0x372B66E + 3: 0x80}))

    def test_divide_register_changed(self):
        # xmm1 keeps only the low half of b, so the control needs b above 32 bits.
        case = tool.Case(a=2 ** 40, b=2 ** 40, p=0.5)
        self.assertIsNone(self.failure({}, [("large", case)]))
        self.assertIsNotNone(self.failure({0x372F2F0: 0xC1}, [("large", case)]))


class Census(unittest.TestCase):
    def test_gate_sites(self):
        rows = tool.slot_rows(IMAGE)
        self.assertEqual(len(rows), 6)
        self.assertEqual(sorted(row[4] for row in rows), [0x3980, 0x3980, 0x3980, 0x3980, 0x4400, 0x4400])

    def test_slot_moved_fails(self):
        clone = copy.copy(IMAGE)
        clone.relative_map = dict(IMAGE.relative())
        clone.relative_map[tool.SLOT_SPOT] = 0x1234
        with self.assertRaises(tool.EvidenceError):
            tool.slot_rows(clone)

    def test_no_direct_calls(self):
        self.assertEqual(tool.direct_calls(IMAGE, tool.SPOT_GATE), [])
        self.assertEqual(tool.direct_calls(IMAGE, tool.PERP_GATE), [])

    def test_direct_call_scan_works(self):
        self.assertGreater(len(tool.direct_calls(IMAGE, tool.HASH)), 2)

    def test_tag_census(self):
        self.assertEqual(tool.tag_writes(IMAGE, tool.TAG_BAND), [0x3713E87, 0x372F34F])
        self.assertEqual(tool.tag_writes(IMAGE, tool.TAG_CAP), [0x372F38E])

    def test_vote_guards(self):
        rows = tool.vote_rows(IMAGE)
        self.assertEqual([row[7] for row in rows], ["0x3980", "0x3980", "0x4400"])

    def test_vote_constant_changed_drops_all_guards(self):
        self.assertEqual(tool.vote_rows(edited(IMAGE, {0x20A768: byte_at(0x20A768) ^ 1})), [])

    def test_vote_error_tag_changed_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.vote_rows(edited(IMAGE, {0x235B85D + 3: 0x42}))

    def test_key_row(self):
        rows = tool.key_rows(IMAGE)
        self.assertTrue(rows)
        self.assertEqual({row[3] for row in rows}, {"max_order_distance_from_anchor"})

    def test_key_text_changed_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.key_rows(edited(IMAGE, {tool.KEY_ANCHOR: 0x4E}))

    def test_wrapper_changed_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.wrapper_check(edited(IMAGE, {tool.WRAPPER + 2: 0x88}))

    def test_band_message(self):
        _, first, second = tool.band_message(IMAGE)
        self.assertEqual(first + "80" + second, "Order price cannot be more than 80% away from the reference price")

    def test_band_message_changed_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.band_message(edited(IMAGE, {tool.BAND_ARM_LEA + 3: byte_at(tool.BAND_ARM_LEA + 3) ^ 1}))

    def test_field_census_forms(self):
        rows = tool.field_census(IMAGE)
        self.assertEqual(sum(1 for row in rows if row[2] == "store f64"), 6)


class Evidence(unittest.TestCase):
    def test_generated_tables_match(self):
        files = tool.render(tool.analyse(IMAGE, full=False, vectors=3000))
        for name, text in files.items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(rows)
        names = set()
        for row in rows:
            digest, name = row.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"})

    def test_mutants_all_explained(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertGreater(len(rows), 50)
        self.assertTrue(all(row.split("\t")[2] == "killed" or row.split("\t")[3] for row in rows))


if __name__ == "__main__":
    unittest.main()
