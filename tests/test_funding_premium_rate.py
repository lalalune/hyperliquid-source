"""Tests for tools/funding_premium_rate.py: spec agreement, committed evidence, and negative controls on bytes and addresses."""

import copy
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-007-funding-premium-rate-94"
SPEC = importlib.util.spec_from_file_location("funding_premium_rate", ROOT / "tools" / "funding_premium_rate.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


SHARED = {}


def prepare(cls):
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["evidence"] = tool.analyse(SHARED["image"], full=False)[0]
        SHARED["saved"] = json.loads((FOLDER / "evidence.json").read_text(encoding="utf-8"))
    cls.image, cls.evidence, cls.saved = SHARED["image"], SHARED["evidence"], SHARED["saved"]


class Base(unittest.TestCase):
    setUpClass = classmethod(prepare)

    def clone(self):
        other = copy.copy(self.image)
        other.blob = bytearray(self.image.blob)
        return other


class Agreement(Base):
    def test_no_mismatch(self):
        self.assertEqual(self.evidence["mismatches"], 0, self.evidence["first_mismatch"])

    def test_case_counts_are_committed(self):
        self.assertEqual(self.evidence["cases"], self.saved["cases"])
        self.assertEqual(self.evidence["instructions_stepped"], self.saved["instructions_stepped"])

    def test_every_outcome_is_reached(self):
        self.assertEqual(set(self.evidence["cases"]["outcomes"]), {"premium none", "premium panic panic", "premium panic sub_overflow", "premium some", "rate none", "rate some"})

    def test_static_sections_are_committed(self):
        for key in ("side_call", "functions", "fields", "constants", "scale_table", "callers", "locations", "worked", "reference_claims", "target_sha256"):
            self.assertEqual(self.evidence[key], self.saved[key], key)

    def test_worked_values(self):
        rows = {row["label"]: row for row in self.evidence["worked"]}
        self.assertEqual(rows["no premium, default rate, clamp 0.0005"]["real_bytes"], "1.25e-05")
        self.assertEqual(rows["mean 0.5, saturated"]["real_bytes"], "0.04")
        self.assertEqual(rows["mean -0.5, saturated"]["real_bytes"], "-0.04")
        self.assertEqual(rows["impact gap formula, same book"]["real_bytes"], "0.01")
        self.assertEqual(rows["hl only, 7000 percent mid gap"]["real_bytes"], "0.5")
        self.assertIsNone(rows["oracle 0"]["real_bytes"])

    def test_reference_text_differs_where_claimed(self):
        rows = {row["label"]: row for row in self.evidence["worked"]}
        for label in ("impact gap formula, same book", "hl only, 70 percent mid gap", "hl only, 7000 percent mid gap", "mid / oracle - 1 rounding", "oracle 0"):
            self.assertNotEqual(rows[label]["real_bytes"], rows[label]["reference_text"], label)

    def test_fields_cover_both_functions(self):
        offsets = [row["offset"] for row in self.evidence["fields"]]
        self.assertEqual(offsets, ["0x00", "0x30", "0x60", "0x90", "0xa8", "0xb0", "0xb8", "0xd0"])

    def test_side_word_is_file_backed_and_nonzero(self):
        self.assertEqual(self.evidence["side_call"]["section"], ".data")
        self.assertEqual(self.evidence["side_call"]["file_bytes"], "03000000")

    def test_callers(self):
        rows = self.evidence["callers"]
        self.assertEqual([len(row["indirect_calls"]) for row in rows], [3, 3])
        self.assertEqual([row["direct_rel32"] for row in rows], [0, 0])

    def test_constants_seen_by_the_rate(self):
        values = {row["f64"] for row in self.evidence["constants"]["rate"] if "f64" in row}
        self.assertTrue({"0.0001", "1.0", "-0.32", "0.32", "0.125", "-0.0"} <= values)

    def test_tool_uses_no_external_disassembler(self):
        text = (ROOT / "tools" / "funding_premium_rate.py").read_text(encoding="utf-8")
        self.assertNotIn("subpro" + "cess", text)


class Mutants(Base):
    def rows(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]
        return [line.split("\t") for line in lines]

    def test_summary_matches_rows(self):
        rows = self.rows()
        for name in ("killed", "survived", "unreached"):
            self.assertEqual(sum(1 for row in rows if row[3] == name), self.saved["mutations"][name])

    def test_every_live_mutant_has_a_reason(self):
        for row in self.rows():
            if row[3] != "killed":
                self.assertTrue(row[5], row)

    def test_flipped_branch_is_seen(self):
        harness = tool.Harness(self.image)
        case = tool.premium_case("flip", oracle=0)
        self.assertIsNone(tool.compare_run(harness, case))
        va = 0x3750D91
        at = self.image.offset(va)
        self.assertEqual(self.image.blob[at], 0x75)
        harness.machine.patches = {va: 0x74}
        harness.machine.cache.pop(va, None)
        self.assertIsNotNone(tool.compare_run(harness, case))

    def test_division_before_clamp_is_seen(self):
        harness = tool.Harness(self.image)
        case = tool.premium_case("order", bid=71000000, ask=71000000, hl_only=(1,))
        _, result, _ = harness.premium(case)
        self.assertEqual(result[0], 0.5)
        self.assertNotEqual(result[0], tool.reference_premium(case))


class Negative(Base):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.PREMIUM + 1)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)

    def test_bss_has_no_file_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(self.image.named[".bss"]["address"])

    def test_changed_serializer_offset_is_refused(self):
        other = self.clone()
        at = other.offset(0x37518EC)
        self.assertEqual(bytes(other.blob[at:at + 3]), b"\x49\x8d\xb6")
        other.blob[at + 3] ^= 8
        with self.assertRaises(tool.EvidenceError):
            tool.field_map(other)

    def test_changed_struct_name_is_refused(self):
        other = self.clone()
        other.blob[other.offset(tool.STRUCT_NAME) + 7] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.field_map(other)

    def test_changed_scale_table_is_refused(self):
        other = self.clone()
        other.blob[other.offset(0x584B08) + 7] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.scale_table(other)

    def test_changed_rate_constant_is_seen(self):
        other = self.clone()
        at = other.offset(0x20AD50)
        struct.pack_into("<d", other.blob, at, 0.5)
        harness = tool.Harness(other)
        self.assertIsNotNone(tool.compare_run(harness, tool.rate_case("cap", premiums=((7, (0.5,)),))))

    def test_changed_slot_is_refused(self):
        tool_slot = tool.SLOT_RATE
        try:
            tool.SLOT_RATE = tool_slot + 8
            with self.assertRaises(tool.EvidenceError):
                tool.call_sites(self.image)
        finally:
            tool.SLOT_RATE = tool_slot


class Specification(unittest.TestCase):
    def test_rate_formula(self):
        value, _ = tool.rate_spec(tool.rate_case("x", premiums=((7, (0.002,)),)))
        self.assertEqual(value, (0.002 + (0.0001 - 0.002 if False else -0.0005)) * 0.125)

    def test_missing_vector(self):
        self.assertIsNone(tool.rate_spec(tool.rate_case("x", premiums=()))[0])

    def test_nan_passes_both_clamps(self):
        self.assertTrue(math.isnan(tool.rate_spec(tool.rate_case("x", premiums=((7, (math.nan,)),)))[0]))

    def test_size_guard(self):
        panic, _, _ = tool.premium_spec(tool.premium_case("x", sz_decimals=(0, 7)))
        self.assertEqual(panic, ("sub_overflow", 319))

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
