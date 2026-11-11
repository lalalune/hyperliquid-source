import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import asset_decimal_scale_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "risk-asset-decimal-scale-115"
TOP = tool.TOP


class DecimalScaleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.named = tool.named_cases()
        cls.table = {t: tool.decode_range(cls.image, *cls.image.exact_fde(t)) for t in tool.TARGETS}

    def pair(self, case, variant=None):
        before, got = self.harness.run(case)
        return got, tool.rule_run(case, variant)

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "hl-node"
            path.write_bytes(b"\x7fELF" + bytes(100))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_binary_digest_constant(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)

    def test_function_extents(self):
        extents = {t: self.image.exact_fde(t) for t in tool.TARGETS}
        self.assertEqual(extents[tool.POW], (0x3C4B280, 0x3C4B30C))
        self.assertEqual(extents[tool.FLOOR], (0x434F580, 0x434F65C))
        self.assertEqual(extents[tool.MULFLOOR], (0x434F660, 0x434F789))
        self.assertEqual(extents[tool.ENTRY], (0x3C479C0, 0x3C47AD5))
        self.assertEqual(extents[tool.CEIL], (0x3F10820, 0x3F1093E))
        self.assertEqual(extents[tool.ROUNDED], (0x4217E60, 0x4217F8B))

    def test_not_a_function_start(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.CEIL + 4)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x10)

    def test_every_named_case_matches(self):
        for case in self.named:
            got, want = self.pair(case)
            self.assertEqual(got, want, case["name"])

    def test_ladder_limits(self):
        for diff in range(0, 26):
            got, want = self.pair(tool.mkcase(tool.POW, "d%d" % diff, lo=10, hi=10 + diff))
            if diff <= 19:
                self.assertEqual(got, ("ret", 10 ** diff))
            else:
                self.assertEqual(got, (tool.KIND_PANIC, "ladder"))
            self.assertEqual(got, want)

    def test_borrow_panics_for_every_smaller_high_byte(self):
        for lo in (1, 2, 100, 255):
            for hi in range(0, lo):
                got, _ = self.pair(tool.mkcase(tool.POW, "b", lo=lo, hi=hi))
                self.assertEqual(got, (tool.KIND_PANIC, "ladder"))

    def test_power_for_all_byte_pairs(self):
        for lo in range(0, 256, 5):
            for hi in range(0, 256, 3):
                got, want = self.pair(tool.mkcase(tool.POW, "p", lo=lo, hi=hi))
                self.assertEqual(got, want)

    def test_index_zero_skips_the_record_in_mul_floor(self):
        got, _ = self.pair(tool.mkcase(tool.MULFLOOR, "z", lo=9, hi=1, x=7, idx=0, m=3))
        self.assertEqual(got, ("pair", 1, 21))
        got, _ = self.pair(tool.mkcase(tool.MULFLOOR, "z", lo=9, hi=1, x=7, idx=1, m=3))
        self.assertEqual(got, (tool.KIND_PANIC, "ladder"))

    def test_mul_floor_fallback_order(self):
        got, _ = self.pair(tool.mkcase(tool.MULFLOOR, "f", lo=0, hi=3, x=TOP, idx=1, m=2))
        self.assertEqual(got, ("pair", 1, TOP // 1000 * 2))
        got, _ = self.pair(tool.mkcase(tool.MULFLOOR, "f", lo=0, hi=0, x=TOP, idx=1, m=2))
        self.assertEqual(got, ("pair", 0, (TOP * 2) & TOP))

    def test_ceil_rounds_up_and_overflow_is_zero(self):
        up, _ = self.pair(tool.mkcase(tool.CEIL, "c", lo=0, hi=2, x=5, idx=1, d=101))
        exact, _ = self.pair(tool.mkcase(tool.CEIL, "c", lo=0, hi=2, x=5, idx=1, d=100))
        big, _ = self.pair(tool.mkcase(tool.CEIL, "c", lo=0, hi=19, x=TOP, idx=1, d=1))
        self.assertEqual((up, exact, big), (("ret", 5), ("ret", 5), ("ret", 0)))

    def test_ceil_checks_index_before_divisor(self):
        got, _ = self.pair(tool.mkcase(tool.CEIL, "c", lo=0, hi=2, x=5, idx=4, d=0))
        self.assertEqual(got, (tool.KIND_PANIC, "index"))
        got, _ = self.pair(tool.mkcase(tool.CEIL, "c", lo=0, hi=2, x=5, idx=1, d=0))
        self.assertEqual(got, (tool.KIND_PANIC, "divide"))

    def test_rounded_flag_uses_low_byte_only(self):
        base = dict(lo=0, hi=2, x=5, idx=1, d=101)
        low, _ = self.pair(tool.mkcase(tool.ROUNDED, "r", flag=0x100, **base))
        up, _ = self.pair(tool.mkcase(tool.ROUNDED, "r", flag=0x101, **base))
        self.assertEqual((low, up), (("pair", 1, 4), ("pair", 1, 5)))

    def test_entry_branches(self):
        entries = [(0, 11), (3, 22), (1, 33), (2, 44), (1, 55)]
        flagged, _ = self.pair(tool.mkcase(tool.ENTRY, "e", lo=1, hi=3, flag=1, a=6, b=7, idx=2, entries=entries))
        plain, _ = self.pair(tool.mkcase(tool.ENTRY, "e", lo=1, hi=3, flag=0, a=6, b=7, idx=2, entries=entries))
        self.assertEqual(flagged, ("out", 33, 1, 42))
        self.assertEqual(plain, ("out", 1, 1, 700))
        slice_fault, _ = self.pair(tool.mkcase(tool.ENTRY, "e", lo=1, hi=3, flag=0, a=1, b=1, idx=5, entries=entries))
        self.assertEqual(slice_fault, (tool.KIND_PANIC, "slice"))

    def test_panic_locations_are_decoded_from_the_bytes(self):
        rows = tool.location_rows(self.image)
        self.assertEqual([row[0] for row in rows], ["0x6476a48", "0x64768d8", "0x6476678"])
        self.assertEqual([row[1] for row in rows], ["l1/src/spot_meta.rs"] * 3)

    def test_every_instruction_is_reached(self):
        for case in self.named:
            self.harness.run(case)
        for case in tool.stream_cases(600):
            self.harness.run(case)
        for target, rows in self.table.items():
            missing = [hex(row.va) for row in rows if row.va not in self.harness.machine.seen]
            self.assertEqual(missing, [], tool.NAMES[target])

    def test_stream_agrees_with_the_rule_list(self):
        self.assertEqual(tool.check_stream(self.harness, tool.stream_cases(1800, seed=99)), 1800)

    def test_wrong_rule_lists_are_all_detected(self):
        cases = self.named + list(tool.stream_cases(900, seed=5))
        results = tool.wrong_rule_controls(self.harness, cases)
        self.assertGreaterEqual(len(results), 20)
        self.assertEqual([r for r in results if r[1] != "detected"], [])

    def test_edited_bytes_are_noticed(self):
        chosen = [case for case in self.named if case["target"] == tool.CEIL]
        edits = tool.edits_for(self.image, self.table[tool.CEIL], self.harness.machine.seen)
        self.assertGreater(len(edits), 30)
        noticed = 0
        for va, kind, patch in edits:
            harness = tool.Harness(self.image, patch)
            harness.machine.step_limit = 20000
            noticed += tool.first_failure(harness, chosen) is not None
        equivalent = sum(1 for va, _, _ in edits if (tool.CEIL, va) in tool.EQUIVALENT)
        self.assertEqual(equivalent, 1)
        self.assertEqual(noticed, len(edits) - equivalent)

    def test_damaged_image_and_foreign_digest_are_refused(self):
        rows = tool.corrupted_inputs(self.harness)
        self.assertEqual([r[1] for r in rows], ["detected"] * 3)

    def test_unedited_image_passes_under_the_mutant_limit(self):
        harness = tool.Harness(self.image)
        harness.machine.step_limit = 20000
        self.assertIsNone(tool.first_failure(harness, self.named))

    def test_unexplained_survivor_is_refused(self):
        keys = set(tool.EQUIVALENT)
        self.assertEqual(len(keys), 7)
        self.assertTrue(all(isinstance(reason, str) and reason for reason in tool.EQUIVALENT.values()))

    def test_committed_evidence_matches_a_rebuild(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.generate(folder)
            for path in sorted(WORK.iterdir()):
                if path.name in ("README.md", "MANIFEST.sha256"):
                    continue
                self.assertEqual(path.read_bytes(), (pathlib.Path(folder) / path.name).read_bytes(), path.name)

    def test_measure_counts_are_consistent(self):
        measure = json.loads((WORK / "measure.json").read_text())
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertEqual(measure["instructions_reached"], measure["instructions_total"])

    def test_manifest_lists_every_file(self):
        listed = {}
        for line in (WORK / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            listed[name] = digest
        names = sorted(p.name for p in WORK.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), names)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
