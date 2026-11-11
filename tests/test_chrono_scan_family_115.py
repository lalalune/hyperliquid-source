import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chrono_scan_family_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "foundation-chrono-scan-family-115"


def sample_cases():
    """Named inputs, a slice of every generated stream and the name families: a few thousand cases, not the full 70 thousand."""
    seen = {kind: 0 for kind in tool.TARGETS}
    out = list(tool.named_cases())
    for kind in (tool.TRIM, tool.COLON):
        for char in ("\u200b", "\u0085", "\u2003", ":", "\u180e"):
            out.append(tool.Case(kind, char.encode("utf-8") + b"x"))
    for case in tool.all_cases():
        if seen[case.kind] < 400 or case.crit and seen[case.kind] < 900:
            seen[case.kind] += 1
            out.append(case)
    return out


class ChronoScanFamilyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.cpu.load_image(tool.BINARY, tool.SHA256)
        cls.harness = tool.Harness(cls.image)
        cls.cases = sample_cases()

    def test_digest_is_checked_first(self):
        with self.assertRaises(tool.EvidenceError):
            tool.cpu.load_image(tool.BINARY, "0" * 64)

    def test_every_target_is_a_function_start(self):
        for target in tool.TARGETS:
            self.assertEqual(self.image.exact_fde(target)[0], target)

    def test_inside_a_function_is_refused(self):
        for target in tool.TARGETS:
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(target + 1)

    def test_bodies_agree_with_the_rule_list(self):
        for case in self.cases:
            self.assertEqual(self.harness.run(case), tool.Spec().run(case), case.label())

    def test_named_edges(self):
        spec = tool.Spec()
        probe = {tool.NUMBER: (b"12x", 2, 2), tool.MONTH: (b"Sep",), tool.WEEKDAY: (b"sun",), tool.LONG_MONTH: (b"September",), tool.COMMENT: (b"(a(b)c)d",)}
        for kind, args in probe.items():
            case = tool.Case(kind, *args)
            got = self.harness.run(case)
            self.assertEqual(got, spec.run(case))
            self.assertEqual(got[0], "out")

    def test_number_do_while_quirk(self):
        case = tool.Case(tool.NUMBER, b"123", 0, 0)
        got = self.harness.run(case)
        # max == 0 consumes every digit but cuts at min(len, 0), so the input is returned whole
        self.assertEqual(got, tool.Spec().run(case))
        self.assertEqual(int.from_bytes(got[1][0:8], "little"), tool.STR)
        self.assertEqual(int.from_bytes(got[1][8:16], "little"), 3)
        self.assertEqual(int.from_bytes(got[1][16:24], "little"), 123)

    def test_number_overflow_is_out_of_range(self):
        case = tool.Case(tool.NUMBER, b"9223372036854775808", 1, 19)
        got = self.harness.run(case)
        self.assertEqual(got, tool.Spec().err(tool.OUT_OF_RANGE))

    def test_nanosecond_scale_table(self):
        case = tool.Case(tool.NANO, b"123", 3)
        got = self.harness.run(case)
        self.assertEqual(int.from_bytes(got[1][16:24], "little"), 123000000)

    def test_nanosecond_ten_digits_index_panic(self):
        got = self.harness.run(tool.Case(tool.NANO, b"1234567890", 10))
        self.assertEqual(got, ("panic", "index", 10, 10))

    def test_weekday_error_niche(self):
        got = self.harness.run(tool.Case(tool.WEEKDAY, b"xyz"))
        self.assertEqual(got[1][0], tool.INVALID)
        self.assertEqual(got[1][0x10], 7)

    def test_trim_follows_the_unicode_set(self):
        for code in sorted(tool.WHITESPACE) + [0x200B, 0x180E, 0xFEFF, 0x61, 0x3A]:
            case = tool.Case(tool.TRIM, chr(code).encode("utf-8") + b"x")
            self.assertEqual(self.harness.run(case), tool.Spec().run(case), hex(code))

    def test_white_space_map_agrees_with_the_set(self):
        entries = dict(tool.white_space_runs(self.image))
        # U+2000..U+200A, U+2028, U+2029, U+202F, U+205F read bit 1; U+0085 and U+00A0 read bit 0
        for code in list(range(0, 11)) + [0x28, 0x29, 0x2F, 0x5F]:
            self.assertEqual(entries[code], 2)
        self.assertEqual(entries[0x85], 1)
        self.assertEqual(entries[0xA0], 1)
        self.assertEqual(len(entries), 17)

    def test_constants_all_match(self):
        rows = tool.constant_rows(self.image)
        self.assertGreater(len(rows), 30)
        self.assertNotIn("DIFFERENT", [row[-1] for row in rows])

    def test_every_wrong_rule_is_contradicted(self):
        for name in tool.SPEC_MUTANTS:
            wrong = tool.Wrong(frozenset((name,)))
            found = any(self.harness.run(case) != wrong.run(case) for case in self.cases)
            self.assertTrue(found, name)

    def test_empty_mutant_set_is_the_claim(self):
        for case in self.cases[:300]:
            self.assertEqual(tool.Wrong(frozenset()).run(case), tool.Spec().run(case))

    def test_a_flipped_condition_is_noticed(self):
        """Flip the first conditional jump of short_month0 (length above 2): the one-letter and three-letter inputs must disagree."""
        rows = tool.edit_rows(self.image)
        spec = tool.Spec()
        jump = next(row for row in rows[tool.MONTH] if row.op == "jcc")
        at = self.image.offset(jump.va) + jump.size - 5 if jump.size >= 6 else self.image.offset(jump.va)
        patch = {jump.va + (at - self.image.offset(jump.va)): self.image.blob[at] ^ 1}
        patched = tool.Harness(self.image, patch)
        probe = [tool.Case(tool.MONTH, b"Mar"), tool.Case(tool.MONTH, b"ma")]
        self.assertTrue(any(self._differs(patched, spec, case) for case in probe))
        clean = tool.Harness(self.image)
        self.assertFalse(any(self._differs(clean, spec, case) for case in probe))

    @staticmethod
    def _differs(harness, spec, case):
        try:
            return harness.run(case) != spec.run(case)
        except (tool.Halt, tool.EvidenceError):
            return True

    def test_panic_slots_are_relative_slots(self):
        relative = self.image.relative()
        for slot in tool.PANIC_SLOTS:
            self.assertIn(slot, relative)

    def test_big_string_is_refused(self):
        with self.assertRaises(tool.Halt):
            tool.Harness(self.image).run(tool.Case(tool.NUMBER, b"1" * 140000, 0, 5000))

    def test_evidence_manifest_matches_files(self):
        manifest = (WORK / "MANIFEST.sha256").read_text().splitlines()
        self.assertGreater(len(manifest), 8)
        for line in manifest:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_file_counts(self):
        summary = json.loads((WORK / "measure.json").read_text())
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertGreaterEqual(summary["negative_controls"], 30)
        self.assertEqual(summary["negative_detected"], summary["negative_controls"])
        self.assertEqual(summary["binary_sha256"], tool.SHA256)

    def test_tool_has_no_external_program_calls(self):
        source = pathlib.Path(tool.__file__).read_text()
        for word in ("subprocess", "os.system", "objdump", "readelf"):
            self.assertNotIn(word + "(", source)


if __name__ == "__main__":
    unittest.main()
