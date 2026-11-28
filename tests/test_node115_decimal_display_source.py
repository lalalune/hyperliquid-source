"""Check the measured public-source comparison's ELF destinations without a toolchain install."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PACKET = Path(__file__).resolve().parents[1] / "research/work-items/RE-002-node115-rust-decimal-display-source"
spec = importlib.util.spec_from_file_location("decimal_display_compare", PACKET / "compare.py")
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class DecimalDisplaySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.frames, cls.bindings = comparison.capture()
        cls.report = json.loads((PACKET / "results.json").read_text())

    def test_source_comparison_controls(self):
        checked = self.report["comparisons"]["checked"]
        for name, start in [("digits", comparison.DIGITS), ("display", comparison.DISPLAY)]:
            target = comparison.target.read(self.data, start, self.frames[start] - start)[1]
            self.assertEqual(checked[name]["target_body_sha256"], comparison.digest(target))
        self.assertEqual(checked["digits"]["bytes_outside_relocations"], 1461)
        self.assertEqual(checked["digits"]["unmasked_difference_count"], 0)
        self.assertFalse(checked["display"]["same_extent"])
        self.assertFalse(self.report["comparisons"]["unchecked"]["digits"]["same_extent"])
        runs = self.report["runs"]
        self.assertEqual(runs["primary"]["rendered_tsv_sha256"], runs["other-release"]["rendered_tsv_sha256"])
        self.assertNotEqual(runs["primary"]["crate_sha256"], runs["other-release"]["crate_sha256"])

    def test_every_captured_destination_and_literal(self):
        root = self.report["comparisons"]["checked"]["digits"]
        self.assertEqual(root["target_bytes"] - 4 * len(root["relocations"]), root["bytes_outside_relocations"])
        for row in root["relocations"]:
            at = comparison.DIGITS + int(row["offset"], 16)
            dest = comparison.target.rip_target(self.data, at, 0)
            self.assertEqual(hex(dest), row["destination"])
            if "literal_hex" in row:
                literal = bytes.fromhex(row["literal_hex"])
                self.assertEqual(comparison.target.read(self.data, dest, len(literal))[1], literal)
            elif "location" in row:
                evidence = row["location"]
                length, line, column = struct.unpack("<QII", comparison.target.read(self.data, dest + 8, 16)[1])
                typ, path = self.bindings[dest]
                self.assertEqual(typ, 8)
                self.assertEqual(comparison.source_path_tail(comparison.target.read(self.data, path, length)[1]),
                                 evidence["source_tail"])
                self.assertEqual([line, column], evidence["source_line_column"])
            elif "vtable_header" in row:
                self.assertEqual(list(struct.unpack("<QQQ", comparison.target.read(self.data, dest, 24)[1])),
                                 row["vtable_header"])
            else:
                self.assertEqual(self.bindings[dest], (8, int(row["target_relative_addend"], 16)))


if __name__ == "__main__":
    unittest.main()
