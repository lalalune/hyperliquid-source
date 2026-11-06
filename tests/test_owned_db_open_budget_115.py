"""Static and Rust checks for the node #115 owned-db open budget."""
import json
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "tools"))
import owned_db_open_budget_115 as subject

RECORD = ROOT / "research/work-items/RE-009-node115-owned-db-open-budget/records.json"
CRATE = ROOT / "src/node115-owned-db-open"


class OwnedDbOpenBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        cls.record = subject.inspect(cls.image)

    def test_record_matches_the_authenticated_image(self):
        self.assertEqual(self.record, json.loads(RECORD.read_text()))
        self.assertEqual(self.record["body"]["size"], 1147)
        self.assertEqual(self.record["cache_default"], "0x800<<20")
        self.assertEqual(self.record["sibling_default"]["immediate"], "0x4000")
        self.assertFalse(self.record["gates_changed"])
        self.assertFalse(self.record["target_executed"])
        self.assertEqual(self.record["direct_caller"]["skip_byte"], 3)

    def test_wrong_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            subject.inspect(b"not node115")

    def test_truncated_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated image"):
            subject.inspect(self.image[:-1], authenticated=False)

    def _flip(self, va, message):
        data = bytearray(self.image)
        rows = subject._section_map(bytes(data))
        file_off = next(row["offset"] + (va - row["address"])
                        for row in rows if row["type"] != 8 and row["address"] <= va < row["address"] + row["size"])
        data[file_off] ^= 0x01
        with self.assertRaisesRegex(ValueError, message):
            subject.inspect(bytes(data), authenticated=False)

    def test_cache_immediate_must_stay_two_gibibytes(self):
        self._flip(0x4524747, "cache immediate changed")

    def test_block_size_must_stay_16_kibibytes(self):
        self._flip(0x45247f2, "block size immediate changed")

    def test_companion_immediate_must_stay(self):
        self._flip(0x452482e, "companion immediate changed")

    def test_flag_mask_must_read_only_the_low_bit(self):
        self._flip(0x4524732, "flag mask changed")

    def test_saturation_and_scale_shifts_must_stay(self):
        self._flip(0x4524739, "high-bit shift changed")
        self._flip(0x4524753, "saturation shift changed")
        self._flip(0x452476b, "final scale shift changed")

    def test_error_niche_branch_must_stay_overflow(self):
        self._flip(0x452488e, "error niche branch changed")

    def test_missing_key_and_height_branches_must_stay(self):
        self._flip(0x4524678, "null-root branch changed")
        self._flip(0x45246e7, "height borrow branch changed")

    def test_caller_skips_only_mode_byte_three(self):
        self._flip(0x37befe9, "caller mode compare changed")

    def test_sibling_default_must_stay_distinct(self):
        self._flip(0x57c661b, "sibling default changed")

    def test_body_byte_outside_an_anchor_still_fails(self):
        data = bytearray(self.image)
        rows = subject._section_map(bytes(data))
        file_off = next(row["offset"] + (subject.START - row["address"])
                        for row in rows if row["name"] == ".text")
        data[file_off] ^= 0x01
        with self.assertRaisesRegex(ValueError, "root pointer load changed|body digest changed"):
            subject.inspect(bytes(data), authenticated=False)

    def test_rust_budget_and_lookup_match_the_pinned_relation(self):
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(ROOT / "work/owned-db-open-target")
        completed = subprocess.run(
            ["cargo", "test", "--offline", "--locked", "--manifest-path",
             str(CRATE / "Cargo.toml")],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout)


if __name__ == "__main__":
    unittest.main()
