"""Verification tests for RE-002-node115-zforks-wave2-byte-matches."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-002-node115-zforks-wave2-byte-matches"
VERIFY = PACKET / "verify.py"


class TestZforksWave2ByteMatches115(unittest.TestCase):
    def test_verify_script_and_negative_controls(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY), "--self-test"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS: RE-002-node115-zforks-wave2-byte-matches:", proc.stdout)
        self.assertIn("negative_controls=4/4", proc.stdout)

    def test_records_summary_and_strict_attribution(self) -> None:
        data = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(
            data["target"]["sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        )
        summary = data["summary"]
        self.assertEqual(summary["total_windows"], 145)
        self.assertEqual(summary["total_bytes"], 131922)
        self.assertEqual(summary["raw_equal_windows"], 13)
        self.assertEqual(summary["crates_matched"], 20)
        self.assertEqual(len(data["records"]), 145)

        allowed_deps = {"vendored-crates", "rust-core", "rust-alloc", "rust-std"}
        crates = set()
        for rec in data["records"]:
            self.assertIn(rec["dependency"], allowed_deps)
            self.assertNotIn("zforks_w2_", rec["symbol"])
            self.assertIn(rec["match_tier"], {"unique_fde", "high_entropy_multi_copy"})
            crates.add(rec["crate"])

        for expected in ("ark-ff", "revm-interpreter", "revm-precompile", "alloy-consensus", "k256"):
            self.assertIn(expected, crates)


if __name__ == "__main__":
    unittest.main()
