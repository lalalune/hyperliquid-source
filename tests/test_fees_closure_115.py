"""Tests for RE-004-node115-fees-closure full-scope node #115 fees closure."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-004-node115-fees-closure"


class FeesClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("4/4 files", proc.stdout)
        self.assertIn("4/4 Locations", proc.stdout)
        self.assertIn("17/17 Location FDEs", proc.stdout)
        self.assertIn("15/15 FeeTracker business FDEs", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_summary_and_manifest(self) -> None:
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(
            records["observed_source_files"],
            [
                "l1/src/fees/compute.rs",
                "l1/src/fees/fees.rs",
                "l1/src/raw_vlm.rs",
                "l1/src/scaled_vlm.rs",
            ],
        )
        self.assertEqual(records["summary"]["combined_unique_fdes"], 32)
        self.assertEqual(records["summary"]["combined_unique_fde_bytes"], 57013)
        proc = subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=PACKET,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
