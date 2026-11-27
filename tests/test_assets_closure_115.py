"""Tests for RE-004-node115-assets-closure full-scope node #115 assets closure."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-004-node115-assets-closure"


class AssetsClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("8/8 files", proc.stdout)
        self.assertIn("144/144 Locations", proc.stdout)
        self.assertIn("783/783 Location FDEs", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_summary_and_manifest(self) -> None:
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(
            records["observed_source_files"],
            [
                "l1/src/asset/pdi.rs",
                "l1/src/perp_meta.rs",
                "l1/src/qtys/impl_ntl.rs",
                "l1/src/qtys/impl_sz.rs",
                "l1/src/qtys/impl_wei.rs",
                "l1/src/qtys/mod.rs",
                "l1/src/spot_meta.rs",
                "l1/src/wire_qty.rs",
            ],
        )
        self.assertEqual(records["summary"]["location_count"], 144)
        self.assertEqual(records["summary"]["location_referencing_fdes"], 783)
        self.assertEqual(records["summary"]["location_referencing_fde_bytes"], 2020566)
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
