"""Unit tests for RE-005-node115-bincode-fork-cross-cgu-identity."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-005-node115-bincode-fork-cross-cgu-identity"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST_SHA256 = PACKET_DIR / "MANIFEST.sha256"


class TestBincodeForkCrossCguIdentity115(unittest.TestCase):
    def test_verify_script_and_negative_controls(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("PASS: 26/26 relocation-qualified, 4168 B", proc.stdout)
        self.assertIn("cross-CGU Locations=100 [standalone=11, caller=89]", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_schema_and_manifest(self) -> None:
        rec = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        self.assertEqual(rec["component"], "serialization")
        self.assertEqual(len(rec["windows"]), 26)
        self.assertEqual(rec["summary"]["matched_bytes"], 4168)
        self.assertEqual(rec["summary"]["raw_equal_windows"], 4)
        self.assertEqual(rec["summary"]["serialization_cumulative_identity"]["total_verified_serialization_fdes"], 50)
        self.assertEqual(rec["summary"]["serialization_cumulative_identity"]["total_verified_serialization_bytes"], 12837)

        part = rec["cross_cgu_location_100_partition"]
        self.assertEqual(part["total_cross_cgu_location_fdes"], 100)
        self.assertEqual(part["total_cross_cgu_location_bytes"], 61605)
        self.assertEqual(part["standalone_serialization_fdes"], 11)
        self.assertEqual(part["caller_crate_composite_fdes"], 89)

        self.assertTrue(MANIFEST_SHA256.exists())
        subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=str(PACKET_DIR),
            capture_output=True,
            text=True,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
