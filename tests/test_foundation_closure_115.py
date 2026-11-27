"""Regression tests for node #115 foundation (base/src/*.rs) full-scope closure."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-foundation-closure"
sys.path.insert(0, str(ROOT / "tools"))
import verify_packets  # noqa: E402


class TestFoundationClosure115(unittest.TestCase):
    def test_manifest_and_summary(self):
        entries = verify_packets.parse_manifest(PACKET / "MANIFEST.sha256")
        self.assertEqual(len(entries), 3)
        for expected_sha, rel in entries:
            target = PACKET / rel
            self.assertTrue(target.is_file(), f"missing {rel}")
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"digest mismatch for {rel}")
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["component"], "foundation")
        self.assertEqual(rec["summary"]["source_file_count"], 33)
        self.assertEqual(rec["summary"]["location_count"], 247)
        self.assertEqual(rec["summary"]["unreferenced_location_count"], 0)
        self.assertEqual(rec["summary"]["unique_location_fde_count"], 839)
        self.assertFalse(rec["summary"]["byte_identity_summary"]["identity_gate_satisfied"])

    def test_verify_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("33/33 base/src files", proc.stdout)
        self.assertIn("247/247 Locations (0 unreferenced)", proc.stdout)
        self.assertIn("839/839 Location FDEs", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
