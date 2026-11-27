"""Regression tests for node #115 foundation base/src/l1_map/entry.rs byte matches."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-foundation-l1-map-byte-matches"
sys.path.insert(0, str(ROOT / "tools"))
import verify_packets  # noqa: E402


class TestFoundationL1MapByteMatches115(unittest.TestCase):
    def test_manifest_integrity(self):
        entries = verify_packets.parse_manifest(PACKET / "MANIFEST.sha256")
        self.assertEqual(len(entries), 4)
        for expected_sha, rel in entries:
            target = PACKET / rel
            self.assertTrue(target.is_file(), f"missing {rel}")
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"digest mismatch for {rel}")

    def test_live_compile_and_negative_controls(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["component"], "foundation")
        self.assertEqual(records["summary"]["window_count"], 79)
        self.assertEqual(records["summary"]["total_bytes"], 19901)
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("79/79 relocation-qualified", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
