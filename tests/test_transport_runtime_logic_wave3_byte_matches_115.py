"""Unit tests for RE-005-node115-transport-runtime-logic-wave3-byte-matches."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-005-node115-transport-runtime-logic-wave3-byte-matches"
)
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST_SHA256 = PACKET_DIR / "MANIFEST.sha256"


class TestTransportRuntimeLogicWave3ByteMatches115(unittest.TestCase):
    def test_verify_script_and_negative_controls(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("PASS: 8/8 relocation-qualified, 3893 B", proc.stdout)
        self.assertIn("node-runtime=8 FDEs/3893 B", proc.stdout)
        self.assertIn("5/5 negative controls rejected", proc.stdout)

    def test_records_schema_and_manifest(self) -> None:
        rec = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        self.assertEqual(rec["source_kind"], "first-party clean-room rebuild")
        self.assertEqual(len(rec["windows"]), 8)
        self.assertEqual(rec["summary"]["matched_bytes"], 3893)
        self.assertEqual(rec["summary"]["raw_equal_bytes"], 3438)
        self.assertEqual(rec["components"]["node-runtime"]["windows"], 8)
        self.assertEqual(rec["components"]["node-runtime"]["bytes"], 3893)

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
