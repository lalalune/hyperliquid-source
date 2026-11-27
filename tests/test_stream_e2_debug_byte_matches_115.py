"""Regression tests for RE-007-node115-stream-e2-debug-byte-matches."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-007-node115-stream-e2-debug-byte-matches"
VERIFY_PY = PACKET / "verify.py"
RECORDS_PATH = PACKET / "records.json"


class TestStreamE2DebugByteMatches115(unittest.TestCase):
    def test_verify_self_test_passes_and_summary_matches(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("PASS: 36/36 relocation-qualified", proc.stdout)
        rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(rec["summary"]["window_count"], 36)
        self.assertEqual(rec["summary"]["total_bytes"], 8901)
        self.assertEqual(
            set(rec["summary"]["by_component"].keys()),
            {"risk", "vaults", "l1-shared", "action-wire", "exchange"},
        )

    def test_manifest_and_forbid_unsafe(self) -> None:
        src = (PACKET / "main.rs").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", src)
        subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=str(PACKET),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


if __name__ == "__main__":
    unittest.main()
