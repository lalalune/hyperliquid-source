"""Targeted regression tests for RE-015-node115-info-api-closure."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research/work-items/RE-015-node115-info-api-closure"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"


class InfoApiClosure115Test(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        self.assertIn("PASS: 7/7 info_server/src files, 43/43 Locations (0 unreferenced), 131/131 FDEs (131304 B)", proc.stdout)
        self.assertIn("55/55 InfoRequest variants", proc.stdout)
        self.assertIn("5/5 negative controls rejected", proc.stdout)

    def test_records_totals_and_forbid_unsafe(self) -> None:
        data = json.loads(RECORDS_JSON.read_text())
        s = data["summary"]
        self.assertEqual(s["source_files"], 7)
        self.assertEqual(s["locations"], 43)
        self.assertEqual(s["unreferenced_locations"], 0)
        self.assertEqual(s["referencing_fdes"], 131)
        self.assertEqual(s["referencing_fde_bytes"], 131304)
        self.assertEqual(s["info_request_variants"], 55)
        self.assertIn("#![forbid(unsafe_code)]", (REPO_ROOT / "src/info-api/src/lib.rs").read_text())


if __name__ == "__main__":
    unittest.main()
