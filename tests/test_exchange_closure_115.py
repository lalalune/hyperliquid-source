"""Regression tests for RE-010-node115-exchange-closure."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-010-node115-exchange-closure"


class ExchangeClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("15/15 files, 70/70 Locations, 102/102 Location FDEs (611186 B)", proc.stdout)
        self.assertIn("17 business FDEs (9479 B)", proc.stdout)
        self.assertIn("combined 119 unique FDEs (620665 B)", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_manifest_matches_files(self) -> None:
        manifest = PACKET / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        for ln in lines:
            digest, name = ln.split(None, 1)
            got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(got, digest, f"sha256 mismatch for {name}")
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(records["summary"]["combined_unique_fdes"], 119)
        self.assertEqual(records["summary"]["combined_unique_fde_bytes"], 620665)


if __name__ == "__main__":
    unittest.main()
