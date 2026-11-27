"""Regression tests for RE-007-node115-risk-closure."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-007-node115-risk-closure"


class RiskClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("14/14 files, 82/82 Locations, 117/117 Location FDEs (384117 B)", proc.stdout)
        self.assertIn("7/7 business FDEs (10365 B)", proc.stdout)
        self.assertIn("combined 124 unique FDEs (394482 B)", proc.stdout)
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
        self.assertEqual(records["summary"]["combined_unique_fdes"], 124)
        self.assertEqual(records["summary"]["combined_unique_fde_bytes"], 394482)


if __name__ == "__main__":
    unittest.main()
