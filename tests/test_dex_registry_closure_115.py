"""Regression tests for RE-007-node115-dex-registry-closure."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-007-node115-dex-registry-closure"


class DexRegistryClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("3/3 files, 5/5 Locations, 373/373 Location FDEs (1177785 B)", proc.stdout)
        self.assertIn("20/20 business FDEs (14248 B)", proc.stdout)
        self.assertIn("combined 393 unique FDEs (1192033 B)", proc.stdout)
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
        self.assertEqual(records["summary"]["combined_unique_fdes"], 393)
        self.assertEqual(records["summary"]["combined_unique_fde_bytes"], 1192033)


if __name__ == "__main__":
    unittest.main()
