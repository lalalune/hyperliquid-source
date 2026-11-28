"""Regression tests for RE-007-node115-risk-exchange-vaults-logic-byte-matches."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-007-node115-risk-exchange-vaults-logic-byte-matches"


class RiskExchangeVaultsLogicByteMatches115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(
            "10/10 vaults/risk business-logic FDEs relocation-qualified (1823 B",
            proc.stdout,
        )
        self.assertIn("0 overlaps, 4/4 negative controls rejected", proc.stdout)

    def test_manifest_matches_files(self) -> None:
        manifest = PACKET / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 5)
        for ln in lines:
            digest, name = ln.split(None, 1)
            got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(got, digest, f"sha256 mismatch for {name}")
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(records["summary"]["window_count"], 10)
        self.assertEqual(records["summary"]["total_bytes"], 1823)
        self.assertEqual(records["summary"]["by_component"]["vaults"]["bytes"], 347)
        self.assertEqual(records["summary"]["by_component"]["risk"]["bytes"], 1476)
        self.assertEqual(set(records["summary"]["by_component"].keys()), {"vaults", "risk"})


if __name__ == "__main__":
    unittest.main()
