#!/usr/bin/env python3
"""Targeted tests for RE-008-node115-staking-governance-and-requirements."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PKT = REPO / "research" / "work-items" / "RE-008-node115-staking-governance-and-requirements"


class TestNode115StakingGovernanceAndRequirements(unittest.TestCase):
    def test_manifest_and_summary(self) -> None:
        manifest = PKT / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        for ln in lines:
            expected_sha, rel = ln.split("  ", 1)
            actual = hashlib.sha256((PKT / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"manifest mismatch for {rel}")

        rec = json.loads((PKT / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["summary"]["fde_count"], 11)
        self.assertEqual(rec["summary"]["fde_total_bytes"], 10925)
        self.assertEqual(rec["summary"]["instruction_windows"], 7)
        self.assertEqual(rec["summary"]["stake_requirement_rows"], 4)
        self.assertEqual(rec["summary"]["user_error_anchors"], 5)

    def test_verifier_self_test(self) -> None:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            [sys.executable, str(PKT / "verify.py"), "--self-test"],
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("11/11 FDEs (10925 B)", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
