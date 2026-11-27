#!/usr/bin/env python3
"""Targeted tests for RE-008-node115-staking-closure."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PKT = REPO / "research" / "work-items" / "RE-008-node115-staking-closure"


class TestStakingClosure115(unittest.TestCase):
    def test_manifest_and_inventory_counts(self) -> None:
        manifest = PKT / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        for ln in lines:
            expected_sha, rel = ln.split("  ", 1)
            actual = hashlib.sha256((PKT / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"manifest mismatch for {rel}")

        rec = json.loads((PKT / "records.json").read_text(encoding="utf-8"))
        sm = rec["summary"]
        self.assertEqual(sm["core_file_count"], 2)
        self.assertEqual(sm["core_location_count"], 6)
        self.assertEqual(sm["core_location_fde_count"], 5)
        self.assertEqual(sm["extended_file_count"], 4)
        self.assertEqual(sm["total_locations"], 12)
        self.assertEqual(sm["location_fde_count"], 15)
        self.assertEqual(sm["business_fde_count"], 38)
        self.assertEqual(rec["compiled_byte_identity_honest_summary"]["matched_fde_windows"], 169)
        self.assertEqual(rec["compiled_byte_identity_honest_summary"]["matched_bytes"], 6107)
        self.assertFalse(rec["compiled_byte_identity_honest_summary"]["identity_gate_satisfied"])

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
        self.assertIn("2/2 core + 4/4 extended staking files", proc.stdout)
        self.assertIn("12/12 Locations", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
