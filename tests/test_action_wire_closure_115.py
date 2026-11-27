#!/usr/bin/env python3
"""Regression tests for RE-010-node115-action-wire-closure."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-010-node115-action-wire-closure"


class TestActionWireClosure115(unittest.TestCase):
    def test_manifest_sha256_and_no_pycache(self) -> None:
        self.assertFalse((PACKET / "__pycache__").exists())
        manifest = (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(manifest), 3)
        for line in manifest:
            digest, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, digest, f"digest mismatch for {rel}")

    def test_verify_self_test_and_summary_counts(self) -> None:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        res = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("PASS: action-wire closure verified", res.stdout)
        self.assertIn("4/4 negative controls rejected", res.stdout)

        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        sm = records["summary"]
        self.assertEqual(sm["observed_source_files"], 5)
        self.assertEqual(sm["location_count"], 13)
        self.assertEqual(sm["action_wire_location_fdes"], 15)
        self.assertEqual(sm["action_wire_business_fdes"], 6)
        self.assertEqual(sm["combined_unique_fdes"], 21)

        rmp_rs = (REPO / "src" / "action-wire" / "src" / "rmp_signable.rs").read_text(encoding="utf-8")
        self.assertIn("ENVELOPE_OK_BYTE: u8 = 0x0e", rmp_rs)
        self.assertIn("USER_OUTCOME_DISABLED_TAG: u16 = 0x92", rmp_rs)
        self.assertIn("ACTION_DELAYER_FIELD_COUNT: usize = 6", rmp_rs)


if __name__ == "__main__":
    unittest.main()
