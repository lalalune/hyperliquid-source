#!/usr/bin/env python3
"""Regression tests for RE-010-node115-l1-shared-closure."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-010-node115-l1-shared-closure"


class TestL1SharedClosure115(unittest.TestCase):
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
        self.assertIn("PASS: l1-shared closure verified", res.stdout)
        self.assertIn("5/5 negative controls rejected", res.stdout)

        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        sm = records["summary"]
        self.assertEqual(sm["observed_source_files"], 8)
        self.assertEqual(sm["location_count"], 13)
        self.assertEqual(sm["l1_shared_location_fdes"], 39)
        self.assertEqual(sm["l1_shared_business_fdes"], 14)
        self.assertEqual(sm["combined_unique_fdes"], 53)

        # Cross-check key Rust constants against verified binary records.
        chain_rs = (REPO / "src" / "l1-shared" / "src" / "chain_ext.rs").read_text(encoding="utf-8")
        self.assertIn("0x80, 0xf0, 0xcd, 0x23", chain_rs)
        self.assertIn("0xa4, 0x0c, 0xf2, 0x73", chain_rs)
        self.assertIn("0x3c, 0x83, 0xa5, 0xca", chain_rs)
        utils_rs = (REPO / "src" / "l1-shared" / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("utils_hard_link_and_replace/", utils_rs)
        self.assertIn("0x6a09_e667", utils_rs)


if __name__ == "__main__":
    unittest.main()
