#!/usr/bin/env python3
"""Regression tests for RE-010-node115-action-dispatch-closure."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-010-node115-action-dispatch-closure"


class TestActionDispatchClosure115(unittest.TestCase):
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
        self.assertIn("PASS: action-dispatch closure verified", res.stdout)
        self.assertIn("4/4 negative controls rejected", res.stdout)

        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        sm = records["summary"]
        self.assertEqual(sm["observed_source_files"], 0)
        self.assertEqual(sm["location_count"], 0)
        self.assertEqual(sm["core_dispatch_fdes"], 5)
        self.assertEqual(sm["router_handler_fdes"], 92)
        self.assertEqual(sm["prior_key_clone_count"], 10)
        self.assertEqual(sm["shared_admission_helper_fdes"], 5)
        self.assertEqual(sm["router_caller_fdes"], 3)
        self.assertEqual(sm["combined_unique_fdes"], 105)

        adm_rs = (REPO / "src" / "action-dispatch" / "src" / "admission.rs").read_text(encoding="utf-8")
        self.assertIn("PRIOR_KEY_REJECT_CODE: u16 = 0x120", adm_rs)
        self.assertIn("TIMED_ROUTER_MAX_CWITHDRAW_WORD: u64 = 0x0ccc_cccc_cccc_cccc", adm_rs)
        self.assertIn("NO_0X120_HANDLER_INDICES: [usize; 4] = [3, 4, 18, 35]", adm_rs)


if __name__ == "__main__":
    unittest.main()
