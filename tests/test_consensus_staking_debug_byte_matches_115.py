#!/usr/bin/env python3
"""Targeted regression tests for RE-008-node115-consensus-staking-debug-byte-matches."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PKT = REPO / "research" / "work-items" / "RE-008-node115-consensus-staking-debug-byte-matches"


class TestConsensusStakingDebugByteMatches115(unittest.TestCase):
    def test_manifest_and_source_invariants(self) -> None:
        manifest = PKT / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)
        for ln in lines:
            expected_sha, rel = ln.split("  ", 1)
            actual = hashlib.sha256((PKT / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"manifest mismatch for {rel}")

        src = (PKT / "main.rs").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", src)

        rec = json.loads((PKT / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["summary"]["windows"], 35)
        self.assertEqual(rec["summary"]["total_bytes"], 10441)
        self.assertEqual(rec["summary"]["consensus_windows"], 28)
        self.assertEqual(rec["summary"]["consensus_bytes"], 8384)
        self.assertEqual(rec["summary"]["staking_windows"], 7)
        self.assertEqual(rec["summary"]["staking_bytes"], 2057)

    def test_live_thinlto_verifier_self_test(self) -> None:
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
        self.assertIn("35/35 relocation-qualified", proc.stdout)
        self.assertIn("10441 B", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
