#!/usr/bin/env python3
"""Unit tests for RE-011-node115-evm-closure (complete node #115 evm closure)."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research/work-items/RE-011-node115-evm-closure"
sys.path.insert(0, str(REPO_ROOT / "tools"))
import verify_packets  # noqa: E402


class TestEvmClosure115(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        res = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(res.returncode, 0, msg=res.stderr + res.stdout)
        self.assertIn("PASS: 4/4 evm files, 9/9 Locations (0 unreferenced)", res.stdout)
        self.assertIn("10/10 Location FDEs (83860 B)", res.stdout)
        self.assertIn("20/20 business FDEs (27681 B)", res.stdout)
        self.assertIn("combined 30/30 unique FDEs (111541 B)", res.stdout)
        self.assertIn("3/3 system contracts", res.stdout)
        self.assertIn("5/5 negative controls rejected", res.stdout)

    def test_manifest_integrity(self) -> None:
        manifest = PACKET_DIR / "MANIFEST.sha256"
        rows = verify_packets.parse_manifest(manifest)
        self.assertEqual(len(rows), 3)
        for want, rel in rows:
            target = verify_packets.resolved(REPO_ROOT, PACKET_DIR, rel)
            self.assertIsNotNone(target)
            assert target is not None
            got = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(got, want, f"SHA-256 mismatch for {rel}")


if __name__ == "__main__":
    unittest.main()
