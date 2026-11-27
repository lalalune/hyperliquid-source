"""Tests for RE-012-node115-node-runtime-closure."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-node-runtime-closure"


class TestNodeRuntimeClosure115(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("21/21 non-consensus node/src files", proc.stdout)
        self.assertIn("342/342 Locations", proc.stdout)
        self.assertIn("99/99 FDEs", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_manifest_integrity(self) -> None:
        from tools.verify_packets import parse_manifest

        entries = parse_manifest(PACKET_DIR / "MANIFEST.sha256")
        self.assertEqual(len(entries), 3)
        proc = subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=PACKET_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
