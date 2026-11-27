"""Tests for RE-012-node115-transport-net-utils-closure."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-transport-net-utils-closure"


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_transport_net_utils_closure_115", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTransportNetUtilsClosure115(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("12/12 net_utils/src files", proc.stdout)
        self.assertIn("68/68 Locations", proc.stdout)
        self.assertIn("62/62 FDEs", proc.stdout)
        self.assertIn("5/5 negative controls rejected", proc.stdout)

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
