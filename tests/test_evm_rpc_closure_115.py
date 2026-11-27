"""Targeted regression tests for RE-011-node115-evm-rpc-closure."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research/work-items/RE-011-node115-evm-rpc-closure"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"


class EvmRpcClosure115Test(unittest.TestCase):
    def test_verify_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        self.assertIn("PASS: 6/6 evm_rpc/src files, 57/57 Locations (0 unreferenced), 48/48 FDEs (145280 B)", proc.stdout)
        self.assertIn("29/29 RPC methods", proc.stdout)
        self.assertIn("5/5 negative controls rejected", proc.stdout)

    def test_records_totals_and_forbid_unsafe(self) -> None:
        data = json.loads(RECORDS_JSON.read_text())
        s = data["summary"]
        self.assertEqual(s["source_files"], 6)
        self.assertEqual(s["locations"], 57)
        self.assertEqual(s["unreferenced_locations"], 0)
        self.assertEqual(s["referencing_fdes"], 48)
        self.assertEqual(s["referencing_fde_bytes"], 145280)
        self.assertEqual(s["registered_rpc_methods"], 29)
        self.assertIn("#![forbid(unsafe_code)]", (REPO_ROOT / "src/evm-rpc/src/lib.rs").read_text())


if __name__ == "__main__":
    unittest.main()
