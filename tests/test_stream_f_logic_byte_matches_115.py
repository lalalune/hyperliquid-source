"""Targeted regression tests for RE-011-node115-stream-f-logic-byte-matches."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research/work-items/RE-011-node115-stream-f-logic-byte-matches"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
LIB_RS = PACKET_DIR / "lib.rs"


class StreamFLogicByteMatches115Test(unittest.TestCase):
    def test_live_rebuild_and_negative_controls(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_PY), "--self-test"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        self.assertIn("PASS: 23/23 FDEs relocation-qualified, 20833 B total", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_schema_and_purity(self) -> None:
        src = LIB_RS.read_text()
        self.assertIn("#![forbid(unsafe_code)]", src)
        data = json.loads(RECORDS_JSON.read_text())
        summary = data["summary"]
        self.assertEqual(summary["total_fdes"], 23)
        self.assertEqual(summary["total_bytes"], 20833)
        self.assertEqual(summary["by_component"]["bridge"]["fdes"], 13)
        self.assertEqual(summary["by_component"]["bridge"]["bytes"], 11526)
        self.assertEqual(summary["by_component"]["evm"]["fdes"], 8)
        self.assertEqual(summary["by_component"]["evm"]["bytes"], 8689)
        self.assertEqual(summary["by_component"]["evm-rpc"]["fdes"], 2)
        self.assertEqual(summary["by_component"]["evm-rpc"]["bytes"], 618)
        self.assertEqual(len(data["records"]), 23)
        for rec in data["records"]:
            self.assertTrue(rec["relocation_qualified"])
            self.assertEqual(
                int(rec["end"], 16) - int(rec["start"], 16),
                rec["size"],
            )


if __name__ == "__main__":
    unittest.main()
