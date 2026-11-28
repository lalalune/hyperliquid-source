"""Tests for RE-004-node115-stream-e1-orderbook-assets-logic-byte-matches."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-004-node115-stream-e1-orderbook-assets-logic-byte-matches"


class StreamE1OrderbookAssetsLogicByteMatches115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("16/16 relocation-qualified", proc.stdout)
        self.assertIn("4155 B", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_summary_and_manifest(self) -> None:
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(records["summary"]["windows"], 16)
        self.assertEqual(records["summary"]["total_bytes"], 4155)
        self.assertEqual(records["summary"]["by_component"]["orderbook"]["windows"], 6)
        self.assertEqual(records["summary"]["by_component"]["orderbook"]["bytes"], 1998)
        self.assertEqual(records["summary"]["by_component"]["assets"]["windows"], 10)
        self.assertEqual(records["summary"]["by_component"]["assets"]["bytes"], 2157)
        proc = subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=PACKET,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
