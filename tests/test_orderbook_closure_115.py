"""Tests for RE-006-node115-orderbook-closure full-scope node #115 orderbook closure."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-006-node115-orderbook-closure"


class OrderbookClosure115Test(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("6/6 files", proc.stdout)
        self.assertIn("35/35 Locations", proc.stdout)
        self.assertIn("36/36 core book/slab FDEs", proc.stdout)
        self.assertIn("140/140 books.rs FDEs", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_summary_and_manifest(self) -> None:
        records = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(
            records["observed_source_files"],
            [
                "l1/src/book/book/impl_insert_order.rs",
                "l1/src/book/book/mod.rs",
                "l1/src/book/book_orders.rs",
                "l1/src/book/level.rs",
                "l1/src/books.rs",
                "l1/src/slab/slab.rs",
            ],
        )
        self.assertEqual(records["summary"]["combined_unique_fdes"], 180)
        self.assertEqual(records["summary"]["combined_unique_fde_bytes"], 750257)
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
