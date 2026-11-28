"""Tests for RE-004 Stream E1 fees/orderbook/assets Wave-2 pure business-logic compiled-byte matches."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches"
)
VERIFY_SCRIPT = PACKET_DIR / "verify.py"
RECORDS_PATH = PACKET_DIR / "records.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"


class StreamE1FeesBookLogicWave2ByteMatches115Tests(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), "--self-test"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        self.assertIn("PASS: 9/9 relocation-qualified, 2483 B", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)

    def test_records_schema_and_pure_logic_invariants(self) -> None:
        rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            rec["target_binary"]["sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        )
        self.assertEqual(rec["summary"]["windows"], 9)
        self.assertEqual(rec["summary"]["total_bytes"], 2483)
        self.assertEqual(rec["summary"]["by_component"]["fees"]["windows"], 1)
        self.assertEqual(rec["summary"]["by_component"]["fees"]["bytes"], 163)
        self.assertEqual(rec["summary"]["by_component"]["orderbook"]["windows"], 2)
        self.assertEqual(rec["summary"]["by_component"]["orderbook"]["bytes"], 958)
        self.assertEqual(rec["summary"]["by_component"]["assets"]["windows"], 5)
        self.assertEqual(rec["summary"]["by_component"]["assets"]["bytes"], 1162)
        self.assertEqual(rec["summary"]["by_component"]["risk"]["windows"], 1)
        self.assertEqual(rec["summary"]["by_component"]["risk"]["bytes"], 200)
        for w in rec["windows"]:
            self.assertEqual(w["kind"], "logic")
            self.assertEqual(w["non_reloc_diffs"], 0)
            self.assertNotIn("core::", w["label"])
            self.assertNotIn("alloc::", w["label"])
            self.assertNotIn("std::", w["label"])

    def test_forbid_unsafe_code_on_all_sources(self) -> None:
        for fname in ("stubs.rs", "lib_pic.rs", "lib_pie.rs"):
            src = (PACKET_DIR / fname).read_text(encoding="utf-8")
            self.assertIn("#![forbid(unsafe_code)]", src)

    def test_manifest_sha256_valid(self) -> None:
        proc = subprocess.run(
            ["sha256sum", "-c", str(MANIFEST_PATH)],
            cwd=PACKET_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
