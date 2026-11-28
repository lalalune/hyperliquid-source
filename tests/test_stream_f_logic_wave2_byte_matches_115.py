"""Targeted verification tests for RE-015-node115-stream-f-logic-wave2-byte-matches."""

from __future__ import annotations

import hashlib
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
    / "RE-015-node115-stream-f-logic-wave2-byte-matches"
)
sys.path.insert(0, str(REPO_ROOT / "tools"))
from verify_packets import parse_manifest  # noqa: E402


class TestStreamFLogicWave2ByteMatches115(unittest.TestCase):
    def test_manifest_hashes_and_parser(self) -> None:
        manifest = PACKET_DIR / "MANIFEST.sha256"
        self.assertTrue(manifest.is_file())
        entries = parse_manifest(manifest)
        self.assertEqual(len(entries), 12)
        for expected_sha, rel_path in entries:
            full = PACKET_DIR / rel_path
            self.assertTrue(full.is_file(), f"missing manifest file: {rel_path}")
            actual_sha = hashlib.sha256(full.read_bytes()).hexdigest()
            self.assertEqual(actual_sha, expected_sha, f"sha256 mismatch: {rel_path}")

    def test_verify_script_self_test(self) -> None:
        res = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"stderr:\n{res.stderr}\nstdout:\n{res.stdout}")
        self.assertIn("PASS: 70/70 first-party Stream F logic Wave-2 FDEs", res.stdout)
        self.assertIn("29815 B", res.stdout)
        self.assertIn("4/4 negative controls rejected", res.stdout)

    def test_records_schema_and_pure_first_party_attribution(self) -> None:
        rec = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(
            rec["target_sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        )
        s = rec["summary"]
        self.assertEqual(s["windows"], 70)
        self.assertEqual(s["total_bytes"], 29815)
        self.assertEqual(s["relocation_qualified_windows"], 70)
        self.assertEqual(s["relaxed_sites"], 0)
        self.assertEqual(s["by_component"]["info-api"]["windows"], 68)
        self.assertEqual(s["by_component"]["info-api"]["bytes"], 29739)
        self.assertEqual(s["by_component"]["bridge"]["windows"], 1)
        self.assertEqual(s["by_component"]["bridge"]["bytes"], 50)
        self.assertEqual(s["by_component"]["evm"]["windows"], 1)
        self.assertEqual(s["by_component"]["evm"]["bytes"], 26)
        self.assertEqual(len(rec["locations"]), 4)
        self.assertEqual(len(rec["rodata_anchors"]), 3)
        for w in rec["windows"]:
            self.assertEqual(w["attribution"], "first_party_logic")
            self.assertNotIn("drop_in_place", w["symbol"])
            self.assertFalse(w["symbol"].startswith("_ZN4core"))
            self.assertFalse(w["symbol"].startswith("_ZN5alloc"))
            self.assertFalse(w["symbol"].startswith("_ZN3std"))

    def test_licenses_all_permissive(self) -> None:
        lic = json.loads((PACKET_DIR / "licenses.json").read_text(encoding="utf-8"))
        crates = lic["external_crates"]
        self.assertEqual(len(crates), 6)
        for c in crates:
            self.assertEqual(c["license"], "MIT OR Apache-2.0")


if __name__ == "__main__":
    unittest.main()
