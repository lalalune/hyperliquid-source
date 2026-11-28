"""Tests for RE-008-node115-consensus-bincode-encode-byte-matches."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = (
    REPO
    / "research"
    / "work-items"
    / "RE-008-node115-consensus-bincode-encode-byte-matches"
)
VERIFY = PACKET / "verify.py"
RECORDS = PACKET / "records.json"
MANIFEST = PACKET / "MANIFEST.sha256"


class TestConsensusBincodeEncodeByteMatches115(unittest.TestCase):
    def test_manifest_and_summary(self) -> None:
        sys.path.insert(0, str(REPO / "tools"))
        import verify_packets

        entries = verify_packets.parse_manifest(MANIFEST)
        self.assertEqual(len(entries), 4)
        for expected_sha, rel_name in entries:
            target = PACKET / rel_name
            self.assertTrue(target.is_file(), f"Missing manifest file: {rel_name}")
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(actual, expected_sha, f"SHA-256 mismatch for {rel_name}")

        rec = json.loads(RECORDS.read_text(encoding="utf-8"))
        self.assertEqual(
            rec["target_binary"]["sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        )
        s = rec["summary"]
        self.assertEqual(s["windows"], 23)
        self.assertEqual(s["total_bytes"], 6916)
        self.assertEqual(s["consensus_windows"], 23)
        self.assertEqual(s["consensus_bytes"], 6916)
        self.assertEqual(s["raw_equal_bytes"], 6330)
        self.assertEqual(len(rec["windows"]), 23)
        for w in rec["windows"]:
            self.assertEqual(w["component"], "consensus")
            self.assertTrue(w["relocation_qualified"])
            self.assertEqual(w["equal_non_relocation_bytes"], w["non_relocation_bytes"])
            self.assertGreater(len(w["call_target_anchors"]), 0)

    def test_live_verify_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(VERIFY), "--self-test"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"verify.py --self-test failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )
        self.assertIn("PASS: 23/23 relocation-qualified", proc.stdout)
        self.assertIn("4/4 negative controls rejected", proc.stdout)


if __name__ == "__main__":
    unittest.main()
