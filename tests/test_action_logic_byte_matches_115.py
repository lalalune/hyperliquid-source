"""Tests for RE-010-node115-action-logic-byte-matches."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO
    / "research"
    / "work-items"
    / "RE-010-node115-action-logic-byte-matches"
)

sys.path.insert(0, str(REPO / "tools"))
import verify_packets as vp  # noqa: E402


class TestActionLogicByteMatches115(unittest.TestCase):
    def test_verify_self_test_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(PACKET_DIR / "verify.py"), "--self-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("17/17 relocation-qualified, 3426 B (3082 raw-equal, 1 100%-raw", proc.stdout)
        self.assertIn("l1-shared 7w/2023B, action-wire 10w/1403B", proc.stdout)
        self.assertIn("5/5 negative controls rejected", proc.stdout)

    def test_records_attribution_and_licenses(self) -> None:
        records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        sm = records["summary"]
        self.assertEqual(sm["windows"], 17)
        self.assertEqual(sm["total_bytes"], 3426)
        self.assertEqual(sm["raw_equal_bytes"], 3082)
        self.assertEqual(sm["raw_equal_windows"], 1)
        self.assertEqual(sm["by_component"]["l1-shared"]["windows"], 7)
        self.assertEqual(sm["by_component"]["l1-shared"]["bytes"], 2023)
        self.assertEqual(sm["by_component"]["action-wire"]["windows"], 10)
        self.assertEqual(sm["by_component"]["action-wire"]["bytes"], 1403)

        for w in records["windows"]:
            self.assertNotIn("dependency", w)
            self.assertIn(w["component"], ("l1-shared", "action-wire"))
            sym = w["compiled_section"]
            for bad in ("drop_in_place", "core::", "alloc::", "std::", "hashbrown"):
                self.assertNotIn(bad, sym)
            for rel in w["relocations"]:
                self.assertEqual(rel["width"], 4)
                self.assertIn(rel["kind"], (2, 4, 9))
                self.assertNotIn("relaxation", rel)

        licenses = json.loads((PACKET_DIR / "licenses.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(licenses), 15)
        for pkg, spdx in licenses.items():
            self.assertNotEqual(spdx, "UNKNOWN", msg=f"unknown license for {pkg}")
            self.assertTrue(
                any(tok in spdx for tok in ("MIT", "Apache-2.0", "Unlicense", "BSD")),
                msg=f"non-permissive license for {pkg}: {spdx}",
            )

    def test_manifest_and_packet_hygiene(self) -> None:
        proc = subprocess.run(
            ["sha256sum", "-c", "MANIFEST.sha256"],
            cwd=PACKET_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        entries = vp.parse_manifest(PACKET_DIR / "MANIFEST.sha256")
        self.assertEqual(len(entries), 10)
        for digest, rel in entries:
            target = vp.resolved(REPO, PACKET_DIR, rel)
            self.assertTrue(target.is_file(), msg=f"missing manifest file {rel}")
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest, msg=f"digest mismatch {rel}")
        self.assertFalse(list(PACKET_DIR.rglob("__pycache__")))
        self.assertFalse(list(PACKET_DIR.rglob("*.pyc")))


if __name__ == "__main__":
    unittest.main()
