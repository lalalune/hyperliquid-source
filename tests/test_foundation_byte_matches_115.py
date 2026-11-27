"""Unit tests for RE-001-node115-foundation-byte-matches."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-001-node115-foundation-byte-matches"
sys.path.insert(0, str(REPO_ROOT / "tools"))
import verify_packets  # noqa: E402


def _load_verify_module():
    spec = importlib.util.spec_from_file_location(
        "re001_foundation_byte_matches_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FoundationByteMatches115Tests(unittest.TestCase):
    def test_live_rebuild_and_negative_controls(self) -> None:
        mod = _load_verify_module()
        hl_data = mod.BINARY_PATH.read_bytes()
        records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        mod.verify_records(records, hl_data, rebuild=True)
        self.assertEqual(records["summary"]["windows"], 69)
        self.assertEqual(records["summary"]["total_bytes"], 9450)
        self.assertEqual(
            records["summary"]["by_category"]["business_logic"],
            {"windows": 1, "bytes": 89},
        )
        self.assertEqual(
            records["summary"]["by_category"]["struct_debug"],
            {"windows": 36, "bytes": 8513},
        )
        neg = mod.run_negative_controls(records, hl_data)
        self.assertEqual(neg, 4)

    def test_manifest_integrity(self) -> None:
        entries = verify_packets.parse_manifest(PACKET_DIR / "MANIFEST.sha256")
        self.assertEqual(len(entries), 5)
        for expected_sha, rel in entries:
            target = (PACKET_DIR / rel).resolve()
            self.assertTrue(target.is_relative_to(PACKET_DIR.resolve()))
            self.assertTrue(target.is_file(), f"missing manifest file {rel}")
            self.assertEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(), expected_sha
            )


if __name__ == "__main__":
    unittest.main()
