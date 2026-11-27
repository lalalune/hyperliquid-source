"""Targeted tests for RE-008-node115-hotstuff-vote-and-qc and node115-consensus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-hotstuff-vote-and-qc"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST = PACKET_DIR / "MANIFEST.sha256"


def load_verify_module():
    spec = importlib.util.spec_from_file_location("re008_hotstuff_vote_qc_verify", VERIFY_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115HotStuffVoteAndQc(unittest.TestCase):
    def test_live_binary_verification_and_negative_controls(self) -> None:
        mod = load_verify_module()
        summary = mod.verify_all(generate=False)
        self.assertEqual(summary["functions_verified"], 4)
        self.assertEqual(summary["windows_verified"], 9)
        self.assertEqual(summary["rodata_f64_anchors"], 2)
        self.assertEqual(summary["facts_verified"], 8)
        self.assertEqual(summary["negative_controls_passed"], 6)

    def test_manifest_covers_all_packet_files(self) -> None:
        self.assertTrue(MANIFEST.exists())
        lines = [ln.strip() for ln in MANIFEST.read_text(encoding="utf-8").splitlines() if ln.strip()]
        listed = {}
        for line in lines:
            digest, name = line.split("  ", 1)
            listed[name] = digest
            actual = hashlib.sha256((PACKET_DIR / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f"digest mismatch for {name}")
        self.assertEqual(set(listed.keys()), {"README.md", "records.json", "verify.py"})

    def test_rust_voting_constants_match_records(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        ro = {r["name"]: r for r in records["rodata_f64"]}
        voting_rs = (ROOT / "src/node115-consensus/src/voting.rs").read_text(encoding="utf-8")
        self.assertEqual(ro["max_future_block_drift_secs"]["f64"], 3.5)
        self.assertEqual(ro["vote_pacing_delay_secs"]["f64"], 0.05)
        self.assertIn("MAX_BLOCK_TX_BYTES: u64 = 5_000_000", voting_rs)
        self.assertIn("0x400c_0000_0000_0000", voting_rs)
        self.assertIn("0x3fa9_9999_9999_999a", voting_rs)

    def test_no_pycache_in_packet_dir(self) -> None:
        self.assertFalse((PACKET_DIR / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
