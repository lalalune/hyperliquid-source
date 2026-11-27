"""Targeted tests for RE-008-node115-consensus-crate-map and node115-consensus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-consensus-crate-map"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST = PACKET_DIR / "MANIFEST.sha256"


def load_verify_module():
    spec = importlib.util.spec_from_file_location("re008_consensus_crate_map_verify", VERIFY_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115ConsensusCrateMap(unittest.TestCase):
    def test_live_binary_verification_and_negative_controls(self) -> None:
        mod = load_verify_module()
        summary = mod.verify_all(generate=False)
        self.assertEqual(summary["source_files_mapped"], 17)
        self.assertEqual(summary["locations_mapped"], 115)
        self.assertGreaterEqual(summary["distinct_fdes_mapped"], 40)
        self.assertEqual(summary["core_functions_verified"], 8)
        self.assertEqual(summary["windows_verified"], 5)
        self.assertEqual(summary["facts_verified"], 6)
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

    def test_records_cover_every_expected_consensus_module(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        paths = [f["path"] for f in records["inventory"]["files"]]
        self.assertIn("node/src/consensus/state.rs", paths)
        self.assertIn("node/src/consensus/signed.rs", paths)
        self.assertIn("node/src/consensus/validator_set.rs", paths)
        self.assertIn("node/src/consensus/validator_stakes.rs", paths)
        self.assertIn("node/src/consensus/timer.rs", paths)
        self.assertEqual(len(paths), 17)

    def test_no_pycache_in_packet_dir(self) -> None:
        self.assertFalse((PACKET_DIR / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
