"""Targeted tests for RE-008-node115-staking-crate-map and node115-staking."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-staking-crate-map"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST = PACKET_DIR / "MANIFEST.sha256"


def load_verify_module():
    spec = importlib.util.spec_from_file_location("re008_staking_crate_map_verify", VERIFY_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115StakingCrateMap(unittest.TestCase):
    def test_live_binary_verification_and_negative_controls(self) -> None:
        mod = load_verify_module()
        summary = mod.verify_all(generate=False)
        self.assertEqual(summary["source_files_mapped"], 4)
        self.assertEqual(summary["locations_mapped"], 12)
        self.assertGreaterEqual(summary["distinct_fdes_mapped"], 10)
        self.assertEqual(summary["core_functions_verified"], 5)
        self.assertEqual(summary["windows_verified"], 8)
        self.assertEqual(summary["rela_slots_verified"], 3)
        self.assertEqual(summary["facts_verified"], 10)
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

    def test_rust_lifecycle_constants_match_records(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        paths = [f["path"] for f in records["inventory"]["files"]]
        self.assertIn("l1/src/c_staking/jailing.rs", paths)
        self.assertIn("l1/src/staking.rs", paths)
        vl_rs = (ROOT / "src/node115-staking/src/validator_lifecycle.rs").read_text(encoding="utf-8")
        self.assertIn("MAX_REGISTERED_VALIDATORS: usize = 1_000", vl_rs)
        self.assertIn("MAX_COMMISSION_BPS: u64 = 10_000", vl_rs)
        self.assertIn("MAX_COMMISSION_INCREASE_BPS: u64 = 100", vl_rs)

    def test_no_pycache_in_packet_dir(self) -> None:
        self.assertFalse((PACKET_DIR / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
