"""Targeted tests for RE-008-node115-staking-delegation and node115-staking."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-staking-delegation"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"
MANIFEST = PACKET_DIR / "MANIFEST.sha256"


def load_verify_module():
    spec = importlib.util.spec_from_file_location("re008_staking_delegation_verify", VERIFY_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115StakingDelegation(unittest.TestCase):
    def test_live_binary_verification_and_negative_controls(self) -> None:
        mod = load_verify_module()
        summary = mod.verify_all(generate=False)
        self.assertEqual(summary["functions_verified"], 7)
        self.assertEqual(summary["windows_verified"], 16)
        self.assertEqual(summary["rodata_f64_anchors"], 9)
        self.assertEqual(summary["rela_slots_verified"], 5)
        self.assertEqual(summary["facts_verified"], 16)
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
        expected_files = {"README.md", "records.json", "verify.py"}
        self.assertEqual(set(listed.keys()), expected_files)

    def test_rust_constants_match_verified_records(self) -> None:
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        ro = {r["name"]: r for r in records["rodata_f64"]}
        deleg_rs = (ROOT / "src/node115-staking/src/delegation.rs").read_text(encoding="utf-8")
        gov_rs = (ROOT / "src/node115-staking/src/governance.rs").read_text(encoding="utf-8")

        self.assertIn("0x4122_7500_0000_0000", deleg_rs)
        self.assertIn("0x405e_0000_0000_0000", deleg_rs)
        self.assertIn("0x40f5_1800_0000_0000", deleg_rs)
        self.assertIn("0x417e_187e_0000_0000", deleg_rs)
        self.assertEqual(ro["delegation_lockup_mainnet"]["f64"], 86400.0)
        self.assertEqual(ro["self_delegation_lock_1yr"]["f64"], 31557600.0)

        self.assertIn("0x4072_c000_0000_0000", gov_rs)
        self.assertIn("0x411f_a400_0000_0000", gov_rs)
        self.assertIn("1_000_000_000", gov_rs)
        self.assertEqual(ro["propose_duration_main_long"]["f64"], 518400.0)

    def test_no_pycache_in_packet_dir(self) -> None:
        self.assertFalse((PACKET_DIR / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
