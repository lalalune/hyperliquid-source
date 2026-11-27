"""Tests for node #115 serialization (z_forks/bincode-fork) gate-closure packet."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-005-node115-bincode-fork-gate-closure"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re005_bincode_fork_gate_closure_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bincode_verify = _load_verify()


class TestBincodeForkGateClosure115(unittest.TestCase):
    def test_packet_self_test_and_byte_matches(self) -> None:
        summary = bincode_verify.verify_all(self_test=True)
        self.assertEqual(summary["compiled"]["matched_windows"], 8)
        self.assertEqual(summary["compiled"]["total_bytes"], 1044)
        self.assertEqual(summary["compiled"]["total_raw_equal_bytes"], 987)
        self.assertEqual(summary["static"]["cgu_fdes"], 19)
        self.assertEqual(summary["static"]["cgu_bytes"], 7575)
        self.assertEqual(summary["static"]["location_structs"], 13)
        self.assertEqual(summary["static"]["unique_call_site_fdes"], 100)
        self.assertEqual(summary["negative_controls_rejected"], 4)

    def test_records_disjoint_and_pure_std(self) -> None:
        rec = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["component"], "serialization")
        self.assertEqual(len(rec["windows"]), 8)
        bincode_verify.check_disjointness(rec["windows"])
        src = (PACKET_DIR / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", src)


if __name__ == "__main__":
    unittest.main()
