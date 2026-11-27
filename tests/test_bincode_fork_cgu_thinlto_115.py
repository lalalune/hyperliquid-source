"""Tests for node #115 z_forks/bincode-fork ThinLTO CGU compiled-byte matches."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-005-node115-bincode-fork-cgu-thinlto-matches"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re005_bincode_fork_cgu_thinlto_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


thin_verify = _load_verify()


class TestBincodeForkCguThinLto115(unittest.TestCase):
    def test_thinlto_cgu_12_fdes_and_negative_controls(self) -> None:
        summary = thin_verify.verify_all(self_test=True)
        self.assertEqual(summary["compiled"]["matched_windows"], 12)
        self.assertEqual(summary["compiled"]["total_bytes"], 7170)
        self.assertEqual(summary["compiled"]["total_raw_equal_bytes"], 6434)
        self.assertEqual(summary["negative_controls_rejected"], 4)

    def test_records_disjoint_and_pure_std(self) -> None:
        rec = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["component"], "serialization")
        self.assertEqual(len(rec["windows"]), 12)
        thin_verify.check_disjointness(rec["windows"])
        src = (PACKET_DIR / "main.rs").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", src)


if __name__ == "__main__":
    unittest.main()
