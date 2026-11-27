"""Tests for node #115 z_forks/bincode-fork 19/19 (100.00%) CGU identity packet."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-005-node115-bincode-fork-cgu-100pct-identity"
)


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re005_bincode_fork_cgu_100pct_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cgu100_verify = _load_verify()


class TestBincodeForkCgu100Pct115(unittest.TestCase):
    def test_offline_committed_body_data_tables_and_negative_controls(self) -> None:
        summary = cgu100_verify.verify_all(rebuild=False, self_test=True)
        self.assertEqual(summary["committed"]["windows"], 1)
        self.assertEqual(summary["committed"]["bytes"], 209)
        self.assertEqual(summary["committed"]["raw_equal_bytes"], 189)
        self.assertEqual(summary["tables"]["cgu_fdes"], 19)
        self.assertEqual(summary["tables"]["cgu_bytes"], 7575)
        self.assertEqual(summary["tables"]["integer_types_verified"], 13)
        self.assertEqual(summary["tables"]["decode_error_arms_verified"], 18)
        self.assertEqual(summary["negative_controls_rejected"], 4)

    def test_records_schema_and_disjointness(self) -> None:
        rec = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["component"], "serialization")
        self.assertEqual(rec["cgu_100pct_audit"]["matched_fdes"], 19)
        self.assertEqual(rec["cgu_100pct_audit"]["total_fdes"], 19)
        self.assertEqual(rec["cgu_100pct_audit"]["matched_bytes"], 7575)
        self.assertEqual(rec["cgu_100pct_audit"]["coverage_pct"], 100.0)
        cgu100_verify.check_disjointness(rec["windows"])


if __name__ == "__main__":
    unittest.main()
