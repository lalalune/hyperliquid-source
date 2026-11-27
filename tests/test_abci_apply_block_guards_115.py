"""Tests for RE-009-node115-abci-apply-block-guards-and-history-prune."""

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
    / "RE-009-node115-abci-apply-block-guards-and-history-prune"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"


def _load_verify():
    spec = importlib.util.spec_from_file_location("re009_apply_guards_verify", PACKET_DIR / "verify.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class AbciApplyBlockGuards115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_verify_against_node115(self) -> None:
        self.mod.verify_records(self.records, self.data)
        self.assertEqual(self.records["apply_block_invariants"]["required_feature_version"], 3)

    def test_records_match_deterministic_builder(self) -> None:
        self.assertEqual(self.mod.build_records(self.data), self.records)

    def test_all_four_negative_controls_are_rejected(self) -> None:
        self.assertEqual(self.mod.run_negative_controls(self.records, self.data), 4)


if __name__ == "__main__":
    unittest.main()
