#!/usr/bin/env python3
"""Verify RE-008-node115-hotstuff-commit-and-quorum packet and node #115 binary anchors."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-008-node115-hotstuff-commit-and-quorum"
VERIFY_PY = PACKET_DIR / "verify.py"
RECORDS_JSON = PACKET_DIR / "records.json"


def _load_verify():
    spec = importlib.util.spec_from_file_location("re008_hotstuff_commit_verify", VERIFY_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestNode115HotstuffCommitAndQuorum(unittest.TestCase):
    def test_verify_packet_and_negative_controls(self) -> None:
        mod = _load_verify()
        data = mod.BINARY_PATH.read_bytes()
        records = json.loads(RECORDS_JSON.read_text(encoding="utf-8"))
        mod.verify_records(records, data)
        neg = mod.run_negative_controls(records, data)
        self.assertEqual(neg, 3)

        summary = records["summary"]
        self.assertEqual(summary["functions"], 5)
        self.assertEqual(summary["total_function_bytes"], 28_277)
        self.assertEqual(summary["instruction_windows"], 6)


if __name__ == "__main__":
    unittest.main()
