"""Tests for RE-015-node115-stream-f-byte-matches."""

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
    / "RE-015-node115-stream-f-byte-matches"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re015_stream_f_byte_matches_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class StreamFByteMatches115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_rebuild_and_match_node115(self) -> None:
        self.mod.verify_records(self.records, self.data, rebuild=True)
        s = self.records["summary"]
        self.assertEqual(s["windows"], 138)
        self.assertEqual(s["total_bytes"], 6060)
        self.assertEqual(s["relocation_qualified_windows"], 138)
        self.assertEqual(s["by_component"]["info-api"]["windows"], 42)
        self.assertEqual(s["by_component"]["info-api"]["bytes"], 3579)
        self.assertEqual(s["by_component"]["evm-rpc"]["windows"], 7)
        self.assertEqual(s["by_component"]["evm-rpc"]["bytes"], 175)
        self.assertEqual(s["by_component"]["evm"]["windows"], 55)
        self.assertEqual(s["by_component"]["evm"]["bytes"], 1375)
        self.assertEqual(s["by_component"]["bridge"]["windows"], 30)
        self.assertEqual(s["by_component"]["bridge"]["bytes"], 750)
        self.assertEqual(s["by_component"]["constants"]["windows"], 4)
        self.assertEqual(s["by_component"]["constants"]["bytes"], 181)

    def test_all_four_negative_controls_are_rejected(self) -> None:
        rejected = self.mod.run_negative_controls(self.records, self.data)
        self.assertEqual(rejected, 4)


if __name__ == "__main__":
    unittest.main()
