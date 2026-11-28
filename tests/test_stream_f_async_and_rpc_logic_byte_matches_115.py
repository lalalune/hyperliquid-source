"""Tests for RE-015-node115-stream-f-async-and-rpc-logic-byte-matches."""

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
    / "RE-015-node115-stream-f-async-and-rpc-logic-byte-matches"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re015_stream_f_async_rpc_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class StreamFAsyncAndRpcLogicByteMatches115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))

    def test_live_compile_matches_38_stream_f_logic_fdes_and_zero_overlaps(self) -> None:
        self.mod.verify_records(self.records, self.data)
        s = self.records["summary"]
        self.assertEqual(s["windows"], 38)
        self.assertEqual(s["total_bytes"], 7090)
        self.assertEqual(s["relocation_qualified_windows"], 38)
        self.assertEqual(s["by_component"]["evm-rpc"]["windows"], 1)
        self.assertEqual(s["by_component"]["evm-rpc"]["bytes"], 94)
        self.assertEqual(s["by_component"]["info-api"]["windows"], 37)
        self.assertEqual(s["by_component"]["info-api"]["bytes"], 6996)
        self.assertEqual(len(self.records["locations"]), 3)
        for row in self.records["windows"]:
            self.assertEqual(row["attribution"], "first_party_logic")
            self.assertIn("stream_f_async_rpc", row["symbol"])

    def test_all_four_negative_controls_are_rejected(self) -> None:
        self.assertEqual(self.mod.run_negative_controls(self.records, self.data), 4)


if __name__ == "__main__":
    unittest.main()
