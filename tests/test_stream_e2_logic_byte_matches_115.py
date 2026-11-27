"""Live rustc 1.95.0 compiled-byte identity tests for Stream E2 non-visitor business-logic FDEs."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research" / "work-items" / "RE-007-node115-stream-e2-logic-byte-matches"
VERIFY_PATH = PACKET_DIR / "verify.py"
RECORDS_PATH = PACKET_DIR / "records.json"


def _load_verify():
    spec = importlib.util.spec_from_file_location("verify_stream_e2_logic_115", VERIFY_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestStreamE2LogicByteMatches115(unittest.TestCase):
    def test_live_rebuild_and_records_match_16_fdes(self) -> None:
        mod = _load_verify()
        binary_bytes = mod.BINARY_PATH.read_bytes()
        obj_bytes, rustc_ver = mod.compile_object()
        recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        mod.verify_records(recs, binary_bytes, obj_bytes, rustc_ver)
        self.assertEqual(recs["summary"]["total_windows"], 16)
        self.assertEqual(recs["summary"]["total_bytes"], 4645)
        self.assertEqual(
            sorted(recs["summary"]["by_component"].keys()),
            ["action-wire", "exchange", "l1-shared", "risk"],
        )

    def test_negative_controls_rejected(self) -> None:
        mod = _load_verify()
        binary_bytes = mod.BINARY_PATH.read_bytes()
        obj_bytes, rustc_ver = mod.compile_object()
        recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        caught = mod.run_negative_controls(recs, binary_bytes, obj_bytes, rustc_ver)
        self.assertEqual(caught, 4)


if __name__ == "__main__":
    unittest.main()
