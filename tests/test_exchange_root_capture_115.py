"""Static verification tests for RE-009-node115-exchange-root-capture-and-db-paths."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-node115-exchange-root-capture-and-db-paths"
SPEC = importlib.util.spec_from_file_location("verify_exchange_capture_115", PACKET / "verify.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ExchangeRootCaptureAndDbPaths115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.sections, _, cls.bounds, cls.relocs = MOD.load_elf(ROOT / MOD.TARGET_REL)
        cls.record = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_verify_live_and_slow_74_slot_parity(self):
        stats = MOD.verify_record_dict(self.data, self.sections, self.bounds, self.relocs, self.record)
        self.assertEqual(stats["fdes"], 4)
        self.assertEqual(stats["capture_slots"], 74)
        self.assertEqual(stats["anchors"], 10)
        self.assertEqual(stats["slots"], 2)
        self.assertEqual(stats["literals"], 2)

    def test_records_match_deterministic_builder(self):
        self.assertEqual(self.record, MOD.build_records())

    def test_all_six_negative_controls_are_rejected(self):
        self.assertEqual(
            MOD.run_negative_controls(self.data, self.sections, self.bounds, self.relocs, self.record),
            6,
        )


if __name__ == "__main__":
    unittest.main()
