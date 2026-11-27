"""Static verification tests for RE-009-node115-abci-blake3-root."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-node115-abci-blake3-root"
SPEC = importlib.util.spec_from_file_location("verify_abci_blake3_root_115", PACKET / "verify.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class AbciBlake3Root115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.sections, cls.bounds, cls.relocs = MOD.load_elf(ROOT / MOD.TARGET_REL)
        cls.record = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_verify_against_node115(self):
        stats = MOD.verify_record_dict(self.data, self.sections, self.bounds, self.relocs, self.record)
        self.assertEqual(stats["fdes"], 5)
        self.assertEqual(stats["anchors"], 15)
        self.assertEqual(stats["slots"], 8)
        self.assertEqual(stats["jt_arms"], 5)

    def test_records_match_deterministic_builder(self):
        self.assertEqual(self.record, MOD.build_records())

    def test_all_five_negative_controls_are_rejected(self):
        self.assertEqual(
            MOD.run_negative_controls(self.data, self.sections, self.bounds, self.relocs, self.record),
            5,
        )


if __name__ == "__main__":
    unittest.main()
