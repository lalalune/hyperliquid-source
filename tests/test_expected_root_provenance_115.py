"""Static verification tests for RE-009-node115-expected-root-provenance."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-node115-expected-root-provenance"
SPEC = importlib.util.spec_from_file_location("verify_expected_root_115", PACKET / "verify.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ExpectedRootProvenance115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.sections, cls.bounds, cls.fde_sorted, cls.fde_starts = MOD.load_elf(
            ROOT / MOD.TARGET_REL, check_digest=True
        )
        cls.record = json.loads((PACKET / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_verify_against_pinned_node115(self):
        stats = MOD.verify_record_dict(
            self.data, self.sections, self.bounds, self.fde_sorted, self.fde_starts, self.record
        )
        self.assertEqual(stats["fdes"], 15)
        self.assertEqual(stats["anchors"], 85)
        self.assertEqual(stats["direct_calls"], 28)
        self.assertEqual(stats["census_0x3e50"], 27)

    def test_records_match_deterministic_builder(self):
        self.assertEqual(self.record, MOD.build_records())

    def test_all_eight_negative_controls_are_rejected(self):
        rejected = MOD.run_negative_controls(
            self.data, self.sections, self.bounds, self.fde_sorted, self.fde_starts, self.record
        )
        self.assertEqual(rejected, 8)


if __name__ == "__main__":
    unittest.main()
