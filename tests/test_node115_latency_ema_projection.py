import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-node115-latency-ema-projection"

_spec = importlib.util.spec_from_file_location("node115_latency_ema_projection_verify", PACKET / "verify.py")
packet = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(packet)


class Node115LatencyEmaProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = packet.self_test()

    def test_four_complete_fde_bodies_are_authenticated(self):
        windows = self.report["windows"]
        self.assertEqual({role: (row["start"], row["end"], row["instructions"]) for role, row in windows.items()}, {
            "row-closure": ("0x5a327a0", "0x5a329d8", 145),
            "collector": ("0x5b80ea0", "0x5b810ce", 126),
            "sort-build": ("0x4d55b50", "0x4d55cb2", 85),
            "entry": ("0x5a71d90", "0x5a71e1d", 35),
        })
        self.assertEqual(self.report["authenticated_instruction_rows"], 391)
        self.assertEqual(self.report["target_sha256"], packet.TARGET_SHA256)

    def test_assertion_is_bound_to_the_ema_tracker_source_location(self):
        self.assertEqual(self.report["assertion_literal"], "assertion failed: self.denom > 0.")
        self.assertEqual(self.report["location"], "base/src/ema_tracker.rs:58:13")
        self.assertEqual(self.report["byte_scans"]["location_lea_candidates"], ["0x5a305c8", "0x5a329c6"])

    def test_call_chain_candidates_are_exhaustive_over_text(self):
        self.assertEqual(self.report["byte_scans"]["rel32_candidates"], {
            "0x5a327a0": ["0x5b80ee9", "0x5b80fea"],
            "0x5b80ea0": ["0x4d55b90"],
            "0x4d55b50": ["0x5a71e00"],
            "0x5a71d90": [],
        })
        self.assertEqual(packet.RELATIVE_SLOTS[0x64E8718], 0x5A71D90)

    def test_imports_are_resolved_from_relocations(self):
        self.assertEqual(self.report["import_slot"], {"slot": "0x64dfb50", "symbol": "memcmp"})
        self.assertEqual(set(self.report["plt_calls"].values()), {"_Unwind_Resume"})

    def test_sanitisation_classes(self):
        cases = {
            0x0000000000000000: 0x0000000000000000,
            0x8000000000000000: 0x8000000000000000,
            0x0000000000000001: 0x0000000000000001,
            0x000FFFFFFFFFFFFF: 0x000FFFFFFFFFFFFF,
            0x0010000000000000: 0x0010000000000000,
            0x7FEFFFFFFFFFFFFF: 0x7FEFFFFFFFFFFFFF,
            0x7FF0000000000000: 0,
            0x7FF8000000000000: 0,
            0x8000000000000001: 0,
            0xBFE8000000000000: 0,
            0xFFF0000000000000: 0,
        }
        for bits, expected in cases.items():
            self.assertEqual(packet.native_sanitize(bits), expected, hex(bits))
            self.assertEqual(packet.closed_form_sanitize(bits), expected, hex(bits))

    def test_every_corruption_control_is_rejected(self):
        self.assertEqual(len(self.report["negative_controls"]), 22)
        self.assertFalse(self.report["captured_binary_executed"])


if __name__ == "__main__":
    unittest.main()
