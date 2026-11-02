"""Frozen static-derived mode0 algebra; no captured execution or Rust emulation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-qc-mode0-group-94"
SPEC = importlib.util.spec_from_file_location("qc_mode0_native_evidence", PACKET / "verify.py")
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


class Mode0NativeDerivedContract(unittest.TestCase):
    def test_word_witness_cannot_pass_without_success_values(self):
        spec = importlib.util.spec_from_file_location("qc_mode0_rust_comparator", PACKET / "verify_rust.py")
        comparator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(comparator)
        control = next(c for c in MODEL.freeze()["native_controls"] if c["name"] == "FB-Reader-sign-extend")
        outside = comparator.read_result(b"id\t0\t0\t0\t-\t-\t-\t-\t-\t-\t-\t-")
        with self.assertRaisesRegex(ValueError, "word predicate requires"):
            comparator.verify_control(control, outside)

    def test_pre_rust_pin_and_full_word_charge_guards(self):
        frozen = MODEL.freeze()
        self.assertEqual(hashlib.sha256((PACKET / "pre-rust/PRE-RUST-FREEZE.json").read_bytes()).hexdigest(), MODEL.FREEZE)
        self.assertEqual([f["bytes"] for f in frozen["functions"]], [479, 229, 316, 717])
        self.assertEqual([g["hex"] for g in frozen["mode_guards"]][-3:], ["49833e007416"] * 3)
        exclusions = json.loads((PACKET / "pre-rust/API-EXCLUSIONS.json").read_text())
        self.assertEqual(exclusions[0]["mode_word"], 1 << 32)
        self.assertTrue(all(e["native_outcome"] == "unqualified" for e in exclusions))

    def test96_independent_frozen_final_states_and_route_boundaries(self):
        rows = MODEL.verify_vectors()
        frozen = MODEL.freeze()
        self.assertEqual(sum(c["kind"] == "success" for c in frozen["case_domains"].values()), 36)
        self.assertEqual(sum(c["kind"] != "success" for c in frozen["case_domains"].values()), 60)
        self.assertTrue(any(int(r["charge"]) == (1 << 64) - 1 and int(r["limit"]) == 0 for r in rows))
        for name in ("i", "fb", "fc"):
            for k in range(1, 5):
                a = frozen["case_domains"][f"{name}-k{k}-n8"]
                b = frozen["case_domains"][f"{name}-k{k}-n9"]
                self.assertEqual(a["remaining_before"][k - 1], 8)
                self.assertEqual(b["remaining_before"][k - 1], 9)
                self.assertEqual(a["route_sequence"][k - 1], "R")
                self.assertEqual(b["route_sequence"][k - 1], "F")

    def test_static_controls_bind_opcodes_and_initialized_high_word_witness(self):
        frozen = MODEL.freeze()
        native = dict(MODEL.partition((PACKET / "pre-rust/fresh-native.gnu.txt").read_text()))
        byte_map = {va + i: byte for va, code in native.items() for i, byte in enumerate(code)}
        self.assertEqual(len(frozen["native_controls"]), 12)
        for control in frozen["native_controls"]:
            self.assertIn(control["witness"], frozen["case_domains"])
            for change in control["changes"]:
                start = int(change["va"], 16)
                before = bytes.fromhex(change["before"])
                self.assertEqual(bytes(byte_map[start + i] for i in range(len(before))), before)
                self.assertNotEqual(before, bytes.fromhex(change["after"]))
        narrow = next(c for c in frozen["native_controls"] if c["name"] == "Reader-stores-only32")
        self.assertEqual(narrow["witness"], "fc-k2-n8")
        # A previous complete FD initializes the high word; no uninitialized
        # stack content is selected to make this counterexample work.
        self.assertEqual((0x8877665544332211 & 0xffffffff00000000) | 0x89abcdef,
                         narrow["predicted_difference"]["second_word"])


if __name__ == "__main__":
    unittest.main()
