import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import node115_libm_fma_dispatch as dispatch  # noqa: E402


class Node115LibmFmaDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = dispatch.TARGET.read_bytes()
        cls.report = dispatch.analyze(cls.data)

    def test_target_and_fde_identities_match_std_census(self):
        self.assertEqual(self.report["target"]["sha256"], dispatch.TARGET_SHA256)
        self.assertEqual(self.report["census"]["fma_fallback"]["range"],
                         "0x63f0230..0x63f0679")
        self.assertIn("fma_fallback", self.report["census"])
        self.assertIn("load_x86_features", self.report["census"])

    def test_function_pointer_relocations_join_wrapper_and_initializer(self):
        self.assertEqual(self.report["dispatch"]["slot_relocations"], {
            "0x64e0fd0": "0x63f0210", "0x64ffe00": "0x63f06a0"})
        self.assertEqual(self.report["dispatch"]["cached_feature_byte"], "0x6728920")

    def test_initializer_selects_fma3_fma4_or_fallback(self):
        entries = self.report["dispatch"]["selected_entries"]
        self.assertEqual(entries["fma3"]["address"], "0x63f0680")
        self.assertEqual(entries["fma4"]["address"], "0x63f0690")
        self.assertEqual(entries["fallback"]["address"], "0x63f0230")
        self.assertIn("FMA3 bit 6 selects first", self.report["dispatch"]["priority"])

    def test_feature_bits_are_bound_to_cpuid_and_xcr0_paths(self):
        features = self.report["dispatch"]["features"]
        self.assertEqual(features["fma3"]["source"], "CPUID leaf 1 ECX bit 12")
        self.assertIn("XCR0 bits 1/2", features["fma3"]["xcr0_gate"])
        self.assertEqual(features["fma4"]["source"],
                         "CPUID leaf 0x80000001 ECX bit 16")
        self.assertEqual(features["fma4"]["vendor_gate"],
                         ["AuthenticAMD", "HygonGenuine"])
        self.assertEqual(features["fma4"]["xcr0_gate"],
                         "none observed in this feature-byte path")

    def test_instruction_bytes_are_fma3_and_fma4_entries(self):
        entries = self.report["dispatch"]["selected_entries"]
        self.assertEqual(entries["fma3"]["bytes"], "c4e2f1a9c2c3")
        self.assertEqual(entries["fma4"]["bytes"], "c4e3f96bc210c3")
        self.assertFalse(self.report["captured_code_executed"])

    def test_wrong_target_digest_is_rejected(self):
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaisesRegex(dispatch.EvidenceError, "wrong target digest"):
            dispatch.analyze(bytes(changed))

    def test_corrupted_feature_dispatch_opcode_is_rejected(self):
        changed = bytearray(self.data)
        section = next(s for s in dispatch.sections(self.data)
                       if s["type"] != 8 and s["address"] <= 0x63F06B3
                       and 0x63F06B3 + 7 <= s["address"] + s["size"])
        offset = section["offset"] + 0x63F06B3 - section["address"]
        changed[offset] ^= 1
        with self.assertRaisesRegex(dispatch.EvidenceError, "unexpected opcode"):
            dispatch._rel32_target(bytes(changed), 0x63F06B3,
                                   bytes.fromhex("488d15"), 7)
        changed = bytearray(self.data)
        section = next(s for s in dispatch.sections(self.data)
                       if s["type"] != 8 and s["address"] <= 0x63F0839
                       and 0x63F0839 + 5 <= s["address"] + s["size"])
        offset = section["offset"] + 0x63F0839 - section["address"]
        changed[offset] ^= 1
        with self.assertRaisesRegex(dispatch.EvidenceError, "unexpected opcode"):
            dispatch._rel32_target(bytes(changed), 0x63F0839, b"\xe8", 5)


if __name__ == "__main__":
    unittest.main()
