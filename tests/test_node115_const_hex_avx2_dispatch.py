import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import node115_const_hex_avx2_dispatch as dispatch  # noqa: E402


class Node115ConstHexAvx2DispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = dispatch.TARGET.read_bytes()
        cls.report = dispatch.analyze(cls.data)

    def test_census_binds_caller_and_avx2_function(self):
        self.assertEqual(self.report["caller_fde"]["range"], "0x167a9c0..0x167abfb")
        self.assertEqual(self.report["caller_fde"]["bytes"], 571)
        self.assertIn("decode_to_slice_inner", self.report["caller_fde"]["vendor_census_symbol"])
        self.assertEqual(self.report["avx2_fde"]["range"], "0x167ac00..0x167afcf")
        self.assertEqual(self.report["avx2_fde"]["bytes"], 975)
        self.assertIn("decode_avx2", self.report["avx2_fde"]["vendor_census_symbol"])
        self.assertEqual(self.report["avx2_fde"]["candidate_versions"], ["1.14.0", "1.14.1"])

    def test_avx2_arm_is_gated_by_a15(self):
        gate = self.report["feature_path"]
        self.assertEqual(gate["cached_word"], "A")
        self.assertEqual(gate["tested_bit"], 15)
        self.assertEqual(gate["support"], ["cpuid leaf 7 subleaf 0 ebx bit 5"])
        self.assertEqual(gate["set_bit_branch"]["condition"], "JS")
        self.assertEqual(gate["set_bit_branch"]["target"], "0x167abcc")
        self.assertEqual(gate["clear_bit_branch"]["condition"], "JNS")
        self.assertEqual(gate["clear_bit_branch"]["target"], "0x167ab00")
        self.assertEqual(gate["gated_call"]["target"], "0x167ac00")
        self.assertEqual(gate["xcr0_gate"], "XCR0 bits 1 and 2, per the A bit 15 provenance record")

    def test_cache_slots_resolve_to_a_and_refresh_helper(self):
        cache = self.report["cache"]
        self.assertEqual(cache["pointer_slot"], "0x64dfa60")
        self.assertEqual(cache["word_address"], "0x6500098")
        self.assertEqual(cache["refresh_pointer_slot"], "0x64dfa68")
        self.assertEqual(cache["refresh_helper"], "0x5cadd50")

    def test_avx2_body_is_bound_to_the_pinned_target(self):
        body = dispatch._read_va(self.data, dispatch.AVX2_BODY[0], 975)
        self.assertTrue(body.startswith(bytes.fromhex("415741564154534883f9200f82")))
        self.assertIn(bytes.fromhex("c5f877"), body)  # vzeroupper
        self.assertTrue(self.report["global_target_cpu_features"].startswith("unresolved;"))

    def test_wrong_target_digest_is_rejected(self):
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaisesRegex(dispatch.EvidenceError, "wrong target digest"):
            dispatch.analyze(bytes(changed))

    def test_inverted_feature_branch_is_rejected(self):
        changed = bytearray(self.data)
        instruction = dispatch._read_va(self.data, dispatch.FEATURE_BRANCH, 6)
        # Locate the VA in its file-backed ELF section, then invert JS to JNS.
        section = next(s for s in dispatch.sections(self.data)
                       if s["type"] != 8 and s["address"] <= dispatch.FEATURE_BRANCH
                       and dispatch.FEATURE_BRANCH + 6 <= s["address"] + s["size"])
        file_offset = section["offset"] + dispatch.FEATURE_BRANCH - section["address"]
        changed[file_offset + 1] = 0x89
        self.assertEqual(instruction[1], 0x88)
        with self.assertRaisesRegex(dispatch.EvidenceError, "unexpected opcode"):
            dispatch._rel32_target(bytes(changed), dispatch.FEATURE_BRANCH,
                                   bytes.fromhex("0f88"), 6)


if __name__ == "__main__":
    unittest.main()
