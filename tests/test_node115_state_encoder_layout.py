"""Target-bound structural corruption controls, not target execution/equivalence."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-state-encoder-layout-115"
spec = importlib.util.spec_from_file_location("state_encoder_layout_115", PACKET / "extract.py")
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)


class StateEncoderLayoutControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
        layout.identity(cls.data)
        cls.report = json.loads((PACKET / "field-layout.json").read_text(encoding="utf-8"))
        cls.mapping = layout.loads(cls.data)

    def patch(self, va, replacement):
        result = bytearray(self.data)
        off = layout.file_offset(self.mapping, va, len(replacement))
        result[off:off + len(replacement)] = replacement
        return result

    def test_authenticated_reproduction_matches_retained_evidence(self):
        self.assertEqual(layout.analyze(self.data), self.report)

    def test_truncated_artifact_rejected(self):
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            layout.identity(self.data[:-1])

    def test_changed_byte_outside_selected_code_rejected_by_full_identity(self):
        result = bytearray(self.data)
        result[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            layout.identity(result)

    def test_header_count_corruption_rejected(self):
        # Actual MOV edx,59 immediately before named exchange-header call.
        call = int(self.report["headers"][2]["call"], 16)
        off = layout.file_offset(self.mapping, call - 5, 5)
        self.assertEqual(self.data[off:off + 5], b"\xba\x3b\0\0\0")
        with self.assertRaisesRegex(ValueError, "header order/count"):
            layout.analyze(self.patch(call - 4, b"\x3a"))

    def test_native_field_displacement_change_is_reported(self):
        row = self.report["fields"][3]["sourceInstructions"][0]
        va = int(row["va"], 16)
        self.assertEqual(row["operands"], "rdx, [r15 + 0x7d8]")
        changed = layout.analyze(self.patch(va + 3, struct.pack("<i", 0x7e0)))
        self.assertNotEqual(changed["fields"][3], self.report["fields"][3])
        self.assertIn("0x7e0", changed["fields"][3]["sourceInstructions"][0]["operands"])

    def test_exact_key_bytes_change_is_reported(self):
        row = self.report["fields"][3]["key"]
        changed = layout.analyze(self.patch(int(row["va"], 16), b"g"))
        self.assertEqual(changed["fields"][3]["key"]["text"], "gtr")
        self.assertNotEqual(changed, self.report)

    def test_non_ascii_key_rejected(self):
        va = int(self.report["fields"][3]["key"]["va"], 16)
        with self.assertRaisesRegex(ValueError, "printable ASCII"):
            layout.analyze(self.patch(va, b"\0"))

    def test_wrong_success_comparison_rejected(self):
        row = self.report["fields"][0]["resultGuard"][1]
        self.assertEqual(row["bytes"], "4c39e0")
        with self.assertRaisesRegex(ValueError, "success/error guard"):
            layout.analyze(self.patch(int(row["va"], 16), bytes.fromhex("4c39e8")))

    def test_wrong_error_branch_destination_rejected(self):
        row = self.report["fields"][0]["resultGuard"][2]
        va = int(row["va"], 16)
        self.assertTrue(row["bytes"].startswith("0f85"))
        changed = self.patch(va + 2, struct.pack("<i", 0x5481675 - (va + 6)))
        with self.assertRaisesRegex(ValueError, "success/error guard"):
            layout.analyze(changed)

    def test_valid_but_different_callee_is_not_silently_accepted_as_same_evidence(self):
        va = int(self.report["fields"][0]["call"], 16)
        changed = self.patch(va + 1, struct.pack("<i", 0x4d6fce0 - (va + 5)))
        report = layout.analyze(changed)
        self.assertEqual(report["fields"][0]["helper"], "0x4d6fce0")
        self.assertNotEqual(report, self.report)

    def test_deleted_value_dispatch_rejected(self):
        va = int(self.report["fields"][-1]["call"], 16)
        with self.assertRaisesRegex(ValueError, "75 value dispatches"):
            layout.analyze(self.patch(va, b"\x90" * 5))

    def test_fde_end_change_rejected(self):
        va = int(self.report["outer"]["fde"], 16)
        off = layout.file_offset(self.mapping, va, 16)
        self.assertEqual(struct.unpack_from("<i", self.data, off + 12)[0], 3388)
        with self.assertRaisesRegex(ValueError, "Outer FDE end"):
            layout.analyze(self.patch(va + 12, struct.pack("<i", 3389)))

    def test_ambiguous_and_unbacked_coordinates_rejected(self):
        va = layout.START
        with self.assertRaisesRegex(ValueError, "Ambiguous/unbacked"):
            layout.file_offset(self.mapping + self.mapping, va, 1)
        with self.assertRaisesRegex(ValueError, "Ambiguous/unbacked"):
            layout.file_offset(self.mapping, 1 << 63, 16)


if __name__ == "__main__":
    unittest.main()
