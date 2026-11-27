import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_d1_address_encoding_115 as subject
from elf_index import sections


class D1AddressEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subject.TARGET.read_bytes()

    def test_records_reproduce(self):
        expected = json.loads((ROOT / 'research/work-items/RE-005-node115-d1-address-encoding-bridge/records.json')
                              .read_text(encoding='utf-8'))
        self.assertEqual(subject.extract(self.original), expected)

    def test_wrong_target_identity_rejects(self):
        changed = bytearray(self.original)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target size/SHA-256 mismatch'):
            subject.extract(bytes(changed))

    def test_serializer_field_call_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x240f20b - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x240f20b'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_serializer_variant_pointer_adjustment_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x2bced39 - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x2bced39'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_serializer_variant_call_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x2bced9e - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x2bced9e'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_method_variant_pointer_adjustment_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x36c3696 - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x36c3696'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_enum_variant_literal_corruption_rejects(self):
        changed = bytearray(self.original)
        rodata = next(s for s in sections(changed) if s['name'] == '.rodata')
        offset = rodata['offset'] + 0x5f174d - rodata['address']
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'rodata witness mismatch at 0x5f174d'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_method_callback_output_handoff_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x442d194 - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x442d194'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_typed_data_callback_reuse_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x44289ca - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x44289b2'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_typed_data_hash_handoff_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x44340ef - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x44340ef'):
            subject.extract(bytes(changed), expected_digest=None)


if __name__ == '__main__':
    unittest.main()
