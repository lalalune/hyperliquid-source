"""Regression controls for the 0x1000 TLS-layout transcription error."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_lu_coop_context as coop
import node115_lu_tag_meaning as tag


class TLSOffsets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coop = bytes.fromhex((coop.PACKET / 'coop.hex').read_text())
        cls.helper = bytes.fromhex((tag.PACKET / 'helper.hex').read_text())
        cls.coop_record = json.loads((coop.PACKET / 'records.json').read_text(encoding='utf-8'))
        cls.tag_record = json.loads((tag.PACKET / 'records.json').read_text(encoding='utf-8'))

    def test_coop_bound_offsets(self):
        self.assertEqual(coop.validate_tls_record(self.coop, self.coop_record), {
            'base': -0x1130, 'state_byte': -0x10e8,
            'route_byte': -0x10ea, 'object_pointer': -0x1108,
        })

    def test_helper_bound_offsets(self):
        self.assertEqual(tag.validate_tls_record(self.helper, self.tag_record), {
            'r15': '-0x1130', 'state_byte': 'fs:[-0x10e8]',
            'word': 'fs:[-0x10ec]', 'byte': 'fs:[-0x10eb]',
        })

    def test_old_helper_metadata_rejected_below_body_hash_guard(self):
        old = dict(self.tag_record, tls={
            'r15': '-0x130', 'state_byte': 'fs:[-0xe8]',
            'word': 'fs:[-0xec]', 'byte': 'fs:[-0xeb]',
        })
        with self.assertRaisesRegex(ValueError, 'signed operands'):
            tag.validate_tls_record(self.helper, old)

    def test_old_coop_metadata_rejected_below_body_hash_guard(self):
        old = dict(self.coop_record, tls_offsets={
            'base': -0x130, 'state_byte': -0xe8,
            'route_byte': -0xea, 'object_pointer': -0x108,
        })
        with self.assertRaisesRegex(ValueError, 'signed operands'):
            coop.validate_tls_record(self.coop, old)

    def test_old_immediate_mutant_rejected_against_correct_record(self):
        for module, body, index, record in (
            (coop, self.coop, 8, self.coop_record),
            (tag, self.helper, 0x18, self.tag_record),
        ):
            with self.subTest(module=module.__name__):
                altered = bytearray(body)
                altered[index] = 0xfe  # d0 ee ff ff -> d0 fe ff ff: -0x130.
                with self.assertRaisesRegex(ValueError, 'signed operands'):
                    module.validate_tls_record(altered, record)

    def test_displacement_mutants_rejected_against_record(self):
        for module, body, indices, record in (
            (coop, self.coop, (0x0f, 0x44, 0x4c), self.coop_record),
            (tag, self.helper, (0x2c, 0x5a, 0x75), self.tag_record),
        ):
            for index in indices:
                with self.subTest(module=module.__name__, index=index):
                    altered = bytearray(body)
                    altered[index] ^= 1
                    with self.assertRaises(ValueError):
                        module.validate_tls_record(altered, record)

    def test_signed_imm32_boundary_vectors(self):
        for module, body, index, key in (
            (coop, self.coop, 7, 'base'),
            (tag, self.helper, 0x17, 'r15'),
        ):
            for raw, expected in ((b'\x00\x00\x00\x80', -2147483648),
                                  (b'\xd0\xee\xff\xff', -4400),
                                  (b'\xd0\xfe\xff\xff', -304),
                                  (b'\x00\x00\x00\x00', 0),
                                  (b'\xff\xff\xff\x7f', 2147483647)):
                with self.subTest(module=module.__name__, expected=expected):
                    altered = bytearray(body)
                    altered[index:index + 4] = raw
                    result = module.tls_offsets(altered)[key]
                    self.assertEqual(result, expected if module is coop else hex(expected))

    def test_truncated_or_wrong_opcode_refused(self):
        for module, body, index in ((coop, self.coop, 4), (tag, self.helper, 0x14)):
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.tls_offsets(body[:index + 3])
                altered = bytearray(body)
                altered[index] ^= 1
                with self.assertRaises(ValueError):
                    module.tls_offsets(altered)


if __name__ == '__main__':
    unittest.main()
