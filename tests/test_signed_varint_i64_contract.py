"""Actual immutable native closure and below-identity corruption controls."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import signed_varint_i64_contract as subject


class SignedContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.body = (subject.PACKET / 'native/target.bin').read_bytes()
        cls.snapshot = subject.analyze(cls.target)

    def test_actual_complete_primary_and_separate_helpers(self):
        self.assertEqual([x['bytes'] for x in self.snapshot['bodies']], [357, 316, 14])
        self.assertEqual(self.snapshot['primary_certificate']['rows'], 99)
        self.assertEqual(self.snapshot['all_RELA_records_scanned'], 80300)
        self.assertEqual(self.snapshot['previous_helper_bytes'], 330)
        self.assertEqual(len(self.snapshot['jump_tables']), 2)

    def test_actual_zigzag_neg_to_not_bypasses_identity_then_rejects(self):
        changed = bytearray(self.body)
        self.assertEqual(changed[0xad], 0xd9)
        changed[0xad] ^= 8  # Actual NEG rcx -> NOT rcx, no captured execution.
        with self.assertRaisesRegex(ValueError, 'instruction encoding differs'):
            subject.prove_primary(bytes(changed))

    def test_truncated_body_rejects(self):
        with self.assertRaisesRegex(ValueError, 'Complete immutable357-byte body'):
            subject.prove_primary(self.body[:-1])

    def test_actual_fde_extent_change_below_identity_rejects(self):
        changed = bytearray(self.target)
        offset = self.snapshot['bodies'][0]['frame']['FDE_range_file_offset']
        struct.pack_into('<I', changed, offset, 356)
        with self.assertRaisesRegex(ValueError, 'FDE extent disagreement'):
            subject.inspect(bytes(changed))

    def test_actual_primary_jump_destination_change_rejects(self):
        changed = bytearray(self.target)
        offset = self.snapshot['jump_tables'][0]['mapping']['file_offset']
        struct.pack_into('<i', changed, offset, 0)
        with self.assertRaisesRegex(ValueError, 'jump-table destinations differ'):
            subject.inspect(bytes(changed))

    def test_actual_child_jump_destination_change_rejects(self):
        changed = bytearray(self.target)
        offset = self.snapshot['jump_tables'][1]['mapping']['file_offset']
        struct.pack_into('<i', changed, offset, 0)
        with self.assertRaisesRegex(ValueError, 'jump-table destinations differ'):
            subject.inspect(bytes(changed))

    def test_actual_typed_helper_slot_kind_change_rejects(self):
        changed = bytearray(self.target)
        offset = self.snapshot['slots'][0]['typed_relative']['record_file_offset']
        struct.pack_into('<Q', changed, offset + 8, 1)
        with self.assertRaisesRegex(ValueError, 'one symbol-zero RELATIVE relocation'):
            subject.inspect(bytes(changed))

    def extra_write(self, address):
        changed = bytearray(self.target)
        table = subject.Elf(self.target, 3).by_name('.rela.dyn')
        selected = self.snapshot['slots'][0]['typed_relative']['record_file_offset']
        offset = table['offset'] if table['offset'] != selected else table['offset'] + 24
        struct.pack_into('<QQq', changed, offset, address, 8, 0x466d980)
        return bytes(changed)

    def test_actual_duplicate_helper_slot_write_rejects(self):
        with self.assertRaisesRegex(ValueError, 'one symbol-zero RELATIVE relocation'):
            subject.inspect(self.extra_write(0x57745e0))

    def test_actual_partial_helper_slot_write_rejects(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting or partial selected helper-slot write'):
            subject.inspect(self.extra_write(0x57745e4))

    def test_actual_eight_byte_rela_crossing_code_start_rejects(self):
        changed = bytearray(self.target)
        table = subject.Elf(self.target, 3).by_name('.rela.dyn')
        struct.pack_into('<QQq', changed, table['offset'], subject.PRIMARY - 4, 18, 0)
        with self.assertRaisesRegex(ValueError, 'relocation may overlap selected code'):
            subject.inspect(bytes(changed))

    def test_full_changed_target_identity_rejects(self):
        changed = bytearray(self.target)
        changed[self.snapshot['bodies'][0]['mapping']['file_offset']] ^= 1
        with self.assertRaisesRegex(ValueError, 'Full immutable node94 identity differs'):
            subject.analyze(bytes(changed))


if __name__ == '__main__':
    unittest.main()
