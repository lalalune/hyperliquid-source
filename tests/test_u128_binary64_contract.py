"""Actual pinned-input and fixed-row corruption controls; no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_binary64_contract as subject


class Binary64ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.body = (subject.PACKET / 'native/target-132.bin').read_bytes()
        cls.observed = json.loads((subject.PACKET / 'native/record.json').read_text())

    def test_complete_actual_body(self):
        result = subject.inspect_target(self.target)
        self.assertEqual(result['body_sha256'], subject.BODY_SHA256)
        self.assertEqual(result['proof']['rows'], 36)
        self.assertEqual(result['proof']['returns'], [0x5660003])
        self.assertEqual(result['selected_frame']['end'], subject.BEGIN + 132)

    def test_actual_instruction_change_bypasses_file_guard_then_rejects(self):
        # Actual AND edx,r10d -> XOR: changes the nearest-even increment relation.
        changed = bytearray(self.body)
        changed[0x57] ^= 0x10
        with self.assertRaisesRegex(ValueError, 'instruction encoding differs'):
            subject.prove_body(bytes(changed))

    def test_truncated_complete_body_rejects(self):
        with self.assertRaisesRegex(ValueError, '132-byte body required'):
            subject.prove_body(self.body[:-1])

    def test_actual_fde_size_change_bypasses_digest_guard_then_rejects(self):
        changed = bytearray(self.target)
        off = self.observed['target']['selected_frame']['FDE_range_file_offset']
        struct.pack_into('<I', changed, off, 133)
        with self.assertRaisesRegex(ValueError, 'FDE extent disagreement'):
            subject.inspect_target(bytes(changed))

    def test_actual_slot_kind_change_bypasses_digest_guard_then_rejects(self):
        changed = bytearray(self.target)
        off = self.observed['target']['slot']['record_file_offset']
        struct.pack_into('<Q', changed, off + 8, 1)
        with self.assertRaisesRegex(ValueError, 'RELATIVE relocation'):
            subject.inspect_target(bytes(changed))

    def add_slot_write(self, address):
        changed = bytearray(self.target)
        selected = self.observed['target']['slot']['record_file_offset']
        table = subject.Elf(self.target, 3).by_name('.rela.dyn')
        spare = table['offset'] if table['offset'] != selected else table['offset'] + 24
        struct.pack_into('<QQq', changed, spare, address, 8, subject.BEGIN)
        return bytes(changed)

    def test_actual_duplicate_selected_slot_write_rejects(self):
        with self.assertRaisesRegex(ValueError, 'one symbol-zero RELATIVE relocation'):
            subject.inspect_target(self.add_slot_write(subject.SLOT))

    def test_actual_partial_selected_slot_write_rejects(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting or partial selected-slot RELA write'):
            subject.inspect_target(self.add_slot_write(subject.SLOT + 4))

    def test_full_input_admission_rejects_changed_target(self):
        changed = bytearray(self.target)
        changed[self.observed['target']['mapping']['file_offset']] ^= 1
        with self.assertRaisesRegex(ValueError, 'Target identity differs'):
            subject.analyze(bytes(changed), b'not-an-archive')

    def test_full_archive_admission_rejects_unpinned_input(self):
        with self.assertRaisesRegex(ValueError, 'archive identity differs'):
            subject.analyze(self.target, b'not-an-archive')

    def test_retained_both_actual_candidates_equal(self):
        records = self.observed['official']['definitions']
        self.assertEqual(len(records), 2)
        self.assertEqual({row['member'] for row in records}, set(subject.DEFINITIONS))
        for row in records:
            self.assertEqual(bytes.fromhex(row['body_hex']), self.body)
            self.assertEqual(row['code_relocations'], [])
        self.assertTrue(all(row['raw_equal'] for row in self.observed['comparison']))
        self.assertEqual(self.observed['selected_interval_denominator'], 1)


if __name__ == '__main__':
    unittest.main()
