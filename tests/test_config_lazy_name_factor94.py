import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import config_lazy_name_factor94 as subject


class ConfigLazyNameFactorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(subject.BINARY.read_bytes())
        cls.secs = subject.sections(cls.data)
        cls.result = subject.build(cls.data)
        cls.words = subject.factor_bits(cls.data, cls.secs)

    def mutate(self, offset, replacement, check):
        original = self.data[offset:offset + len(replacement)]
        try:
            self.data[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                check()
        finally:
            self.data[offset:offset + len(replacement)] = original

    def test_input_identity_accepts_exact_capture(self):
        subject.verify_identity(self.data)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA256)

    def test_identity_rejects_changed_hash_and_size(self):
        self.mutate(0, b'X', lambda: subject.verify_identity(self.data))
        with self.assertRaises(ValueError):
            subject.verify_identity(b'\x7fELF')

    def test_selected_fde_and_function_lengths(self):
        functions = self.result[0]
        self.assertEqual([(f['start'], f['end'], f['size']) for f in functions], [
            (0x1402750, 0x14027a9, 89),
            (0x164c560, 0x164c5c6, 102),
            (0x164c5d0, 0x164c636, 102),
        ])
        self.assertTrue(all(f['lsda'] is None for f in functions))

    def test_changed_fde_extent_is_rejected(self):
        fde = self.result[0][0]['fde']
        offset = subject.va_offset(self.data, self.secs, fde, 16) + 12
        self.mutate(offset, bytes([self.data[offset] ^ 1]),
                    lambda: subject.fde_rows(self.data, self.secs))

    def test_changed_branch_polarity_is_rejected(self):
        offset = subject.va_offset(self.data, self.secs, 0x1402761, 1)
        self.mutate(offset, b'\x74', lambda: subject.check_code(self.data, self.secs))

    def test_changed_branch_destination_is_rejected(self):
        offset = subject.va_offset(self.data, self.secs, 0x164c576, 1)
        self.mutate(offset, bytes([self.data[offset] + 1]),
                    lambda: subject.branches(self.data, self.secs))
        with self.assertRaises(ValueError):
            subject.short_target(0x100, b'\x90\x00')

    def test_changed_cell_store_is_rejected(self):
        offset = subject.va_offset(self.data, self.secs, 0x164c5aa, 1)
        self.mutate(offset, bytes([self.data[offset] ^ 1]),
                    lambda: subject.check_code(self.data, self.secs))

    def test_callback_twin_branches(self):
        got = {row['label']: row['target'] for row in self.result[2]}
        self.assertEqual(got['slot20_null'], 0x164c5b3)
        self.assertEqual(got['slot20_state_byte_one'], 0x164c5c0)
        self.assertEqual(got['slot18_null'], 0x164c623)
        self.assertEqual(got['slot18_state_byte_one'], 0x164c630)
        self.assertEqual(got['reader_resume'], 0x1402763)

    def test_failure_helper_return_sites_and_breakpoint_control(self):
        rows = subject.failure_returns(self.data, self.secs)
        self.assertEqual([(r['continuation'], r['following']) for r in rows], [
            (0x164c5c0, 'ff15a2221204'), (0x164c5c6, 'cc'),
            (0x164c630, 'ff1532221204'), (0x164c636, 'cc')])
        for address in (0x164c5c6, 0x164c636):
            with self.subTest(address=address):
                offset = subject.va_offset(self.data, self.secs, address, 1)
                self.mutate(offset, b'\x90',
                            lambda: subject.failure_returns(self.data, self.secs))

    def test_context_consumption_and_copy_ranges(self):
        for base in (0x164c560, 0x164c5d0):
            code = subject.read_va(self.data, self.secs, base, 102)
            self.assertEqual(code[5:18], bytes.fromhex('488b07488b1848c70000000000'))
            self.assertEqual(code[0x22:0x2b], bytes.fromhex('0f104424400f114340'))
            self.assertEqual(code[0x3e:0x4d], bytes.fromhex('0f115b300f1153200f114b100f1103'))

    def test_name_domain_and_exact_independent_one_set(self):
        expected_one = {1, 2, 9, 10, 11, 12, 14, 15, 17, 19, 21, 24, 25, 34, 35, 36}
        actual = {i for i in range(76) if subject.factor_at(self.words, i) == 1.0}
        self.assertEqual(actual, expected_one)
        self.assertEqual(len(self.words) - len(actual), 60)

    def test_named_context_and_table_boundaries(self):
        summary = self.result[-1]
        self.assertEqual(summary['context']['default_name'], 'NvTestnet')
        self.assertEqual(summary['context']['default_discriminant'], 32)
        self.assertEqual([(r['name'], r['factor']) for r in self.result[-2]], [
            ('NvTestnet', 5.0), ('NvTestnet2', 5.0),
            ('NvMainnet', 1.0), ('NvMainnet2', 1.0)])
        self.assertEqual([subject.factor_at(self.words, i) for i in (0, 31, 32, 33, 34, 35, 75)],
                         [5.0, 5.0, 5.0, 5.0, 1.0, 1.0, 5.0])
        for index in (-1, 76, 255, True, 1.0):
            with self.subTest(index=index), self.assertRaises(ValueError):
                subject.factor_at(self.words, index)

    def test_changed_table_byte_and_valid_value_swap_rejected(self):
        offset = subject.va_offset(self.data, self.secs, subject.TABLE + 34 * 8, 8)
        self.mutate(offset, struct.pack('<Q', 0x4014000000000000),
                    lambda: subject.factor_bits(self.data, self.secs))
        self.mutate(offset, bytes.fromhex('0100000000000000'),
                    lambda: subject.factor_bits(self.data, self.secs))

    def test_changed_initial_cell_word_and_vtable_head_rejected(self):
        offset = subject.va_offset(self.data, self.secs, subject.ONCE_WORD, 4)
        self.mutate(offset, struct.pack('<I', 2),
                    lambda: subject.cell_context(self.data, self.secs))
        offset = subject.va_offset(self.data, self.secs, subject.VTABLE + 8, 8)
        self.mutate(offset, struct.pack('<Q', 16),
                    lambda: subject.cell_context(self.data, self.secs))

    def test_name_prefix_length_and_pointer_corruption_rejected(self):
        rows = self.result[4]
        rec = rows[0x5668488]['rela_file_offset']
        wanted = {slot for _, slot, _ in subject.SLOTS} | {
            subject.DESCRIPTORS + 16 * index for index, _, _ in subject.NAME_CONTEXT}
        self.mutate(rec + 16, struct.pack('<q', 0x218108),
                    lambda: subject.name_contexts(self.data, self.secs,
                        subject.selected_relocations(self.data, self.secs, wanted), self.words))
        offset = subject.va_offset(self.data, self.secs, 0x5668490, 8)
        self.mutate(offset, struct.pack('<Q', 10),
                    lambda: subject.name_contexts(self.data, self.secs, rows, self.words))

    def test_rewired_vtable_callback_rejected(self):
        rec = self.result[4][0x567b230]['rela_file_offset']
        self.mutate(rec + 16, struct.pack('<q', 0x164c5d0),
                    lambda: subject.check_slot_targets(subject.selected_relocations(
                        self.data, self.secs, {slot for _, slot, _ in subject.SLOTS})))

    def test_relocation_bindings(self):
        rows = self.result[4]
        self.assertEqual(rows[0x576e928]['addend'], 0x577b288)
        self.assertEqual(rows[0x577b288]['addend'], 0x164ff00)
        self.assertEqual(rows[0x567b230]['addend'], 0x164c560)
        self.assertEqual(rows[0x567b228]['addend'], 0x164c5d0)

    def test_wrong_relocation_type_and_addend_rejected(self):
        rows = self.result[4]
        rec = rows[0x576e928]['rela_file_offset']
        self.mutate(rec + 8, struct.pack('<Q', 7),
                    lambda: subject.selected_relocations(self.data, self.secs, {0x576e928}))
        self.mutate(rec + 16, struct.pack('<q', 0x577b289),
                    lambda: subject.check_slot_targets(subject.selected_relocations(
                        self.data, self.secs, {slot for _, slot, _ in subject.SLOTS})))

    def test_duplicate_selected_relocation_is_rejected(self):
        rec = self.result[4][0x576e928]['rela_file_offset']
        next_rec = rec + 24
        self.mutate(next_rec, struct.pack('<Q', 0x576e928),
                    lambda: subject.selected_relocations(self.data, self.secs, {0x576e928}))

    def test_missing_outside_and_nobits_mappings_rejected(self):
        raw = b'abcdefgh'
        backed = {'name': 'data', 'type': 1, 'address': 100, 'offset': 0, 'size': 8, 'flags': 2}
        nobits = {'name': 'bss', 'type': 8, 'address': 200, 'offset': 0, 'size': 8, 'flags': 2}
        self.assertEqual(subject.read_va(raw, [backed, nobits], 106, 2), b'gh')
        for address, size in ((200, 1), (107, 2), (108, 1), (-1, 1), (100, 0)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                subject.read_va(raw, [backed, nobits], address, size)
        with self.assertRaises(ValueError):
            subject.read_va(raw, [backed, dict(backed)], 100, 1)

    def test_rip_target_and_invalid_instruction(self):
        raw = subject.read_va(self.data, self.secs, 0x1402767, 7)
        self.assertEqual(subject.rip_target(0x1402767, raw), 0x218640)
        with self.assertRaises(ValueError):
            subject.rip_target(0x1402767, b'\x90' * 7)

    def test_regeneration_and_summary(self):
        with tempfile.TemporaryDirectory() as parent:
            a = Path(parent) / 'a'
            b = Path(parent) / 'b'
            first = subject.generate(self.data, a)
            second = subject.generate(self.data, b)
            self.assertEqual(first, second)
            self.assertEqual(first['selected'], {
                'functions': 3, 'fact_windows': 47, 'short_branches': 6,
                'rip_references': 11, 'relocations': 12, 'failure_return_sites': 4})
            files_a = sorted(p.name for p in a.iterdir())
            self.assertEqual(files_a, sorted(p.name for p in b.iterdir()))
            for name in files_a:
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
