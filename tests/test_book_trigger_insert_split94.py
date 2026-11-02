"""Static controls for the digest-bound order-index insertion evidence."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import book_trigger_insert_split94 as evidence
from tools.elf_index import sections


class TriggerIndexInsertionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(evidence.TARGET.read_bytes())
        evidence.validate_identity(cls.data)

    def mutate(self, va):
        off = evidence.file_offset(self.data, va, 1)
        original = self.data[off]
        self.data[off] ^= 1
        self.addCleanup(self.data.__setitem__, off, original)
        return off

    def test_identity_rejects_changed_bytes_and_truncation_before_parsing(self):
        self.mutate(0x28526f0)
        with tempfile.TemporaryDirectory() as temp, patch.object(evidence, 'fde_extents') as fdes:
            out = Path(temp) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'digest'):
                evidence.collect(self.data, out)
            fdes.assert_not_called()
            self.assertFalse(out.exists())
        with self.assertRaisesRegex(ValueError, 'digest'):
            evidence.validate_identity(b'\x7fELF')

    def test_every_witness_rejects_corrupted_local_byte(self):
        for item in evidence.WITNESSES:
            with self.subTest(witness=item[0]):
                original = evidence.checked_witness(self.data, item)
                off = evidence.file_offset(self.data, item[1], 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'Witness bytes changed'):
                        evidence.checked_witness(self.data, item)
                finally:
                    self.data[off] ^= 1
                self.assertEqual(evidence.checked_witness(self.data, item), original)

    def test_all_leaf_and_parent_positions_preserve_order(self):
        pivots = [4, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 6]
        sides = ['left'] * 6 + ['right'] * 6
        left_lengths = [5, 5, 5, 5, 5, 6, 5, 6, 6, 6, 6, 6]
        for parent in (False, True):
            for index in range(12):
                with self.subTest(parent=parent, index=index):
                    row = evidence.split_projection(self.data, index, parent=parent)
                    self.assertEqual(row['old_pivot_index'], pivots[index])
                    self.assertEqual(row['side'], sides[index])
                    self.assertEqual(len(row['left']), left_lengths[index])
                    self.assertEqual(len(row['left']) + len(row['right']), 11)
                    original = [f'old-{i:02d}' for i in range(11)]
                    original.insert(index, 'new')
                    combined = row['left'] + [row['promoted']] + row['right']
                    self.assertEqual(combined, original)
                    self.assertEqual(combined.count('new'), 1)
                    if parent:
                        children = [f'child-{i:02d}' for i in range(12)]
                        children.insert(index + 1, 'new-right-child')
                        self.assertEqual(row['left_children'] + row['right_children'], children)
                        self.assertEqual(len(row['left_children']), len(row['left']) + 1)
                        self.assertEqual(len(row['right_children']), len(row['right']) + 1)

    def test_each_selected_branch_rejects_opcode_and_displacement_corruption(self):
        for name, site, opcode in evidence.BRANCHES:
            with self.subTest(branch=name):
                instruction, _ = evidence.decode_branch(self.data, site, opcode)
                witness = next(w for w in evidence.WITNESSES
                               if w[1] <= site and site + len(instruction) <= w[2])
                for byte in range(len(instruction)):
                    off = evidence.file_offset(self.data, site + byte, 1, True)
                    self.data[off] ^= 1
                    try:
                        with self.assertRaisesRegex(ValueError, 'Witness bytes changed'):
                            evidence.checked_witness(self.data, witness)
                    finally:
                        self.data[off] ^= 1

    def test_split_index_and_decision_corruption_are_rejected(self):
        for value in (-1, 12, 2 ** 64, None, True):
            with self.subTest(index=value), self.assertRaises(ValueError):
                evidence.split_choice(self.data, value)
        self.mutate(0x1ad5d0b)
        with self.assertRaisesRegex(ValueError, 'decision instruction'):
            evidence.split_choice(self.data, 5)

    def test_parent_decision_corruption_is_rejected(self):
        self.mutate(0x1ad6769)
        with self.assertRaisesRegex(ValueError, 'Parent split decision'):
            evidence.split_choice(self.data, 6, parent=True)

    def test_executable_mapping_rejects_bss_range_and_end_overrun(self):
        bss = next(s for s in sections(self.data) if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            evidence.file_offset(self.data, bss['address'], 1)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            evidence.file_offset(self.data, 2 ** 64 - 1, 2, True)
        with self.assertRaises(ValueError):
            evidence.file_offset(self.data, 0, 0)

    def test_call_target_and_indirect_opcode_corruption(self):
        evidence.direct_call(self.data, 0x28527f4, 0x1ad5cd0)
        off = self.mutate(0x28527f5)
        with self.assertRaisesRegex(ValueError, 'target changed'):
            evidence.direct_call(self.data, 0x28527f4, 0x1ad5cd0)
        self.data[off] ^= 1
        self.mutate(0x1ad5e9c)
        with self.assertRaisesRegex(ValueError, 'indirect call'):
            evidence.indirect_slot(self.data, 0x1ad5e9c, 0x576dfd8)

    def test_branch_opcode_and_destination_controls(self):
        site = 0x1ad5ea5
        raw, target = evidence.decode_branch(self.data, site, '0f84')
        self.assertEqual((len(raw), target), (6, 0x1ad7287))
        off = self.mutate(site)
        with self.assertRaisesRegex(ValueError, 'opcode'):
            evidence.decode_branch(self.data, site, '0f84')
        self.data[off] ^= 1
        pos = evidence.file_offset(self.data, site + 2, 4, True)
        prior = bytes(self.data[pos:pos + 4])
        self.data[pos:pos + 4] = b'\xff\xff\xff\x7f'
        try:
            with self.assertRaisesRegex(ValueError, 'file-backed'):
                evidence.decode_branch(self.data, site, '0f84')
        finally:
            self.data[pos:pos + 4] = prior

    def test_twin_controls_cover_masked_and_unmasked_bytes(self):
        masks, normalized = evidence.twin_comparison(self.data)
        self.assertEqual(len(masks), 9)
        self.assertEqual(normalized, '0fe03b4d2ae3f84b7faa5cc8e3ba394875b8a5701dd1c2c487487beb5ccb70cd')
        off = self.mutate(0x28577e0)
        with self.assertRaisesRegex(ValueError, 'outside declared operands'):
            evidence.twin_comparison(self.data)
        self.data[off] ^= 1
        self.mutate(0x28578e5)
        with self.assertRaisesRegex(ValueError, 'targets differ'):
            evidence.twin_comparison(self.data)

    def test_constant_instruction_corruption(self):
        for spec in evidence.CONSTANTS:
            with self.subTest(label=spec[0]):
                evidence.read_constant(self.data, spec)
        self.mutate(0x1ad5e98)
        spec = next(s for s in evidence.CONSTANTS if s[0] == 'leaf-allocation-bytes')
        with self.assertRaisesRegex(ValueError, 'Constant instruction'):
            evidence.read_constant(self.data, spec)

    def test_selected_relocation_corruption(self):
        slots = {slot for _, _, slot in evidence.INDIRECT}
        evidence.checked_relocations(self.data, slots)
        section = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            if int.from_bytes(self.data[pos:pos + 8], 'little') == 0x576dfd8:
                break
        else:
            self.fail('selected relocation missing')
        old = self.data[pos + 8]
        self.data[pos + 8] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'relocation changed'):
                evidence.checked_relocations(self.data, slots)
        finally:
            self.data[pos + 8] = old

    def test_diagnostics_require_exact_text_and_location_fields(self):
        rows = evidence.diagnostics(self.data)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0][7], 'assertion failed: idx < CAPACITY')
        self.assertEqual(rows[0][8], 'alloc/src/collections/btree/node.rs')
        off = self.mutate(0x20ca60)
        with self.assertRaisesRegex(ValueError, 'Diagnostic text'):
            evidence.diagnostics(self.data)
        self.data[off] ^= 1
        self.mutate(0x5688438 + 16)
        with self.assertRaisesRegex(ValueError, 'Location fields'):
            evidence.diagnostics(self.data)

    def test_dynamic_symbol_names_and_corrupt_string_are_checked(self):
        self.assertEqual(evidence.dynamic_symbol_name(self.data, 6), 'memcpy')
        self.assertEqual(evidence.dynamic_symbol_name(self.data, 9), 'memmove')
        with self.assertRaisesRegex(ValueError, 'index outside'):
            evidence.dynamic_symbol_name(self.data, 2 ** 32)
        syms = next(s for s in sections(self.data) if s['name'] == '.dynsym')
        strings = next(s for s in sections(self.data) if s['name'] == '.dynstr')
        name_index = int.from_bytes(self.data[syms['offset'] + 6 * 24:syms['offset'] + 6 * 24 + 4], 'little')
        pos = strings['offset'] + name_index
        previous = self.data[pos]
        self.data[pos] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'symbol name changed'):
                evidence.checked_relocations(self.data, {0x576dfe0})
        finally:
            self.data[pos] = previous

    def test_duplicate_relocation_slot_rejected(self):
        slots = {slot for _, _, slot in evidence.INDIRECT}
        section = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        pos = next(pos for pos in range(section['offset'], section['offset'] + section['size'], 24)
                   if int.from_bytes(self.data[pos:pos + 8], 'little') not in slots)
        previous = bytes(self.data[pos:pos + 8])
        self.data[pos:pos + 8] = (0x576dfd8).to_bytes(8, 'little')
        try:
            with self.assertRaisesRegex(ValueError, 'Duplicate relocation'):
                evidence.checked_relocations(self.data, slots)
        finally:
            self.data[pos:pos + 8] = previous

    def test_fde_end_must_match_selected_extent(self):
        summary, frames, gaps = evidence.fde_extents(self.data)
        fake = [dict(f) for f in frames if f['start'] in {x[1] for x in evidence.FUNCTIONS}]
        fake[0]['end'] -= 1
        with tempfile.TemporaryDirectory() as temp, patch.object(evidence, 'fde_extents', return_value=(summary, fake, gaps)):
            with self.assertRaisesRegex(ValueError, 'indexed FDE'):
                evidence.collect(self.data, Path(temp) / 'out')


if __name__ == '__main__':
    unittest.main()
