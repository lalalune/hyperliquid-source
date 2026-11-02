from contextlib import contextmanager
from pathlib import Path
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import display_name_path_115 as evidence


class DisplayNameEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The fixture is required. A missing target is a failure, not a skip.
        cls.data = bytearray(evidence.TARGET.read_bytes())
        evidence.verify_digest(cls.data)
        cls.image = evidence.Image(cls.data)
        cls.frame_map = evidence.frames(cls.image)
        cls.relocs = evidence.relocations(cls.image)
        (cls.count, cls.ordinal, cls.bias, cls.names,
         cls.bases, cls.tables) = evidence.switch_tables(cls.image, cls.frame_map, cls.relocs)
        cls.values = evidence.facts(cls.image)

    @contextmanager
    def changed(self, offset, replacement):
        old = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = old

    def test_target_digest_rejects_one_changed_byte(self):
        offset = self.image.offset(0x2392218)
        with self.changed(offset, bytes([self.data[offset] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                evidence.verify_digest(self.data)
        evidence.verify_digest(self.data)

    def test_fde_and_independent_formatter_binding(self):
        self.assertEqual(self.count, 92)
        self.assertEqual(self.ordinal, 19)
        self.assertEqual(self.bias + self.ordinal, 0x99)
        self.assertEqual(self.names[self.ordinal][0][2], 'setDisplayName')
        self.assertEqual(self.tables['formatter'][19], 0x2bcb2d4)
        self.assertEqual(self.tables['dispatcher'][19], 0x2bdc64d)
        self.assertEqual((self.frame_map['dispatcher']['start'], self.frame_map['dispatcher']['end']),
                         (0x2bdbaa0, 0x2bdcb65))
        self.assertNotEqual(self.tables['dispatcher'][19], self.frame_map['dispatcher']['start'])
        self.assertEqual((self.frame_map['display_wrapper']['start'], self.frame_map['display_wrapper']['end']),
                         (0x2392200, 0x2392308))

    def test_direct_and_nested_routes_are_distinct(self):
        self.assertEqual(self.tables['router'][19], 0x2bdaf4c)
        self.assertEqual(self.tables['router'][52], 0x2bdb07a)
        self.assertEqual(self.names[52][0][2], 'multiSig')
        self.assertEqual(self.tables['formatter'][52], 0x2bcb7c7)
        self.assertEqual(evidence.branch(self.image, 0x2bdaf5c)[:2], ('call', 0x2c08600))
        self.assertEqual(evidence.branch(self.image, 0x2bdb08a)[:2], ('call', 0x2c12690))
        self.assertEqual(evidence.branch(self.image, 0x2c08a0d)[:2], ('call', 0x2c76380))
        self.assertEqual(self.values['direct_length_limit_exclusive'], 101)
        self.assertEqual(self.values['direct_length_error_word'], self.values['wrapper_length_error_word'])
        self.assertEqual(self.values['direct_prior_rejection_word'], self.values['prior_rejection_word'])

    def test_other_valid_router_arm_cannot_replace_display_arm(self):
        base = self.bases['router']
        offset = self.image.offset(base + 4 * self.ordinal, 4)
        replacement = struct.pack('<i', self.tables['router'][52] - base)
        with self.changed(offset, replacement):
            with self.assertRaisesRegex(ValueError, 'unexpected arm'):
                evidence.switch_tables(self.image, self.frame_map, self.relocs)

    def test_all_named_direct_and_indirect_edges(self):
        self.assertEqual(len(evidence.verify_edges(self.image, self.frame_map)), len(evidence.EDGES))
        rows = evidence.verify_indirects(self.image, self.frame_map, self.relocs)
        self.assertEqual(len(rows), len(evidence.INDIRECTS))
        self.assertEqual(self.relocs[0x64df9f8][3], 'bcmp')
        self.assertEqual(self.relocs[0x64dfb50][3], 'memcmp')
        evidence.verify_relocation_meanings(self.relocs, self.frame_map)

    def test_corrupted_opcode_fails_even_without_digest_check(self):
        offset = self.image.offset(0x2392218)
        with self.changed(offset, bytes([self.data[offset] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                evidence.verify_windows(self.image)

    def test_wrong_call_opcode_is_not_a_call_edge(self):
        offset = self.image.offset(0x2bdc670)
        with self.changed(offset, b'\xe9'):
            with self.assertRaisesRegex(ValueError, 'branch mismatch'):
                evidence.verify_edges(self.image, self.frame_map)

    def test_outside_fde_switch_target_is_rejected(self):
        offset = self.image.offset(self.bases['dispatcher'] + 4 * self.ordinal, 4)
        with self.changed(offset, struct.pack('<i', 0)):
            with self.assertRaisesRegex(ValueError, 'outside its FDE'):
                evidence.switch_tables(self.image, self.frame_map, self.relocs)

    def test_wrong_in_fde_switch_target_is_rejected(self):
        base = self.bases['dispatcher']
        offset = self.image.offset(base + 4 * self.ordinal, 4)
        replacement = struct.pack('<i', self.tables['dispatcher'][20] - base)
        with self.changed(offset, replacement):
            with self.assertRaisesRegex(ValueError, 'unexpected arm'):
                evidence.switch_tables(self.image, self.frame_map, self.relocs)

    def test_corrupt_name_bytes_break_cross_table_agreement(self):
        offset = self.image.offset(self.names[19][0][0])
        with self.changed(offset, b'X'):
            with self.assertRaisesRegex(ValueError, 'variant names differ'):
                evidence.switch_tables(self.image, self.frame_map, self.relocs)

    def test_nobits_name_pointer_is_rejected(self):
        slot = evidence.NAME_TABLES[0] + 19 * 16
        record_off = self.relocs[slot][4]
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.changed(record_off + 16, struct.pack('<q', bss['address'])):
            corrupt = evidence.relocations(self.image)
            with self.assertRaisesRegex(ValueError, 'not uniquely file-backed'):
                evidence.name_at(self.image, corrupt, slot)

    def test_changed_relocation_cannot_claim_classifier(self):
        corrupt = dict(self.relocs)
        typ, symidx, addend, symbol, off = corrupt[0x64e7a78]
        corrupt[0x64e7a78] = (typ, symidx, addend + 1, symbol, off)
        with self.assertRaisesRegex(ValueError, 'unexpected relocation targets'):
            evidence.verify_relocation_meanings(corrupt, self.frame_map)

    def test_inconsistent_index_and_fde_are_rejected(self):
        from elf_index import unwind_index
        _, rows = unwind_index(self.data)
        selected = next(row for row in rows if row['start'] == 0x2392200)
        hdr = self.image.section('.eh_frame_hdr')
        offset = hdr['offset'] + 12 + selected['index'] * 8
        old = struct.unpack_from('<i', self.data, offset)[0]
        with self.changed(offset, struct.pack('<i', old + 1)):
            with self.assertRaisesRegex(ValueError, 'unique indexed FDE'):
                evidence.frames(self.image)

    def test_addresses_must_be_file_backed_and_within_one_section(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        text = self.image.section('.text')
        for va, size in ((bss['address'], 1), (-1, 1),
                         (text['address'] + text['size'] - 1, 2)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(va, size)

    def test_selector_boundaries_and_lower_default(self):
        self.assertEqual(evidence.table_index(0, self.values, self.count), 20)
        self.assertEqual(evidence.table_index(133, self.values, self.count), 20)
        self.assertEqual(evidence.table_index(134, self.values, self.count), 0)
        self.assertEqual(evidence.table_index(153, self.values, self.count), 19)
        self.assertEqual(evidence.table_index(225, self.values, self.count), 91)
        # This is the evidence tool's own bound, not a claim about node behavior.
        with self.assertRaisesRegex(ValueError, 'outside the verified'):
            evidence.table_index(226, self.values, self.count)
        for bad in (-1, 2 ** 64, True):
            with self.subTest(tag=bad), self.assertRaises(ValueError):
                evidence.table_index(bad, self.values, self.count)

    def test_length_and_duplicate_branch_boundaries(self):
        cases = (
            (0, False, ('empty', 14, 418, 'erase')),
            (0, True, ('empty', 14, 418, 'erase')),
            (1, False, ('too_short', 15, 227, 'none')),
            (2, False, ('too_short', 15, 227, 'none')),
            (3, False, ('unique', 14, 418, 'upsert')),
            (3, True, ('duplicate', 15, 228, 'none')),
            (20, False, ('unique', 14, 418, 'upsert')),
            (20, True, ('duplicate', 15, 228, 'none')),
            (21, False, ('too_long', 15, 226, 'none')),
            (100, False, ('too_long', 15, 226, 'none')),
            (101, False, ('wrapper_limit', 15, 344, 'none')),
            (2 ** 64 - 1, False, ('wrapper_limit', 15, 344, 'none')),
        )
        for length, duplicate, expected in cases:
            with self.subTest(length=length, duplicate=duplicate):
                self.assertEqual(evidence.predict(length, duplicate, False, self.values), expected)

    def test_prior_rejection_precedes_length_and_mutation(self):
        for length in (0, 3, 101, 2 ** 64 - 1):
            with self.subTest(length=length):
                self.assertEqual(evidence.predict(length, True, True, self.values),
                                 ('prior_rejection', 15, 288, 'none'))

    def test_storage_transitions_and_invariant_failure_branches(self):
        self.assertEqual(self.values['key_bytes'], 20)
        self.assertEqual(self.values['compact_entry_stride'], 48)
        self.assertEqual(self.values['compact_to_tree_threshold'], 64)
        self.assertEqual(self.values['tree_storage_tag'], '0x8000000000000000')
        self.assertEqual(self.values['new_tree_node_bytes'], 496)
        self.assertEqual(self.values['tree_node_local_limit'], 11)
        self.assertEqual(evidence.branch(self.image, 0x2dc013b)[:2], ('je', 0x2dc01dd))
        self.assertEqual(evidence.branch(self.image, 0x26df2cf)[:2], ('jae', 0x26df34a))
        self.assertEqual(self.relocs[0x64df568][3], 'memmove')

    def test_corrupt_storage_conversion_threshold_fails_closed(self):
        offset = self.image.offset(0x2dc0133)
        with self.changed(offset, b'\x3f'):
            with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                evidence.verify_windows(self.image)

    def test_branch_model_rejects_invalid_inputs(self):
        for length in (-1, 2 ** 64, True, 1.0):
            with self.subTest(length=length), self.assertRaises(ValueError):
                evidence.predict(length, False, False, self.values)
        with self.assertRaises(ValueError):
            evidence.predict(3, 1, False, self.values)

    def test_generated_evidence_matches_packet(self):
        packet = ROOT / 'research/work-items/RE-010-display-name-path-115'
        expected = {'functions.tsv', 'windows.tsv', 'edges.tsv', 'indirect-edges.tsv',
                    'relocations.tsv', 'switches.tsv', 'switch-tables.tsv', 'name-tables.tsv',
                    'branch-vectors.tsv', 'summary.json'}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            summary = evidence.generate(self.data, out)
            self.assertEqual({path.name for path in out.iterdir()}, expected)
            self.assertEqual(summary['selected_tag'], 153)
            for name in sorted(expected):
                with self.subTest(name=name):
                    self.assertEqual((out / name).read_bytes(), (packet / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
