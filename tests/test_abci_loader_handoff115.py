"""Offline, negative-control tests for selected node #115 loader evidence."""
import csv
import hashlib
import mmap
from pathlib import Path
import struct
import tempfile
import unittest

from tools import abci_loader_handoff115 as evidence


class LoaderEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = evidence.BINARY.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = evidence.sections(cls.data)
        cls.tables = evidence.collect(cls.data)
        cls.relocations, _ = evidence.selected_relocations(cls.data, cls.secs)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutate(self, offset, replacement):
        old = bytes(self.data[offset:offset + len(replacement)])
        self.data[offset:offset + len(replacement)] = replacement
        self.addCleanup(self.data.__setitem__, slice(offset, offset + len(old)), old)

    def va_offset(self, va, size=1):
        return evidence.mapping(self.secs, va, size)[1]

    def test_authenticated_target(self):
        self.assertEqual(evidence.authenticate(self.data), evidence.SHA256)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), evidence.SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.authenticate(self.data, '0' * 64)

    def test_modified_binary_digest_rejected(self):
        off = self.va_offset(0x2af0a5f)
        self.mutate(off, bytes([self.data[off] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.authenticate(self.data)

    def test_selected_inventory_has_no_unexpected_missing_records(self):
        counts = {name: len(rows) for name, (_, rows) in self.tables.items()}
        self.assertEqual(counts, {'ranges.tsv': 14, 'windows.tsv': 79, 'fields.tsv': 52,
                                  'edges.tsv': 122, 'tables.tsv': 44,
                                  'relocations.tsv': 13, 'locations.tsv': 12,
                                  'references.tsv': 14, 'literals.tsv': 6, 'copies.tsv': 14, 'projection.tsv': 4, 'handoff.tsv': 3, 'expanded-projection.tsv': 4, 'forwarding.tsv': 2, 'clone-guard.tsv': 1})

    def test_fde_ranges_and_index_are_reconciled(self):
        rows = {r[0]: r for r in self.tables['ranges.tsv'][1]}
        self.assertEqual(rows['middle'][1:3], ['0x2b41b70', '0x2b43283'])
        self.assertEqual(rows['loader_boundary'][1:3], ['0x3c12800', '0x3c12af5'])
        self.assertEqual(rows['result_consumer'][1:3], ['0x2cbfd10', '0x2cc00be'])

    def test_corrupted_fde_range_rejected(self):
        row = next(r for r in self.tables['ranges.tsv'][1] if r[0] == 'middle')
        fde = int(row[5], 16)
        off = self.va_offset(fde, 16)
        old_range = struct.unpack_from('<i', self.data, off + 12)[0]
        self.mutate(off + 12, struct.pack('<i', old_range - 1))
        with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
            evidence.selected_fdes(self.data, self.secs)

    def test_exact_instruction_window_rejects_corruption(self):
        window = next(w for w in evidence.WINDOWS if w[0] == 'middle_loader_call')
        off = self.va_offset(0x2b41f36)
        self.mutate(off, bytes([self.data[off] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'selected bytes changed'):
            evidence.verify_window(self.data, self.secs, window)

    def test_selected_call_edges_bind_upper_lane_and_parent_sibling(self):
        rows = {r[0]: r for r in self.tables['edges.tsv'][1]}
        self.assertEqual(rows['outer_b_to_parent'][-1], '0x2cbbbe0')
        self.assertEqual(rows['parent_a_to_middle'][-1], '0x2b41b70')
        self.assertEqual(rows['parent_b_to_middle'][-1], '0x2b41b70')
        self.assertEqual(rows['parent_a_consumer'][-1], '0x2cbfd10')
        self.assertEqual(rows['parent_b_consumer'][-1], '0x2cbfd10')

    def test_mutated_call_opcode_rejected(self):
        off = self.va_offset(0x2af0a5f)
        self.mutate(off, b'\x90')
        with self.assertRaisesRegex(ValueError, 'unsupported selected transfer'):
            evidence.decode_edge(self.data, self.secs, 0x2af0a5f)

    def test_mutated_call_displacement_rejected(self):
        off = self.va_offset(0x2af0a5f, 5)
        self.mutate(off + 1, bytes([self.data[off + 1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'transfer target changed'):
            evidence.edges_table(self.data, self.secs)

    def test_mutated_conditional_branch_rejected(self):
        off = self.va_offset(0x2af0a7a, 2)
        self.mutate(off + 1, bytes([self.data[off + 1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'transfer target changed'):
            evidence.edges_table(self.data, self.secs)

    def test_two_resumption_tables_are_binary_derived(self):
        rows = {(r[0], int(r[2])): int(r[6], 16) for r in self.tables['tables.tsv'][1]}
        self.assertEqual(rows['parent_initial', 0], 0x2af06bb)
        self.assertEqual(rows['parent_initial', 3], 0x2af074c)
        self.assertEqual(rows['parent_nested', 3], 0x2af0a45)
        self.assertEqual(rows['parent_b_initial', 3], 0x2cbbcb2)
        self.assertEqual(rows['parent_b_nested', 3], 0x2cbc051)
        self.assertEqual(rows['middle_initial', 0], 0x2b41baa)
        self.assertEqual(rows['middle_initial', 4], 0x2b41bfa)
        raw = evidence.read_va(self.data, self.secs, 0x6042bc + 3 * 4, 4)
        self.assertEqual(0x6042bc + struct.unpack('<i', raw)[0], 0x2af0a45)

    def test_table_entry_mutation_rejected_even_with_in_range_target(self):
        slot = 0x6042bc + 3 * 4
        off = self.va_offset(slot, 4)
        wrong_target = 0x2af0a51
        self.mutate(off, struct.pack('<i', wrong_target - 0x6042bc))
        with self.assertRaisesRegex(ValueError, 'jump-table entry changed'):
            evidence.tables_table(self.data, self.secs)

    def test_out_of_range_and_nobits_are_not_file_mappings(self):
        with self.assertRaisesRegex(ValueError, 'not uniquely file-backed'):
            evidence.mapping(self.secs, 0xfffffffffffffff0, 1)
        with self.assertRaisesRegex(ValueError, 'overflow'):
            evidence.mapping(self.secs, 0xfffffffffffffff0, 32)
        with self.assertRaisesRegex(ValueError, 'invalid VA range'):
            evidence.mapping(self.secs, 0, 0)
        artificial = [{'name': '.bss', 'type': 8, 'flags': 3, 'address': 0x100,
                       'offset': 0, 'size': 0x40}]
        with self.assertRaisesRegex(ValueError, 'not uniquely file-backed'):
            evidence.mapping(artificial, 0x110, 1)
        artificial.append({'name': '.data', 'type': 1, 'flags': 3, 'address': 0x100,
                           'offset': 0x200, 'size': 0x40})
        self.assertEqual(evidence.mapping(artificial, 0x110, 1)[1], 0x210)
        artificial.append(dict(artificial[-1], name='.data2'))
        with self.assertRaisesRegex(ValueError, 'not uniquely file-backed'):
            evidence.mapping(artificial, 0x110, 1)

    def test_mutated_relocation_type_and_addend_rejected(self):
        off = self.relocations[0x64e7728][0]
        info = struct.unpack_from('<Q', self.data, off + 8)[0]
        self.mutate(off + 8, struct.pack('<Q', info ^ 1))
        with self.assertRaisesRegex(ValueError, 'relocation changed'):
            evidence.selected_relocations(self.data, self.secs)

    def test_duplicate_selected_relocation_rejected(self):
        sec = evidence.unique_section(self.secs, '.rela.dyn')
        off = sec['offset']
        self.assertNotEqual(struct.unpack_from('<Q', self.data, off)[0], 0x64e7728)
        self.mutate(off, struct.pack('<Q', 0x64e7728))
        with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
            evidence.selected_relocations(self.data, self.secs)

    def test_missing_or_ambiguous_section_rejected(self):
        rela = evidence.unique_section(self.secs, '.rela.dyn')
        with self.assertRaisesRegex(ValueError, 'missing, duplicate or NOBITS'):
            evidence.unique_section(self.secs + [dict(rela)], '.rela.dyn')
        no_file = dict(rela, type=8)
        with self.assertRaisesRegex(ValueError, 'missing, duplicate or NOBITS'):
            evidence.unique_section([no_file], '.rela.dyn')

    def test_dynamic_symbol_is_memcpy(self):
        rows = {r[0]: r for r in self.tables['relocations.tsv'][1]}
        self.assertEqual(rows['copy'][3:6], ['6', '7', '0x0'])
        # selected_relocations also reads the symbol name directly from .dynstr.
        evidence.selected_relocations(self.data, self.secs)

    def test_corrupted_location_and_path_rejected(self):
        off = self.va_offset(0x64767a8 + 16, 4)
        self.mutate(off, struct.pack('<I', 124))
        with self.assertRaisesRegex(ValueError, 'coordinates changed'):
            evidence.locations_table(self.data, self.secs, self.relocations)

    def test_corrupted_location_rip_displacement_rejected(self):
        off = self.va_offset(0x3c1352f, 7)
        self.mutate(off + 3, bytes([self.data[off + 3] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'Location reference changed'):
            evidence.references_table(self.data, self.secs)

    def test_corrupted_literal_rejected(self):
        off = self.va_offset(0x605542)
        self.mutate(off, b'C')
        with self.assertRaisesRegex(ValueError, 'literal changed'):
            evidence.literals_table(self.data, self.secs)

    def test_version_validation_failure_is_anchored_in_both_lanes(self):
        edges = {r[0]: r[-1] for r in self.tables['edges.tsv'][1]}
        refs = {r[0]: r[-1] for r in self.tables['references.tsv'][1]}
        self.assertEqual(edges['parent_a_check_failure'], '0x2af3815')
        self.assertEqual(edges['parent_b_check_failure'], '0x2cbee73')
        self.assertEqual(edges['parent_a_version_trap'], '0x2af397f')
        self.assertEqual(edges['parent_b_version_trap'], '0x2cbf001')
        self.assertEqual(refs['version_descriptor_a'], '0x43bcbc')
        self.assertEqual(refs['version_descriptor_b'], '0x43bcbc')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2af397f, 2), b'\x0f\x0b')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2cbf001, 2), b'\x0f\x0b')

    def test_clone_forwards_two_directly_observed_regions(self):
        rows = {r[0]: r for r in self.tables['forwarding.tsv'][1]}
        self.assertEqual(rows['one'][2:5], ['0x10e8', '0x55f21a9', '0x10e8'])
        self.assertEqual(rows['one'][7:9], ['0x1c58', '16'])
        self.assertEqual(rows['two'][2:5], ['0x10f8', '0x55f22c7', '0x10f8'])
        self.assertEqual(rows['two'][7:9], ['0x1c68', '16'])

    def test_clone_forwarding_rejects_mismatched_region(self):
        fields = [row[:] for row in self.tables['fields.tsv'][1]]
        row = next(row for row in fields if row[0] == 'clone_destination_one')
        row[4] = '0x10e9'
        with self.assertRaisesRegex(ValueError, 'forwarding offset changed'):
            evidence.forwarding_table(fields, self.tables['expanded-projection.tsv'][1])

    def test_clone_size_guard_boundaries_and_failure_join(self):
        row = self.tables['clone-guard.tsv'][1][0]
        self.assertEqual(row[2:], ['0xa0', '0x98', '32', '59',
                                  '0x7ffffffffffffff8', '0x3ffffffffffffff'])
        byte_limit, maximum = int(row[6], 16), int(row[7], 16)
        def rejected(count):
            product = (count * 32) & ((1 << 64) - 1)
            return (count >> 59) != 0 or product > byte_limit
        for count in (0, 1, maximum - 1, maximum):
            self.assertFalse(rejected(count))
        for count in (maximum + 1, 1 << 59, (1 << 64) - 1):
            self.assertTrue(rejected(count))
        edges = {r[0]: r[-1] for r in self.tables['edges.tsv'][1]}
        self.assertEqual(edges['clone_vector_alloc_failure'], '0x55f2efa')
        self.assertEqual(edges['clone_vector_failure_join'], '0x55ea0ea')
        self.assertEqual(edges['clone_size_failure_trap'], '0x55f2fd6')

    def test_clone_size_guard_mutation_rejected(self):
        off = self.va_offset(0x55ea0cf)
        self.mutate(off, bytes([self.data[off] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'guard encoding changed'):
            evidence.clone_guard_table(self.data, self.secs)

    def test_corrupted_version_descriptor_length_rejected(self):
        off = self.va_offset(0x43bcbc)
        self.mutate(off, bytes([self.data[off] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'version descriptor changed'):
            evidence.literals_table(self.data, self.secs)

    def test_location_pairs_are_distinct_from_historical_release(self):
        rows = {r[0]: r for r in self.tables['locations.tsv'][1]}
        self.assertEqual(rows['state_location_boundary'][6:9], ['123', '37', 'l1/src/abci/state.rs'])
        self.assertEqual(rows['startup_mismatch'][6:9], ['92', '13', 'node/src/startup.rs'])
        self.assertNotEqual(int(rows['state_location_boundary'][6]), 107)

    def test_counter_boundary_from_pinned_inc_and_cmov(self):
        # Model only the pinned INC/ZF/CMOVNE sequence; target instructions are not executed.
        raw = evidence.read_va(self.data, self.secs, 0x3c128ec, 18)
        self.assertEqual(raw.hex(), '48ffc048c7c1ffffffff480f45c849894c24')
        max_u64 = (1 << 64) - 1
        def selected(old):
            incremented = (old + 1) & max_u64
            return incremented if incremented != 0 else max_u64
        for value, expected in ((0, 1), (1, 2), (max_u64 - 1, max_u64), (max_u64, max_u64)):
            self.assertEqual(selected(value), expected)

    def test_pending_sentinel_is_one_distinct_raw_value(self):
        raw = evidence.read_va(self.data, self.secs, 0x2af0a64, 14)
        self.assertEqual(raw[:2], b'\x48\xbd')
        minimum = struct.unpack_from('<Q', raw, 2)[0]
        self.assertEqual(minimum, 1 << 63)
        self.assertEqual(raw[10:14], b'\x48\x8d\x45\x01')
        pending = minimum + 1
        self.assertEqual([v == pending for v in (minimum - 1, minimum, pending, pending + 1)],
                         [False, False, True, False])

    def test_relocation_addend_corruption_rejected(self):
        off = self.relocations[0x64e73a0][0]
        old = struct.unpack_from('<q', self.data, off + 16)[0]
        self.mutate(off + 16, struct.pack('<q', old + 1))
        with self.assertRaisesRegex(ValueError, 'relocation changed'):
            evidence.selected_relocations(self.data, self.secs)

    def test_dynamic_symbol_name_corruption_rejected(self):
        syms = evidence.unique_section(self.secs, '.dynsym')
        strings = evidence.unique_section(self.secs, '.dynstr')
        name = struct.unpack_from('<I', self.data, syms['offset'] + 7 * 24)[0]
        off = strings['offset'] + name
        self.assertEqual(bytes(self.data[off:off + 6]), b'memcpy')
        self.mutate(off, b'z')
        with self.assertRaisesRegex(ValueError, 'dynamic symbol changed'):
            evidence.selected_relocations(self.data, self.secs)

    def test_location_path_corruption_rejected(self):
        path_va = self.relocations[0x64767a8][3]
        off = self.va_offset(path_va)
        self.mutate(off, bytes([self.data[off] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'Location path changed'):
            evidence.locations_table(self.data, self.secs, self.relocations)

    def test_loaded_state_fields_are_copied_to_context(self):
        rows = {r[0]: r[4] for r in self.tables['fields.tsv'][1]}
        self.assertEqual([rows['context_state_source_10'], rows['context_state_source_18'],
                          rows['context_state_source_28'], rows['context_state_source_30']],
                         ['0x10', '0x18', '0x28', '0x30'])
        self.assertEqual([rows['context_copy_state_10'], rows['context_copy_state_18_20'],
                          rows['context_copy_state_28'], rows['context_copy_state_30']],
                         ['0x578', '0x588', '0x580', '0x5a0'])
        self.assertEqual([rows['context_record_source'], rows['context_record_destination']],
                         ['0x568', '0x820'])
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2af142b, 0x42),
                         evidence.read_va(self.data, self.secs, 0x2cbcb00, 0x42))

    def test_record_projection_and_adjacent_copy_ranges(self):
        projections = {r[0]: r for r in self.tables['projection.tsv'][1]}
        self.assertEqual(projections['state_word_10'][2:7],
                         ['0x10', '0x2af144a', '0x578', '0x10', '8'])
        self.assertEqual(projections['state_words_18_20'][2:7],
                         ['0x18', '0x2af1458', '0x588', '0x20', '16'])
        fields = {r[0]: int(r[4], 16) for r in self.tables['fields.tsv'][1]}
        copies = {r[0]: int(r[4]) for r in self.tables['copies.tsv'][1]}
        self.assertEqual(fields['context_record_source'] + copies['a_context_forward'],
                         fields['context_record_destination'])
        self.assertEqual(copies['a_context_forward'], copies['b_context_forward'])
        self.assertEqual(copies['a_consumer_into_context'], copies['b_consumer_into_context'])
        self.assertEqual(copies['a_lookup_into_context'], copies['b_lookup_into_context'])

    def test_completed_middle_drop_paths_return_without_calls(self):
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2b42a0a, 5),
                         bytes.fromhex('b001884321'))
        rows = {(r[0], int(r[2])): int(r[6], 16) for r in self.tables['tables.tsv'][1]}
        self.assertEqual(rows['drop_a', 1], 0x2a975be)
        self.assertEqual(rows['drop_b', 1], 0x2c8577e)
        self.assertEqual(rows['drop_a', 2], rows['drop_a', 1])
        self.assertEqual(rows['drop_b', 2], rows['drop_b', 1])
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2a975be, 8),
                         bytes.fromhex('4883c4085b415ec3'))
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2c8577e, 6),
                         bytes.fromhex('5b415e415fc3'))

    def test_completed_drop_table_corruption_rejected(self):
        base = 0x6033d4
        off = self.va_offset(base + 4, 4)
        self.mutate(off, struct.pack('<i', 0x2a973c5 - base))
        with self.assertRaisesRegex(ValueError, 'jump-table entry changed'):
            evidence.tables_table(self.data, self.secs)

    def test_parent_pointer_slots_and_upper_delivery(self):
        rows = {r[0]: r for r in self.tables['handoff.tsv'][1]}
        for lane in ('a', 'b'):
            self.assertEqual(rows[lane + '_parent'][7], '0x380')
            self.assertEqual(int(rows[lane + '_parent'][8]), 0x3b8)
        self.assertEqual(rows['b_outer'][7], '0x380')
        self.assertEqual(int(rows['b_outer'][8]), 0x380)
        self.assertEqual(rows['a_parent'][3:7:3], ['0x2158', '0x24d8'])
        self.assertEqual(rows['b_parent'][3:7:3], ['0x2d50', '0x30d0'])

    def test_final_pointer_slot_offset_corruption_rejected(self):
        off = self.va_offset(0x2af351c, 8)
        self.mutate(off + 4, bytes([self.data[off + 4] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'pointer offset changed'):
            evidence.stitch_table(self.data, self.secs, self.tables['copies.tsv'][1])

    def test_expanded_projection_is_contiguous(self):
        rows = self.tables['expanded-projection.tsv'][1]
        self.assertEqual([r[2] for r in rows], ['0xd88', '0x10e8', '0x10f8', '0x1108'])
        self.assertEqual([r[5] for r in rows], ['0x18f8', '0x1c58', '0x1c68', '0x1c78'])
        for left, right in zip(rows, rows[1:]):
            self.assertEqual(int(left[2], 16) + int(left[6]), int(right[2], 16))
            self.assertEqual(int(left[5], 16) + int(left[6]), int(right[5], 16))
        self.assertEqual(int(rows[-1][5], 16) + int(rows[-1][6]), 0x4350)

    def test_expanded_state_store_corruption_rejected(self):
        off = self.va_offset(0x548d76d, 8)
        self.mutate(off + 4, bytes([self.data[off + 4] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'selected bytes changed'):
            evidence.fields_table(self.data, self.secs)

    def test_constructor_allocation_guard_corruption_rejected(self):
        off = self.va_offset(0x5a6c06b, 6)
        self.mutate(off + 2, bytes([self.data[off + 2] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'transfer target changed'):
            evidence.edges_table(self.data, self.secs)

    def test_copy_length_and_register_target_mutations_rejected(self):
        off = self.va_offset(0x2af147b, 5)
        self.mutate(off + 1, bytes([self.data[off + 1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'copy length changed'):
            evidence.copies_table(self.data, self.secs)

    def test_copy_register_call_mutation_rejected(self):
        off = self.va_offset(0x2af1487, 3)
        self.mutate(off + 2, bytes([self.data[off + 2] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'copy register call changed'):
            evidence.copies_table(self.data, self.secs)

    def test_twenty_byte_lookup_mask_rejects_each_corruption(self):
        # This arithmetic models the two PCMPEQB/PAND/PMOVMSKB witnesses,
        # rather than executing target instructions or asserting Rust types.
        raw = evidence.read_va(self.data, self.secs, 0x24b7a70, 0x28)
        self.assertIn(bytes.fromhex('660f74442430'), raw)
        self.assertIn(bytes.fromhex('660f74d1'), raw)
        self.assertIn(bytes.fromhex('660fdbc2'), raw)
        self.assertIn(bytes.fromhex('660fd7f0'), raw)
        def mask(a, b):
            low = [a[i] == b[i] for i in range(16)]
            tail = [a[16 + i] == b[16 + i] for i in range(4)] + [True] * 12
            return sum((1 << i) for i, (x, y) in enumerate(zip(low, tail)) if x and y)
        key = bytes(range(20))
        self.assertEqual(mask(key, key), 0xffff)
        for i in range(20):
            changed = bytearray(key)
            changed[i] ^= 1
            self.assertNotEqual(mask(key, changed), 0xffff, i)

    def test_deterministic_emit_and_complete_file_set(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / 'a'
            second = Path(temp) / 'b'
            evidence.emit(first, self.tables)
            evidence.emit(second, self.tables)
            self.assertEqual(sorted(p.name for p in first.iterdir()),
                             sorted(p.name for p in second.iterdir()))
            self.assertEqual(len(list(first.iterdir())), 16)
            for path in first.iterdir():
                self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
            with (first / 'edges.tsv').open(newline='', encoding='utf-8') as handle:
                self.assertEqual(len(list(csv.DictReader(handle, delimiter='\t'))), 122)


if __name__ == '__main__':
    unittest.main()
