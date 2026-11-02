"""Static controls for the selected node #94 vote-tracker route."""
import hashlib
import unittest
from unittest.mock import patch

from tools import vote_tracker_state as v
from tools.elf_index import unwind_index


class VoteTrackerStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The target is required in the verification environment. Missing input
        # is an error, not a skipped test.
        cls.data = v.TARGET.read_bytes()
        cls.sections, cls.index = unwind_index(cls.data)
        cls.image = v.Image(cls.data, cls.sections)
        cls.result = v.analyze(cls.data)

    def modified_va(self, address, xor=1):
        changed = bytearray(self.data)
        _, offset = self.image.location(address, 1)
        changed[offset] ^= xor
        return v.Image(changed, self.sections)

    def test_full_target_digest_and_negative_hash(self):
        self.assertEqual(v.authenticate(self.data),
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        with patch.object(v, 'EXPECTED_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                v.authenticate(self.data)
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            v.authenticate(changed)

    def test_selected_fdes_and_body_hashes(self):
        rows = {row['label']: row for row in self.result['functions']}
        self.assertEqual(len(rows), 29)
        self.assertEqual((rows['tracker_writer']['start_va'], rows['tracker_writer']['end_va_exclusive']),
                         ('0x2326ba0', '0x2326d16'))
        self.assertEqual((rows['i_pair_reader']['start_va'], rows['i_pair_reader']['end_va_exclusive']),
                         ('0x183a210', '0x183aca7'))
        self.assertTrue(all(row['section'] == '.text' and row['size'] > 0 for row in rows.values()))
        self.assertTrue(all(len(row['body_sha256']) == 64 for row in rows.values()))
        with self.assertRaisesRegex(ValueError, 'changed FDE body'):
            v.function_records(self.modified_va(0x2326ba0), self.index)

    def test_corrupt_fde_extent_rejected(self):
        frame_va = int(next(row for row in self.result['functions']
                            if row['label'] == 'tracker_writer')['fde_va'], 16)
        # The shared parser reads this record's encoded range; change its low byte.
        with self.assertRaises(ValueError):
            v.function_records(self.modified_va(frame_va + 12), self.index)

    def test_call_chain_edges_and_context(self):
        edges = {row['label']: row for row in self.result['edges']}
        self.assertEqual(len(edges), 71)
        self.assertEqual(edges['parent_to_field_writer']['category'], 'context')
        self.assertEqual(edges['field_writer_to_tracker_writer']['kind'], 'jump')
        self.assertEqual(edges['tracker_i_adapter']['target_va'], '0x25eab80')
        self.assertEqual(edges['map_unit_reader']['target_va'], '0x1968910')
        self.assertEqual(edges['pair_row_reader']['target_va'], '0x17c2a60')
        self.assertEqual(edges['row_qst_payload_writer']['category'], 'selected')
        selected_starts = {row['start_va'] for row in self.result['functions']}
        self.assertTrue(all(row['target_va'] in selected_starts
                            for row in edges.values() if row['category'] == 'selected'))

    def test_bad_call_opcode_and_displacement(self):
        spec = next(row for row in v.EDGES if row[0] == 'tracker_i_adapter')
        with self.assertRaisesRegex(ValueError, 'opcode'):
            v.edge(self.modified_va(spec[1]), *spec)
        with self.assertRaisesRegex(ValueError, 'target'):
            v.edge(self.modified_va(spec[1] + 1), *spec)

    def test_named_fields_and_changed_names(self):
        expected = {b'name': 0, b'hsc': 1, b'i': 2, b'': 3,
                    b'Name': 3, b'namex': 3, b'hs': 3, b'ii': 3, b'unknown': 3}
        for key, selector in expected.items():
            with self.subTest(key=key):
                self.assertEqual(v.classify_key(self.image, key), selector)
        # Every single-bit substitution at every recognized byte is a negative
        # synthetic classifier control; it is not target execution.
        for key in (b'name', b'hsc', b'i'):
            for position in range(len(key)):
                for bit in range(8):
                    changed = bytearray(key)
                    changed[position] ^= 1 << bit
                    self.assertEqual(v.classify_key(self.image, bytes(changed)), 3)
        with self.assertRaises(ValueError):
            v.classify_key(self.image, 'name')

    def test_corrupt_key_comparison_and_rodata(self):
        with self.assertRaisesRegex(ValueError, 'comparison'):
            v.field_keys(self.modified_va(0x16fa0d7))
        with self.assertRaisesRegex(ValueError, 'immediate'):
            v.field_keys(self.modified_va(0x16fa0d9))
        with self.assertRaisesRegex(ValueError, 'referenced bytes'):
            v.literal(self.modified_va(0x3ef4e4), *v.LITERAL_SPECS[0])
        with self.assertRaisesRegex(ValueError, 'RIP-relative opcode'):
            v.literal(self.modified_va(0x27b2a91), *v.LITERAL_SPECS[0])

    def test_field_switch_and_duplicate_routes(self):
        tables = {row['label']: row for row in self.result['relative_tables']}
        first = [row['target_va'] for row in tables['tracker_before_i']['entries']]
        second = [row['target_va'] for row in tables['tracker_after_i']['entries']]
        self.assertEqual(first, ['0x169de3b', '0x169de93', '0x169e01d'])
        self.assertEqual(second, ['0x169e0ca', '0x169e122', '0x169eaa7'])
        branches = {row['label']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(branches['field_duplicate_name'], '0x169efa1')
        self.assertEqual(branches['field_duplicate_hsc'], '0x169ef09')
        self.assertEqual(branches['parent_vtg_duplicate'], '0x16de54b')
        self.assertEqual(branches['field_name_present'], '0x169e1cf')
        self.assertEqual(branches['field_i_present'], '0x169e28d')

    def test_corrupt_table_and_branch(self):
        table = v.TABLES[0]
        with self.assertRaisesRegex(ValueError, 'table entry'):
            v.relative_table(self.modified_va(0x286384), *table)
        with self.assertRaisesRegex(ValueError, 'RIP-relative opcode'):
            v.relative_table(self.modified_va(0x169de2b), *table)
        spec = next(row for row in v.BRANCHES if row[0] == 'pair_too_many')
        with self.assertRaisesRegex(ValueError, 'opcode'):
            v.branch(self.modified_va(spec[1]), *spec)
        with self.assertRaisesRegex(ValueError, 'target'):
            v.branch(self.modified_va(spec[1] + 1), *spec)

    def test_fixed_map_and_array_partition(self):
        # Independent exhaustive byte classification of the selected raw path.
        for marker in range(256):
            if 0x80 <= marker <= 0x8f:
                expected = ('map', marker - 0x80)
            elif 0x90 <= marker <= 0x9f:
                expected = ('array', marker - 0x90)
            else:
                expected = ('other', None)
            self.assertEqual(v.classify_fixed_header(self.image, marker), expected)
        for invalid in (-1, 256, True, b'\x80'):
            with self.assertRaises(ValueError):
                v.classify_fixed_header(self.image, invalid)
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            v.classify_fixed_header(self.modified_va(0x18cadd6), 0x80)

    def test_pair_length_boundaries_and_earlier_failures(self):
        self.assertEqual(v.pair_arity(self.image, 0), 'missing_key')
        self.assertEqual(v.pair_arity(self.image, 1), 'missing_value_after_key')
        self.assertEqual(v.pair_arity(self.image, 2), 'two_children_required')
        for count in range(3, 16):
            self.assertEqual(v.pair_arity(self.image, count), 'extra_after_two_children')
        for invalid in (-1, 16, True):
            with self.assertRaises(ValueError):
                v.pair_arity(self.image, invalid)
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            v.pair_arity(self.modified_va(0x183a8fa), 2)
        branches = {row['label']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(branches['pair_key_error'], '0x183a80a')
        self.assertEqual(branches['pair_value_success'], '0x183a85f')
        self.assertEqual(branches['pair_too_many'], '0x183a91a')

    def test_empty_and_duplicate_paths(self):
        branches = {row['label']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(branches['map_empty'], '0x263f7ef')
        self.assertEqual(branches['seq_empty'], '0x266497d')
        self.assertEqual(branches['map_existing_slot'], '0x263f5e0')
        self.assertEqual(branches['seq_existing_slot'], '0x26647e0')
        self.assertEqual(branches['map_duplicate_error'], '0x263f86f')
        self.assertEqual(branches['seq_duplicate_error'], '0x26649c1')
        self.assertEqual([row['ascii'] for row in self.result['duplicate_diagnostics']],
                         ['duplicate key', 'duplicate key'])
        # The second store overwrites the first three bytes of the first immediate.
        self.assertEqual(v.duplicate_literal(self.modified_va(0x263f8a9), 'map',
                                             0x263f8a7, 0x263f8b5)['ascii'], 'duplicate key')
        with self.assertRaisesRegex(ValueError, 'diagnostic'):
            v.duplicate_literal(self.modified_va(0x263f8ac), 'map', 0x263f8a7, 0x263f8b5)
        with self.assertRaisesRegex(ValueError, 'store'):
            v.duplicate_literal(self.modified_va(0x2664a03), 'sequence', 0x26649f9, 0x2664a07)

    def test_nil_route_and_relative_relocation(self):
        tables = {row['label']: row for row in self.result['relative_tables']}
        self.assertEqual(tables['hsc_raw_c0_marker']['entries'][0]['target_va'], '0x168f24b')
        self.assertEqual(tables['unit_uncached_marker']['entries'][0]['target_va'], '0x1968ac0')
        self.assertEqual(tables['unit_raw_c0_marker']['entries'][0]['target_va'], '0x196893c')
        self.assertEqual(tables['unit_visitor_c0_marker']['entries'][0]['target_va'], '0x2ea2975')
        rel = self.result['relocations'][0]
        self.assertEqual((rel['slot_va'], rel['type'], rel['symbol_index'], rel['addend']),
                         ('0x5772638', 8, 0, '0x2ea2950'))
        self.assertEqual(v.check_window(self.image, 'success', 0x2ea2975, 'c60709')['bytes'], 'c60709')
        changed = bytearray(self.data)
        changed[int(rel['relocation_file_offset'], 16) + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'changed relative relocation'):
            v.relative_relocation(v.Image(changed, self.sections), 0x5772638, 0x2ea2950, 'nil')

    def test_row_descriptor_and_selected_variants(self):
        row = self.result['row_descriptor']
        self.assertEqual(row['text'], 'struct UniqueKeyState with 3 elements')
        self.assertEqual(row['length'], len(row['text']))
        literals = {item['label']: item['ascii'] for item in self.result['literals']}
        for field in ('arq', 'qst', 'vts'):
            self.assertEqual(literals['row_writer_' + field], field)
            self.assertEqual(literals['row_reader_' + field + '_diagnostic'], field)
        self.assertEqual(literals['row_qst_unit'], 'N')
        self.assertEqual(literals['row_qst_payload'], 'Q')
        self.assertEqual(self.result['relocations'][1]['addend'], '0x3b3719')

    def test_hsc_raw_nil_and_empty_sequence_routes(self):
        branches = {row['label']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(branches['hsc_no_raw_byte'], '0x168ee12')
        self.assertEqual(branches['hsc_raw_signed'], '0x168ee1a')
        self.assertEqual(branches['hsc_raw_ge_90'], '0x168eeff')
        self.assertEqual(branches['hsc_raw_ge_a0'], '0x168ef76')
        self.assertEqual(branches['hsc_raw_ge_c0'], '0x168f224')
        self.assertEqual(branches['hsc_empty_success'], '0x168f24b')
        self.assertEqual(v.check_window(self.image, 'nil-or-empty', 0x168f24b,
                                        'c60709')['bytes'], 'c60709')

    def test_qst_key_classifier_and_corruption(self):
        for value in range(256):
            expected = 'N' if value == 0x4e else 'Q' if value == 0x51 else 'other'
            self.assertEqual(v.qst_key(self.image, bytes([value])), expected)
        for key in (b'', b'NN', b'Qx'):
            self.assertEqual(v.qst_key(self.image, key), 'other')
        with self.assertRaises(ValueError):
            v.qst_key(self.image, 'N')
        for address in (0x230176d, 0x2301775, 0x230177a, 0x230178e):
            with self.assertRaisesRegex(ValueError, 'instruction window'):
                v.qst_key(self.modified_va(address), b'N')

    def test_qst_named_and_map_failure_branches(self):
        branches = {row['label']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(branches['qst_no_input'], '0x1684b9b')
        self.assertEqual(branches['qst_map_bad_count'], '0x1684bdb')
        self.assertEqual(branches['qst_bare_q_error'], '0x1684ce9')
        self.assertEqual(branches['qst_map_key_error'], '0x2302f95')
        self.assertEqual(branches['qst_map_q_payload'], '0x2302fcf')
        self.assertEqual(branches['qst_map_n_missing_nil'], '0x2303025')
        self.assertEqual(branches['qst_map_n_not_nil'], '0x230305a')
        edges = {row['label']: row for row in self.result['edges']}
        self.assertEqual(edges['row_qst_reader']['target_va'], '0x1684b00')
        self.assertEqual(edges['qst_map_entry']['target_va'], '0x2302f30')
        self.assertEqual(edges['qst_map_key']['target_va'], '0x19054d0')
        self.assertEqual(edges['qst_map_action_reader']['target_va'], '0x1687210')
        self.assertEqual(edges['qst_key_classifier_borrowed']['target_va'], '0x2301760')
        self.assertEqual(edges['qst_bare_q_error_helper']['target_va'], '0x1705920')
        v.check_window(self.image, 'builder-error', 0x1705986, '48c70374000000')
        v.check_window(self.image, 'reader-error', 0x1684ca3, '48c70375000000')

    def test_row_field_switch_and_deeper_vts_write(self):
        tables = {row['label']: row for row in self.result['relative_tables']}
        self.assertEqual([entry['target_va'] for entry in tables['row_named_fields']['entries']],
                         ['0x17c2fc2', '0x17c2ef9', '0x17c30ac', '0x17c2f98'])
        edges = {row['label']: row for row in self.result['edges']}
        self.assertEqual(edges['row_qst_payload_writer']['target_va'],
                         edges['vts_pair_key_writer']['target_va'])
        self.assertEqual(edges['vts_pair_value_writer']['target_va'], '0x231d2c0')
        literals = {row['label']: row['ascii'] for row in self.result['literals']}
        self.assertEqual((literals['vote_value_vks'], literals['vote_value_hvs']), ('vks', 'hvs'))
        self.assertEqual(literals['enum_type_name'], 'VoteGlobalAction')
        for label in ('vts_array_pair_error', 'vts_pair_key_error',
                      'vts_pair_value_error', 'vote_value_vks_child_error',
                      'vote_value_hvs_child_error'):
            self.assertIn(label, {row['label'] for row in self.result['branches']})
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            v.check_window(self.modified_va(0x16fcb7d), 'rowkey', 0x16fcb7b, '83f861')

    def test_materialization_guard_boundaries_and_corruption(self):
        guard = self.result['materialization_guard']
        self.assertEqual(guard['count_shift'], 4)
        self.assertEqual(guard['high_bits_shift'], 60)
        self.assertEqual(guard['byte_limit'], '0x7ffffffffffffff8')
        self.assertEqual(guard['max_count_without_guard_call'], '0x7ffffffffffffff')
        for value in (0, 1, (1 << 59) - 1):
            self.assertFalse(v.guard_takes_call(self.image, value))
        for value in (1 << 59, 1 << 60, (1 << 64) - 1):
            self.assertTrue(v.guard_takes_call(self.image, value))
        for value in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                v.guard_takes_call(self.image, value)
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            v.materialization_guard(self.modified_va(0x256a2df))
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            v.materialization_guard(self.modified_va(0x256a2d9))

    def test_action_table_and_bounded_selector(self):
        dispatch = self.result['action_dispatch']
        self.assertEqual((dispatch['lower_bound'], dispatch['fallback_index']), (18, 78))
        entries = dispatch['entries']
        self.assertEqual(len(entries), 79)
        self.assertEqual(len({row['target_va'] for row in entries}), 79)
        self.assertEqual(entries[0]['target_va'], '0x236b295')
        self.assertEqual(entries[-1]['target_va'], '0x236ceb0')
        self.assertTrue(entries[-1]['is_fallback_slot'])
        for value, index in ((0, 78), (17, 78), (18, 0), (19, 1), (95, 77), (96, 78)):
            self.assertEqual(v.action_index(self.image, value), index)
        # These are boundaries of the model, not claims about the machine's
        # behavior on arbitrary or invalid in-memory discriminants.
        for invalid in (-1, 97, True):
            with self.assertRaises(ValueError):
                v.action_index(self.image, invalid)
        with self.assertRaisesRegex(ValueError, 'action selector'):
            v.action_dispatch(self.modified_va(0x236b278))
        with self.assertRaisesRegex(ValueError, 'action table bytes'):
            v.action_dispatch(self.modified_va(0x3dd85c))

    def test_address_bounds_and_nobits_are_rejected(self):
        for va, size in ((-1, 1), (0, 0), (0xffffffffffffffff, 1)):
            with self.assertRaises(ValueError):
                self.image.read(va, size)
        text_sec = next(row for row in self.sections if row['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text_sec['address'] + text_sec['size'] - 1, 2, True)
        only_nobits = v.Image(b'1234', [{'name': '.bss', 'type': 8, 'flags': 2,
                                       'address': 0x1000, 'offset': 0, 'size': 4}])
        with self.assertRaises(ValueError):
            only_nobits.read(0x1000, 1)

    def test_result_is_derived_from_the_pinned_target(self):
        self.assertEqual(self.result['sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(len(self.result['branches']), 148)
        self.assertEqual(len(self.result['windows']), 164)
        self.assertEqual(len(self.result['relative_tables']), 8)
        self.assertEqual(len(self.result['relocations']), 2)


if __name__ == '__main__':
    unittest.main()
