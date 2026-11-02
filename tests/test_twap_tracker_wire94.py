import mmap
import struct
import unittest

from tools import twap_tracker_wire94 as t


class TrackerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = t.BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = t.Image(cls.data)
        cls.evidence, cls.rows = t.collect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_input_identity_and_corrupt_hash(self):
        t.verify_digest(self.data)
        old = self.data[0]
        try:
            self.data[0] = old ^ 1
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                t.verify_digest(self.data)
        finally:
            self.data[0] = old

    def test_schema_and_relative_dispatch(self):
        c = self.evidence['classifier']
        self.assertEqual(c['field_names'], ['running_heap', 'user_to_id_to_state'])
        self.assertEqual(c['codes'], [0, 1, 2])
        self.assertEqual(c['end_of_map_code'], 3)
        self.assertEqual(c['dispatch_targets'],
                         ['0x190712a', '0x1907099', '0x1907100', '0x1907193'])
        self.assertEqual(self.evidence['literals'][-1]['text'], 'spot_twap_tracker')

    def test_field_comparisons_exhaust_each_bit(self):
        names = [x.encode('ascii') for x in self.evidence['classifier']['field_names']]
        codes = self.evidence['classifier']['codes']
        for expected, key in enumerate(names):
            self.assertEqual(t.classify(key, names, codes), expected)
            for pos in range(len(key)):
                for bit in range(8):
                    changed = key[:pos] + bytes([key[pos] ^ (1 << bit)]) + key[pos + 1:]
                    self.assertEqual(t.classify(changed, names, codes), 2, (pos, bit))
            self.assertEqual(t.classify(key[:-1], names, codes), 2)
            self.assertEqual(t.classify(key + b'\x00', names, codes), 2)
        self.assertEqual(t.classify(b'', names, codes), 2)

    def test_named_and_compact_container_shape(self):
        self.assertEqual(self.evidence['compact_header'],
                         {'xor': 1, 'shift': 4, 'or': 130, 'flag_0': 146, 'flag_1': 130})
        self.assertEqual(self.evidence['compact_item_header'],
                         {'xor': 1, 'shift': 4, 'or': 131, 'flag_0': 147, 'flag_1': 131})
        self.assertEqual(self.evidence['layout'], {
            'heap_stride': 40, 'compact_heap_stride': 40,
            'outer_tree_row_stride': 16, 'pair_marker': 146,
            'compact_pair_marker': 146, 'key_input_length': 20,
            'key_format_buffer_length': 42, 'formatter_slot_va': '0x5773120',
            'formatter_relocation_target_va': '0x29ed380'})
        self.assertEqual([x['text'] for x in self.evidence['literals'][2:5]],
                         ['next_slice_time', 'user', 'twap_id'])

    def test_missing_and_duplicate_messages_bound_to_fields(self):
        rows = {x['case']: x for x in self.evidence['field_errors']}
        self.assertEqual(set(rows), {'missing_heap', 'missing_map', 'duplicate_heap', 'duplicate_map'})
        for case, row in rows.items():
            self.assertEqual(row['field'], 'running_heap' if case.endswith('heap') else 'user_to_id_to_state')
            self.assertEqual(row['prefix'], 'missing field `' if case.startswith('missing') else 'duplicate field `')
            self.assertEqual(row['field_length'], len(row['field']))

    def test_all_relative_edges_are_fixed(self):
        self.assertEqual(len(t.EDGES), self.evidence['relative_edge_count'])
        for va, destination in t.EDGES.items():
            self.assertEqual(t.relative_target(self.image, va), destination, hex(va))

    def test_corrupt_branch_operand_is_detected(self):
        va = 0x26db310
        off = self.image.offset(va, 2, True)
        original = self.data[off + 1]
        try:
            self.data[off + 1] ^= 1
            self.assertNotEqual(t.relative_target(self.image, va), t.EDGES[va])
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                t.require_pin(self.image, va, bytes.fromhex(t.PINS[va]))
        finally:
            self.data[off + 1] = original

    def test_corrupt_constant_and_opcode_are_detected(self):
        for va, index in ((0x26db3b5, 3), (0x26db301, 0), (0x26c026f, 2)):
            off = self.image.offset(va, len(bytes.fromhex(t.PINS[va])), True) + index
            original = self.data[off]
            try:
                self.data[off] ^= 1
                with self.assertRaisesRegex(ValueError, 'window mismatch'):
                    t.require_pin(self.image, va, bytes.fromhex(t.PINS[va]))
            finally:
                self.data[off] = original

    def test_reject_unbacked_and_outside_ranges(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        for va, size in ((bss['address'], 1), (-1, 1), (0, 0), (1 << 63, 8)):
            with self.assertRaises(ValueError):
                self.image.offset(va, size)
        rodata = next(s for s in self.image.sections if s['name'] == '.rodata')
        with self.assertRaises(ValueError):
            self.image.offset(rodata['address'], 1, executable=True)

    def test_fde_and_windows_stay_inside_file_backed_code(self):
        self.assertEqual(len(self.evidence['functions']), 24)
        self.assertEqual(len(self.rows), len(t.PINS))
        functions = [(int(x['start_va'], 16), int(x['end_va'], 16))
                     for x in self.evidence['functions']]
        for row in self.rows:
            va, size = int(row['va'], 16), len(bytes.fromhex(row['bytes']))
            self.assertEqual(sum(lo <= va and va + size <= hi for lo, hi in functions), 1)

    def test_literal_and_vector_corruption_control(self):
        literal = next(x for x in self.evidence['literals'] if x['text'] == 'running_heap')
        off = self.image.offset(int(literal['literal_va'], 16), literal['length'])
        original = self.data[off]
        try:
            self.data[off] ^= 1
            self.assertNotEqual(self.image.read(int(literal['literal_va'], 16), literal['length']),
                                b'running_heap')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                t.collect(self.data)
        finally:
            self.data[off] = original

    def test_unknown_opcode_rejected(self):
        with self.assertRaises(ValueError):
            t.relative_target(self.image, 0x26db280)
        with self.assertRaises(ValueError):
            t.rip_target(self.image, 0x26db280, b'\x48\x8d\x35', 7)

    def test_unknown_relocation_slot_rejected(self):
        self.assertEqual(t.relative_relocation(self.image, 0x5773120), 0x29ed380)
        with self.assertRaises(ValueError):
            t.relative_relocation(self.image, 0x5773121)

    def test_corrupt_relocation_type_rejected(self):
        section = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        row = next(off for off in range(section['offset'], section['offset'] + section['size'], 24)
                   if struct.unpack_from('<Q', self.data, off)[0] == 0x5773120)
        original = self.data[row + 8:row + 16]
        try:
            self.data[row + 8:row + 16] = struct.pack('<Q', 7)
            with self.assertRaisesRegex(ValueError, 'R_X86_64_RELATIVE'):
                t.relative_relocation(self.image, 0x5773120)
        finally:
            self.data[row + 8:row + 16] = original

    def test_corrupt_fde_length_rejected(self):
        fde = next(f for f in self.evidence['functions'] if f['name'] == 'field_reader')
        off = self.image.offset(int(fde['fde_va'], 16), 4)
        original = self.data[off:off + 4]
        try:
            self.data[off:off + 4] = b'\xff\xff\xff\xff'
            with self.assertRaises(ValueError):
                t.fde_extents.eh_frame_records(self.data, self.image.sections)
        finally:
            self.data[off:off + 4] = original

    def test_length_guard_boundaries_and_invalid_operands(self):
        guard = self.evidence['length_guard']
        self.assertEqual(guard['short_input_target_va'], '0x16f6b5e')
        self.assertEqual(guard['error_word'], 0x2500000003)
        for remaining, length, fits in ((0, 0, True), (0, 1, False), (11, 12, False),
                                        (12, 12, True), (13, 12, True),
                                        ((1 << 64) - 1, (1 << 64) - 1, True)):
            self.assertEqual(t.length_fits(remaining, length), fits)
        for remaining, length in ((-1, 0), (0, -1), (1 << 64, 0), (0, 1 << 64)):
            with self.assertRaises(ValueError):
                t.length_fits(remaining, length)

    def test_time_writer_separator_helpers_and_failure(self):
        data = self.evidence['time_text']
        self.assertEqual(data['separator'], 'T')
        self.assertEqual(data['helper_slots'], ['0x576f560', '0x576f568'] * 2)
        self.assertEqual(data['helper_relocation_targets'], ['0x151f240', '0x15204a0'] * 2)
        self.assertEqual(data['failure_text'],
                         'a Display implementation returned an error unexpectedly')
        self.assertEqual(t.relative_target(self.image, 0x1dfcabb), 0x1dfcb38)
        self.assertEqual(t.relative_target(self.image, 0x1dfcc31), 0x1dfcc98)

    def test_map_reader_duplicate_unknown_and_missing_decisions(self):
        self.assertEqual(t.map_step(0, 0), (1, 'read_heap'))
        self.assertEqual(t.map_step(1, 1), (3, 'read_map'))
        self.assertEqual(t.map_step(3, 0), (3, 'duplicate_heap'))
        self.assertEqual(t.map_step(3, 1), (3, 'duplicate_map'))
        self.assertEqual(t.map_step(3, 2), (3, 'unknown_value'))
        self.assertEqual(t.map_step(0, 3), (0, 'missing_heap'))
        self.assertEqual(t.map_step(1, 3), (1, 'missing_map'))
        self.assertEqual(t.map_step(2, 3), (2, 'missing_heap'))
        self.assertEqual(t.map_step(3, 3), (3, 'complete'))
        self.assertEqual(len(self.evidence['reader_model']['map_steps']), 16)
        for presence, code in ((-1, 0), (4, 0), (0, -1), (0, 4)):
            with self.assertRaises(ValueError):
                t.map_step(presence, code)

    def test_sequence_reader_count_boundaries(self):
        self.assertEqual([t.sequence_arity(i) for i in range(4)],
                         ['missing_first', 'missing_second', 'two_values', 'excess_values'])
        self.assertEqual(t.sequence_arity((1 << 32) - 1), 'excess_values')
        for count in (-1, 1 << 32, 1.0):
            with self.assertRaises(ValueError):
                t.sequence_arity(count)

    def test_heap_item_names_and_error_routes(self):
        item = self.evidence['item_classifier']
        self.assertEqual(item['field_names'], ['next_slice_time', 'user', 'twap_id'])
        self.assertEqual(item['codes'], [0, 1, 2, 3])
        self.assertEqual(item['dispatch_targets'],
                         ['0x19bf850', '0x19bf91b', '0x19bf897', '0x19bf8e2'])
        names = [name.encode('ascii') for name in item['field_names']]
        for index, name in enumerate(names):
            self.assertEqual(t.classify_item(name, names), index)
            for position in range(len(name)):
                for bit in range(8):
                    changed = name[:position] + bytes([name[position] ^ (1 << bit)]) + name[position + 1:]
                    self.assertEqual(t.classify_item(changed, names), 3)
            self.assertEqual(t.classify_item(name[:-1], names), 3)
            self.assertEqual(t.classify_item(name + b'\x00', names), 3)
        errors = {row['case']: row for row in self.evidence['item_field_errors']}
        self.assertEqual(set(errors), {'missing_time', 'missing_user', 'missing_id',
                                       'duplicate_time', 'duplicate_user', 'duplicate_id'})
        for case, row in errors.items():
            self.assertEqual(row['field'], {'time': 'next_slice_time', 'user': 'user',
                                            'id': 'twap_id'}[case.split('_')[1]])
            self.assertEqual(row['prefix'], 'missing field `' if case.startswith('missing') else 'duplicate field `')


if __name__ == '__main__':
    unittest.main()
