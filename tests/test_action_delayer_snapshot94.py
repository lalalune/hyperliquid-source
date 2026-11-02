"""Static controls for the node #94 ActionDelayer state evidence."""
import hashlib
import struct
import unittest
from pathlib import Path

from tools import action_delayer_snapshot94 as subject


class SnapshotEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.sections = subject.sections(cls.data)
        cls.record = subject.analyze(cls.data)
        cls.fields = cls.record['fields']

    def test_digest_and_scope(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        self.assertEqual(len(self.record['functions']), 53)
        self.assertEqual(next(x for x in self.record['functions'] if x['role'] == 'msgpack_reader')['start_va'], '0x1767dd0')
        self.assertEqual(next(x for x in self.record['functions'] if x['role'] == 'msgpack_reader')['end_va_exclusive'], '0x176ba2b')

    def test_corrupt_digest_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.check_digest(b'not a node')
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.check_digest(data)

    def test_writer_order_and_layout(self):
        expected = [
            ('delayed_actions', '0x30'), ('user_to_n_delayed_actions', '0x48'),
            ('n_total_delayed_actions', '0x60'), ('max_n_delayed_actions', '0x68'),
            ('vty_trackers', '0x70'), ('status_guard', '0x20'),
            ('delayer_mode', '0x0'), ('delay_scale', '0x88'),
        ]
        self.assertEqual([(row['name'], row['state_offset']) for row in self.fields], expected)
        self.assertEqual([row['tag'] for row in self.fields], list(range(8)))
        self.assertTrue(all(row['json_writer_name_lea_va'] for row in self.fields))

    def test_classifier_key_mutation_controls(self):
        rows = self.record['field_classifier']
        for row in rows:
            key = row['text'].encode('ascii')
            self.assertEqual(subject.classify(rows, key), row['code'])
            for i in range(len(key)):
                variant = key[:i] + bytes((key[i] ^ 1,)) + key[i + 1:]
                self.assertEqual(subject.classify(rows, variant), 8, (row['text'], i))
            self.assertEqual(subject.classify(rows, key[:-1]), 8)
            self.assertEqual(subject.classify(rows, key + b'x'), 8)
        self.assertEqual(subject.classify(rows, b''), 8)
        self.assertEqual(subject.classify(rows, b'\xff' * 12), 8)

    def test_classifier_rejects_corrupt_branch(self):
        va = 0x22ecdb8
        _, off = subject.mapped(self.data, self.sections, va, 6)
        broken = bytearray(self.data)
        broken[off + 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'reject mismatches'):
            subject.classifier_arm(broken, self.sections, 0x22ecdb5, 15)

    def test_classifier_rejects_corrupt_offset(self):
        _, off = subject.mapped(self.data, self.sections, 0x22ecdbe, 4)
        broken = bytearray(self.data)
        broken[off + 2] = 9
        with self.assertRaisesRegex(ValueError, 'indexed compare'):
            subject.classifier_arm(broken, self.sections, 0x22ecdb5, 15)

    def test_field_dispatch_and_failures(self):
        self.assertEqual(self.record['field_dispatch'][-1], '0x176acf9')
        self.assertEqual(self.record['unknown_field_call'], '0x19682d0')
        self.assertEqual(sum(x['msgpack_missing_name_lea_va'] is not None for x in self.fields), 6)
        self.assertEqual(sum(x['json_missing_name_lea_va'] is not None for x in self.fields), 6)
        self.assertEqual(len({x['duplicate_branch_va'] for x in self.fields}), 8)
        self.assertTrue(all(x['json_duplicate_name_lea_va'] for x in self.fields))

    def test_map_and_sequence_defaults(self):
        self.assertEqual(self.record['scale_default']['bytes'], '000000000000f03f')
        self.assertEqual(self.record['scale_default']['binary64'], 1.0)
        self.assertEqual([x['target_va'] for x in self.record['sequence_missing_guards']],
                         ['0x1768b2a', '0x1768a4b', '0x1768b4f', '0x1768ef3',
                          '0x1769099', '0x1769260', '0x17695d7'])

    def test_mode_variants_and_guards(self):
        self.assertEqual(self.record['variants'], [{'tag': 0, 'name': 'Enabled'},
                                                  {'tag': 1, 'name': 'PerAsset'}])
        self.assertEqual(subject.branch(self.data, self.sections, 0x1685148)[1], 0x16851c2)
        self.assertEqual(subject.branch(self.data, self.sections, 0x16851c0)[1], 0x168514a)
        self.assertEqual(subject.rel_call(self.data, self.sections, 0x1685154), 0x22ec060)

    def test_mode_names_reject_single_byte_changes(self):
        names = {x['name'].encode('ascii'): x['tag'] for x in self.record['variants']}
        for name in names:
            for i in range(len(name)):
                changed = name[:i] + bytes([name[i] ^ 1]) + name[i + 1:]
                self.assertNotIn(changed, names)
            self.assertNotIn(name + b'x', names)
        self.assertNotIn(b'', names)

    def test_per_asset_map_and_sequence_duplicate_paths(self):
        m = self.record['per_asset']
        self.assertEqual((m['key_type_label'], m['value_type_label']), ('AssetWire', 'ActionDelayerStatus'))
        self.assertEqual((m['key_order'], m['value_slot_bytes'], m['existing_key_result']), ('u32', 8, 1))
        self.assertEqual(m['map_duplicate_error_va'], '0x2637e3d')
        self.assertEqual(m['sequence_duplicate_error_va'], '0x267e9fc')
        self.assertEqual(subject.rel_jump(self.data, self.sections, 0x23d8e82), 0x25ecca0)
        with self.assertRaises(ValueError):
            subject.rel_jump(self.data, self.sections, 0x23d8e00)

    def test_per_asset_status_variants_and_seconds_guards(self):
        m = self.record['per_asset']
        self.assertEqual(m['status_variants'], [{'tag': 0, 'name': 'On'}, {'tag': 1, 'name': 'Alternating'}])
        self.assertEqual(m['status_payload_field'], 'seconds')
        self.assertEqual(subject.branch(self.data, self.sections, 0x19b3f0a)[:2], (0x85, 0x19b4472))
        broken = bytearray(self.data)
        _, off = subject.mapped(broken, self.sections, 0x22ef349, 2)
        broken[off + 1] ^= 1
        with self.assertRaises(ValueError):
            subject.variant_arm(broken, self.sections, 0x22ef340, 2, 0, 0x22ef3ac)

    def test_seconds_numeric_relative_slot_and_marker_routes(self):
        m = self.record['per_asset']
        self.assertEqual(m['seconds_numeric_slot_va'], '0x5770c68')
        self.assertEqual(m['seconds_numeric_rela_addend'], '0x2eb9f30')
        relocation = m['seconds_numeric_rela_record']
        self.assertEqual(relocation['section'], '.rela.dyn')
        self.assertEqual(bytes.fromhex(relocation['record_bytes']), struct.pack('<QQq', 0x5770c68, 8, 0x2eb9f30))
        cases = {row['marker']: row['target_va'] for row in m['seconds_marker_routes']}
        self.assertEqual(cases['0xcc'], '0x2eba01c')
        self.assertEqual(cases['0xcf'], '0x2eba170')
        self.assertEqual(cases['0xd0'], '0x2eba10c')
        self.assertEqual(cases['0xd3'], '0x2eba13d')
        self.assertEqual(len(m['seconds_integer_guards']), 10)
        self.assertEqual(subject.branch(self.data, self.sections, 0x2eba04e)[:2], (0x8e, 0x2eba20a))
        self.assertEqual(subject.branch(self.data, self.sections, 0x2eba0b8)[:2], (0x84, 0x2eba1fa))
        self.assertEqual(subject.branch(self.data, self.sections, 0x2eba1ba)[:2], (0x74, 0x2eba1fa))
        self.assertEqual(subject.branch(self.data, self.sections, 0x2eba12e)[:2], (0x8e, 0x2eba210))
        self.assertEqual(subject.branch(self.data, self.sections, 0x2eba164)[:2], (0x7f, 0x2eba1bf))

    def test_relative_slot_rejects_ambiguous_and_nonrelative_records(self):
        slot = 0x1000
        record = struct.pack('<QQq', slot, 8, 0x1234)
        sec = {'type': 4, 'offset': 0, 'size': len(record)}
        self.assertEqual(subject.relative_slot(record, [sec], slot), 0x1234)
        with self.assertRaises(ValueError):
            subject.relative_slot(record + record, [dict(sec, size=48)], slot)
        with self.assertRaises(ValueError):
            subject.relative_slot(struct.pack('<QQq', slot, (1 << 32) | 8, 0x1234), [sec], slot)
        with self.assertRaises(ValueError):
            subject.relative_slot(record, [sec, {'type': 19}], slot)
        with self.assertRaises(ValueError):
            subject.relative_slot(record[:-1], [sec], slot)

    def test_instruction_corruption_is_refused(self):
        _, off = subject.mapped(self.data, self.sections, 0x1769cba, 8)
        broken = bytearray(self.data)
        broken[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction bytes changed'):
            subject.pin(broken, self.sections, 0x1769cba, bytes.fromhex('f68424b003000001'))

    def test_bad_address_and_nobits_are_refused(self):
        with self.assertRaises(ValueError):
            subject.mapped(self.data, self.sections, 0xffffffffffffffff, 8)
        with self.assertRaises(ValueError):
            subject.mapped(self.data, self.sections, 0x1767dd0, -1)
        with self.assertRaises(ValueError):
            subject.mapped(b'1234', [{'type': 8, 'size': 4, 'address': 100, 'offset': 0}], 100, 1)
        with self.assertRaises(ValueError):
            row = {'type': 1, 'size': 4, 'address': 100, 'offset': 0}
            subject.mapped(b'1234', [row, row.copy()], 100, 1)
        with self.assertRaises(ValueError):
            subject.mapped(b'12', [row], 100, 4)

    def test_bad_call_and_branch_are_refused(self):
        with self.assertRaises(ValueError):
            subject.rel_call(self.data, self.sections, 0x2311e90)
        with self.assertRaises(ValueError):
            subject.branch(self.data, self.sections, 0x2311e90)

    def test_queue_shape_and_duplicate(self):
        queue = self.record['queue']
        self.assertEqual(queue['key_label'], 'Time')
        self.assertEqual(queue['key_size_bytes'], 12)
        self.assertEqual(queue['record_stride_bytes'], 0x148)
        self.assertEqual(queue['pair_marker_byte'], 0x92)
        self.assertEqual(queue['pair_expected_length'], 2)
        self.assertEqual(queue['pair_zero_length_error_va'], '0x1993c74')
        self.assertEqual(queue['pair_one_length_error_va'], '0x1993cea')
        self.assertEqual(queue['pair_excess_length_error_va'], '0x1993c18')
        self.assertEqual(queue['duplicate_diagnostic'], 'duplicate key')
        self.assertEqual(queue['duplicate_branch_va'], '0x264d89c')
        self.assertEqual(queue['sequence_duplicate_branch_va'], '0x26835c6')

    def test_inner_record_fields_and_duplicate_routes(self):
        rows = self.record['queue_record_fields']
        self.assertEqual([x['name'] for x in rows],
                         ['user', 'action', 'id', 'is_frontend', 'expires_after', 'broadcaster'])
        self.assertEqual([x['tag'] for x in rows], list(range(6)))
        self.assertEqual(len({x['duplicate_branch_va'] for x in rows}), 6)
        self.assertEqual([x['name'] for x in rows if x['missing_name_lea_va'] is None], ['expires_after'])
        broken = bytearray(self.data)
        _, off = subject.mapped(broken, self.sections, 0x22ed6f7, 1)
        broken[off] ^= 1
        with self.assertRaises(ValueError):
            subject.record_fields(broken, self.sections)
        broken = bytearray(self.data)
        _, off = subject.mapped(broken, self.sections, 0x17b3193, 6)
        broken[off + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'duplicate branch'):
            subject.record_fields(broken, self.sections)

    def test_record_id_fields_and_duplicate_routes(self):
        rows = self.record['queue_record_id_fields']
        self.assertEqual([x['name'] for x in rows], ['height', 'tx_index'])
        self.assertEqual([x['record_offset'] for x in rows], ['0x100', '0x108'])
        self.assertEqual([x['duplicate_branch_va'] for x in rows], ['0x1886bc5', '0x18871d3'])
        broken = bytearray(self.data)
        _, off = subject.mapped(broken, self.sections, 0x22edcb7, 2)
        broken[off + 1] ^= 1
        with self.assertRaises(ValueError):
            subject.record_id_fields(broken, self.sections)

    def test_broadcaster_variants_and_rejection(self):
        self.assertEqual(self.record['broadcaster_variants'],
                         [{'tag': 0, 'name': 'Evm', 'payload_memory_bytes': 32},
                          {'tag': 1, 'name': 'Broadcaster', 'payload_memory_bytes': 20}])
        broken = bytearray(self.data)
        _, off = subject.mapped(broken, self.sections, 0x21e7b49, 2)
        broken[off + 1] ^= 1
        with self.assertRaises(ValueError):
            subject.variant_arm(broken, self.sections, 0x21e7b40, 3, 0, 0x21e7bb2)

    def test_missing_expiry_and_nil_writer(self):
        self.assertEqual(self.record['absent_record_expiry'],
                         {'writer_null_byte': 0xc0, 'missing_presence_sentinel': 2})
        self.assertEqual(subject.branch(self.data, self.sections, 0x2312b7d)[1], 0x2312bef)

    def test_queue_key_signed_and_unsigned_boundaries(self):
        key = lambda a, b, c: struct.pack('<iII', a, b, c)
        self.assertLess(subject.compare_queue_keys(key(-1, 0xffffffff, 0xffffffff), key(0, 0, 0)), 0)
        self.assertGreater(subject.compare_queue_keys(key(0, 0xffffffff, 0), key(0, 0, 0)), 0)
        self.assertGreater(subject.compare_queue_keys(key(0, 1, 0x80000000), key(0, 1, 0x7fffffff)), 0)
        self.assertEqual(subject.compare_queue_keys(key(-2, 8, 42), key(-2, 8, 42)), 0)
        with self.assertRaises(ValueError):
            subject.compare_queue_keys(b'123', key(0, 0, 0))

    def test_queue_replaced_entry_selects_error_path(self):
        self.assertEqual(subject.rel_call(self.data, self.sections, 0x264d7e7), 0x284e5d0)
        self.assertEqual(subject.branch(self.data, self.sections, 0x264d7fe)[1], 0x264d89c)
        subject.pin(self.data, self.sections, 0x1deeabd, bytes.fromhex('c6040192'))
        _, off = subject.mapped(self.data, self.sections, 0x1deeabd, 4)
        broken = bytearray(self.data)
        broken[off + 3] ^= 1
        with self.assertRaises(ValueError):
            subject.pin(broken, self.sections, 0x1deeabd, bytes.fromhex('c6040192'))

    def test_raw_copy_comparison_has_no_masks(self):
        comparison = self.record['raw_copy_comparison']
        self.assertEqual(comparison['total_bytes'], 676)
        self.assertGreater(comparison['different_byte_positions'], 0)
        self.assertEqual(comparison['equal_byte_positions'] + comparison['different_byte_positions'], 676)
        self.assertEqual(comparison['normalization_masks'], [])
        count = 0
        for row in comparison['difference_ranges']:
            a, b = row['start_offset'], row['end_offset_exclusive']
            left = bytes.fromhex(row['left_bytes'])
            right = bytes.fromhex(row['right_bytes'])
            self.assertEqual(len(left), b - a)
            self.assertEqual(len(right), b - a)
            self.assertTrue(all(x != y for x, y in zip(left, right)))
            self.assertEqual(left, subject.read(self.data, self.sections, 0x2311e90 + a, b - a))
            self.assertEqual(right, subject.read(self.data, self.sections, 0x48b2660 + a, b - a))
            count += b - a
        self.assertEqual(count, comparison['different_byte_positions'])


if __name__ == '__main__':
    unittest.main()
