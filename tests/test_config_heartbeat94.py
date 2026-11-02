"""Target-grounded controls for the heartbeat configuration packet."""
import hashlib
import struct
import unittest
from unittest.mock import patch

from tools import config_heartbeat94 as m


class TargetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.result = m.collect(cls.data)
        cls.view = m.View(cls.data)

    def test_identity_is_required(self):
        m.verify_identity(self.data)
        with self.assertRaises(ValueError):
            m.verify_identity(self.data, '0' * 64)
        with self.assertRaises(ValueError):
            m.verify_identity(b'')

    def test_same_size_corruption_is_rejected(self):
        digest = hashlib.sha256(b'abc').hexdigest()
        with patch.object(m, 'SIZE', 3):
            m.verify_identity(b'abc', digest)
            with self.assertRaises(ValueError):
                m.verify_identity(b'abd', digest)

    def test_locked_site_rejects_a_flipped_byte(self):
        original = bytes(self.view.read(0x474eed1, 10))
        self.assertEqual(original.hex(), '48b8333333333333c33f')
        damaged = original[:-1] + bytes([original[-1] ^ 1])
        with self.assertRaises(ValueError):
            m.require_bytes(damaged, original, 'threshold')

    def test_changed_key_bytes_fail_the_collector(self):
        original_read = m.View.read

        def corrupt_key(view, address, size):
            result = original_read(view, address, size)
            if address == 0x6fab16 and size == 7:
                return bytes([result[0] ^ 1]) + result[1:]
            return result

        with patch.object(m.View, 'read', corrupt_key):
            with self.assertRaisesRegex(ValueError, 'bool_key'):
                m.collect(self.data)

    def test_changed_key_window_is_out_of_bounds(self):
        original_read = m.View.read

        def corrupt_window(view, address, size):
            result = original_read(view, address, size)
            if address == 0x43aec0c and size == 5:
                return result[:-1] + b'\x7f'
            return result

        with patch.object(m.View, 'read', corrupt_window):
            with self.assertRaisesRegex(ValueError, 'key-comparison operand'):
                m.collect(self.data)

    def test_fdes_and_complete_selected_partitions(self):
        rows = {row['role']: row for row in self.result['functions']}
        self.assertEqual(len(rows), 15)
        self.assertEqual(rows['json_document']['start_va'], '0x43a33b0')
        self.assertEqual(rows['json_config_parser']['end_va'], '0x43af1ff')
        self.assertEqual(rows['tracker_constructor']['start_va'], '0x474ece0')
        self.assertEqual(rows['tracker_constructor']['end_va'], '0x474f8a0')
        self.assertEqual(rows['binary_float_writer']['end_va'], '0x4aeb161')
        self.assertEqual(sum(row['size'] for row in rows.values()), 10548)
        self.assertEqual(sum(row['instructions'] for row in rows.values()), 2409)

    def test_config_path_template_and_relocation(self):
        p = self.result['path']
        self.assertEqual(p['template_bytes'],
                         'c0c0172f66696c655f6d6f645f74696d655f747261636b65722fc0052e6a736f6e00')
        self.assertEqual(p['arguments'][1]['length'], 0)
        self.assertEqual(p['arguments'][2]['relative_addend'], '0x6fb695')
        self.assertEqual(p['arguments'][2]['length'], 24)
        self.assertEqual(p['fixed_suffix_length'], 52)
        self.assertEqual(bytes.fromhex(p['fixed_suffix_hex']).split(b'/')[-1],
                         b'heartbeat_jailing_config.json')
        values = ['ROOT', '', 'heartbeat_jailing_config']
        rendered = ''.join(values[t['index']] if t['kind'] == 'argument'
                           else bytes.fromhex(t['hex']).decode('ascii') for t in p['tokens'])
        self.assertEqual(rendered, 'ROOT/file_mod_time_tracker/heartbeat_jailing_config.json')

    def test_default_values_are_independently_pinned(self):
        c = self.result['constants']
        self.assertEqual(c['threshold_bits'], '0x3fc3333333333333')
        self.assertEqual(c['dry_run_default'], 1)
        self.assertEqual(c['interval_bits'], '0x4014000000000000')
        self.assertEqual(c['seed_row_float_bits'], '0x4066800000000000')
        self.assertEqual(c['json_true_hex'], '74727565')
        self.assertEqual(c['json_false_hex'], '66616c7365')
        self.assertEqual(c['binary_bool_base'], '0xc2')
        self.assertEqual(c['binary_float_marker'], '0xcb')
        self.assertEqual(c['json_missing_bool'], 1)
        self.assertEqual(c['json_missing_float_bits'], '0x3fc3333333333333')
        self.assertEqual(c['json_whitespace_mask'], '0x100002600')
        self.assertEqual(c['json_whitespace_upper_byte'], 32)
        self.assertEqual(c['json_trailing_error_code'], 22)

    def test_output_layout_and_copy(self):
        got = {r['role']: r['result_offset'] for r in self.result['stores']}
        self.assertEqual(got, {'path_capacity': '0xb0', 'path_pointer': '0xb8',
                               'path_length': '0xc0', 'threshold_bits': '0xc8',
                               'dry_run_byte': '0xd0', 'check_interval_bits': '0xd8',
                               'error_word': '0xf0', 'metadata_first_word': '0xf8',
                               'metadata_other_words': '0xfc'})
        self.assertIn('ba60010000', self.view.read(0x474f494, 30).hex())

    def test_call_targets_are_relative_operands(self):
        e = {row['role']: row for row in self.result['edges']}
        self.assertEqual(e['binary_encoder']['encoded_target_or_slot'], '0x474ff60')
        self.assertEqual(e['seed_rows']['encoded_target_or_slot'], '0x474e220')
        self.assertEqual(e['insert_seed_row']['encoded_target_or_slot'], '0x4938330')
        self.assertEqual(e['config_cell']['relative_addend'], '0x577b288')
        self.assertEqual(e['write_step']['relative_addend'], '0x144c560')
        self.assertEqual(e['json_float']['encoded_target_or_slot'], '0x4a806e0')
        self.assertEqual(e['prior_parser_json_boundary']['encoded_target_or_slot'], '0x43a33b0')
        self.assertEqual(e['json_document_to_config']['encoded_target_or_slot'], '0x43ae9c0')
        self.assertEqual(e['json_object_bool']['encoded_target_or_slot'], '0x43aa8d0')
        self.assertEqual(e['json_object_number']['encoded_target_or_slot'], '0x43a9250')

    def test_distinct_failure_edges(self):
        b = {row['role']: row for row in self.result['branches']}
        self.assertEqual(b['regular_file']['taken_va'], '0x474eed1')
        self.assertEqual(b['metadata_tag']['fallthrough'], 'metadata error')
        self.assertEqual(b['parse_tag']['fallthrough'], 'parse error')
        self.assertEqual(b['binary_result']['taken_va'], '0x474f69c')
        self.assertEqual(b['parent_result']['taken_va'], '0x474f658')
        self.assertEqual(b['write_result']['taken_va'], '0x474f737')
        self.assertEqual(b['map_comparison']['taken_va'], '0x4938416')
        self.assertEqual(b['json_bool_key_duplicate']['taken_va'], '0x43af11c')
        self.assertEqual(b['json_float_key_duplicate']['taken_va'], '0x43af105')
        self.assertEqual(b['json_trailing_above_space']['taken_va'], '0x43a3476')
        cfg = {r['role']: r['reachable_overapprox'] for r in self.result['cfg']}
        self.assertEqual(cfg['binary_error_to_write'], 0)
        self.assertEqual(cfg['fallback_to_seed_rows'], 1)
        self.assertEqual(cfg['json_object_to_bool'], 1)
        self.assertEqual(cfg['json_duplicate_to_bool_parser'], 0)

    def test_json_key_comparisons_reject_mutated_bytes(self):
        for role, address, length in (('bool', 0x6fab16, 7), ('float', 0x6fab1d, 26)):
            expected = bytes(self.view.read(address, length))
            windows = [row for row in self.result['key_windows'] if row['key'] == role]

            def matches(candidate):
                return len(candidate) == length and all(
                    candidate[row['input_offset']:row['input_offset'] + row['length']].hex() == row['bytes']
                    for row in windows)

            self.assertTrue(matches(expected))
            self.assertFalse(matches(expected[:-1]))
            self.assertFalse(matches(expected + b'X'))
            for index in range(length):
                changed = bytearray(expected)
                changed[index] ^= 1
                with self.subTest(role=role, index=index):
                    self.assertFalse(matches(changed))
        self.assertEqual([x['byte'] for x in self.result['whitespace']], [9, 10, 13, 32])

    def test_comparison_windows_cover_entire_keys(self):
        self.assertEqual(self.result['key_layout'], {
            'bool': {'key_length': 7, 'covered_bytes': 7, 'overlap_bytes': 1},
            'float': {'key_length': 26, 'covered_bytes': 26, 'overlap_bytes': 6},
        })
        windows = self.result['key_windows']
        self.assertEqual([(x['key'], x['input_offset'], x['length']) for x in windows],
                         [('bool', 0, 4), ('bool', 3, 4),
                          ('float', 0, 16), ('float', 10, 16)])
        self.assertEqual(windows[1]['constant_va'], '0x6fab19')
        self.assertEqual(windows[3]['constant_va'], '0x6fab27')

    def test_json_boolean_literal_and_whitespace_bytes(self):
        c = self.result['constants']
        self.assertEqual(bytes.fromhex(c['json_bool_true_word']), b'true')
        self.assertEqual(bytes.fromhex(c['json_bool_false_word']), b'false')
        self.assertNotEqual(bytes.fromhex(c['json_bool_true_word']), b'True')
        mask = int(c['json_whitespace_mask'], 16)
        self.assertEqual([x for x in range(33) if (mask >> x) & 1], [9, 10, 13, 32])
        self.assertFalse((mask >> 11) & 1)
        b = {row['role']: row for row in self.result['branches']}
        self.assertEqual(b['json_bool_truncated_true']['taken'], 'unexpected end')
        self.assertEqual(b['json_bool_first_t']['taken'], 'invalid boolean type')

    def test_nonfinite_and_negative_zero_boundaries(self):
        c = self.result['constants']
        mask = int(c['json_magnitude_mask'], 16)
        inf = int(c['json_infinity_bits'], 16)
        self.assertEqual(mask, 0x7fffffffffffffff)
        self.assertEqual(inf, 0x7ff0000000000000)
        for word in (0, 1 << 63, inf - 1, 0x3fc3333333333333):
            self.assertLess(word & mask, inf)
        for word in (inf, (1 << 63) | inf, inf | 1, (1 << 63) | inf | 1):
            self.assertGreaterEqual(word & mask, inf)
        self.assertEqual(c['binary_float_marker'], '0xcb')
        contracts = {row['label']: row for row in self.result['contracts']}
        self.assertIn('480fc8', contracts['messagepack_float_bytes']['bytes'])
        self.assertIn('6e756c6c', contracts['json_float_values']['bytes'])

    def test_file_failure_paths(self):
        cfg = {r['role']: r['reachable_overapprox'] for r in self.result['cfg']}
        for role in ('special_to_defaults', 'first_failure_to_diagnostic',
                     'second_failure_to_diagnostic', 'write_success_to_seed_rows'):
            self.assertEqual(cfg[role], 1)
        self.assertEqual(cfg['binary_error_to_write'], 0)

    def test_seed_map_layout(self):
        self.assertEqual(self.result['map_layout'], {
            'key_bytes': 20, 'value_stride': 104, 'new_root_allocation': 1376,
            'new_root_capacity_limit': 11, 'tracker_map_offset': 288, 'final_copy_bytes': 352})
        offsets = {row['role']: row['row_offset'] for row in self.result['seed_stores']}
        self.assertEqual(offsets['zero_header'], '0x0')
        self.assertEqual(offsets['zero_sixteen'], '0x10')
        self.assertEqual(offsets['duration_word'], '0x20')
        self.assertEqual(offsets['zero_word_50'], '0x50')

    def test_existing_file_failure_paths(self):
        b = {row['role']: row for row in self.result['branches']}
        self.assertEqual(b['metadata_tag']['bytes'], '7514')
        self.assertEqual(b['metadata_tag']['fallthrough'], 'metadata error')
        self.assertEqual(b['parse_tag']['bytes'], '751a')
        self.assertEqual(b['parse_tag']['fallthrough'], 'parse error')
        cfg = {r['role']: r['reachable_overapprox'] for r in self.result['cfg']}
        self.assertEqual(cfg['metadata_error_to_fallback'], 1)
        self.assertEqual(cfg['parse_error_to_fallback'], 1)

    def test_duplicate_selected_fde_is_rejected(self):
        fake = {'start': 0x43a33b0, 'end': 0x43a34c5, 'fde': 1, 'cie': 2, 'lsda': None}
        with patch.object(m, 'eh_frame_records', return_value=({}, [fake, dict(fake)])):
            with self.assertRaises(ValueError):
                m.collect(self.data)

    def test_exception_records_are_bounded(self):
        self.assertEqual(len(self.result['lsda_headers']), 6)
        self.assertEqual(len(self.result['lsda_sites']), 56)
        for row in self.result['lsda_sites']:
            self.assertLess(int(row['start_va'], 16), int(row['end_va'], 16))


class NegativeControls(unittest.TestCase):
    def test_file_backing_range_and_ambiguity(self):
        base = {'name': 'x', 'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0, 'size': 4}
        nobits = dict(base, name='nobits', type=8)
        view = m.View(b'abcd', [base, nobits])
        self.assertEqual(view.read(0x103, 1), b'd')
        for address, count in ((0x104, 1), (0xff, 1), (0x103, 2), (0x100, 0), (-1, 1)):
            with self.subTest(address=address, count=count), self.assertRaises(ValueError):
                view.read(address, count)
        with self.assertRaises(ValueError):
            m.View(b'abcd', [base, dict(base, name='overlap')]).read(0x100, 1)
        with self.assertRaises(ValueError):
            m.View(b'abcd', [nobits]).read(0x100, 1)

    def test_immediate_opcode_corruption(self):
        sec = {'name': 'x', 'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0, 'size': 5}
        view = m.View(bytes.fromhex('ba14000000'), [sec])
        self.assertEqual(m.immediate(view, 0x100, bytes.fromhex('ba'), 4), 20)
        with self.assertRaises(ValueError):
            m.immediate(view, 0x100, bytes.fromhex('bb'), 4)
        with self.assertRaises(ValueError):
            m.immediate(view, 0x101, bytes.fromhex('ba'), 4)

    def test_template_corruption(self):
        self.assertEqual(m.parse_template(bytes.fromhex('c0016100')),
                         [{'kind': 'argument', 'index': 0}, {'kind': 'literal', 'size': 1, 'hex': '61'}])
        for raw in (bytes.fromhex('c00161'), bytes.fromhex('036100'), bytes.fromhex('c100'), bytes.fromhex('0000')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.parse_template(raw)

    def test_instruction_and_branch_corruption(self):
        with self.assertRaises(ValueError):
            m.decode_one(bytes.fromhex('0f84'), 0, 0)
        with self.assertRaises(ValueError):
            m.decode_one(bytes.fromhex('0fff'), 0, 0)
        with self.assertRaises(ValueError):
            m.decode_body(bytes.fromhex('ebffc3'), 0)
        with self.assertRaises(ValueError):
            m.decode_one(b'\x66' * 9 + b'\x90', 0, 0)

    def test_lsda_corruption_and_boundaries(self):
        def make(raw):
            sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
                   'address': 0x1000, 'offset': 0, 'size': len(raw)}
            return m.View(raw, [sec])
        raw = bytes.fromhex('ffff010400010200')
        head, rows = m.parse_lsda(make(raw), 0x2000, 0x200a, 0x1000)
        self.assertEqual(head['entries'], 1)
        self.assertEqual(rows[0]['landing_va'], '0x2002')
        for corrupt in (bytes.fromhex('ffff010400000200'), bytes.fromhex('ffff010400010a00'),
                        bytes.fromhex('ffff010500010200'), bytes.fromhex('ff00010400010200')):
            with self.subTest(raw=corrupt), self.assertRaises(ValueError):
                m.parse_lsda(make(corrupt), 0x2000, 0x200a, 0x1000)

    def test_relocation_corruption_and_duplicate(self):
        def make(entries):
            rel = b''.join(entries)
            data = rel + bytes(24) + b'\0'
            secs = [
                {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0, 'offset': 0, 'size': len(rel)},
                {'name': '.dynsym', 'type': 11, 'flags': 2, 'address': 0x100, 'offset': len(rel), 'size': 24},
                {'name': '.dynstr', 'type': 3, 'flags': 2, 'address': 0x200, 'offset': len(rel) + 24, 'size': 1},
            ]
            return m.View(data, secs)
        good = struct.pack('<QQq', 0x80, 8, 0x123)
        wrong = struct.pack('<QQq', 0x80, 8, 0x124)
        with patch.object(m, 'REQUIRED_RELOCS', {0x80: (8, 0x123)}):
            self.assertEqual(m.parse_relocations(make([good]), {0x80})[0x80]['addend'], '0x123')
            for records in ([wrong], [good, good], []):
                with self.subTest(records=records), self.assertRaises(ValueError):
                    m.parse_relocations(make(records), {0x80})


if __name__ == '__main__':
    unittest.main()
