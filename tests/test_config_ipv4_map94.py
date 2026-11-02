import csv
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import config_ipv4_map94 as subject


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.ARTIFACT.read_bytes()
        subject.verify_identity(cls.data)
        cls.view = subject.View(cls.data)
        cls.evidence = subject.inspect(cls.data, authenticate=False)
        cls.summary = json.loads(cls.evidence['summary.json'])

    def rows(self, name):
        return list(csv.DictReader(io.StringIO(self.evidence[name].decode()), delimiter='\t'))

    def edited(self, va, replacement):
        out = bytearray(self.data)
        pos = self.view.offset(va, len(replacement))
        out[pos:pos + len(replacement)] = replacement
        return out

    def test_artifact_identity(self):
        self.assertEqual(self.summary['artifact_sha256'], subject.DIGEST)
        self.assertEqual(self.summary['artifact_size'], subject.SIZE)
        self.assertEqual(len(self.data), subject.SIZE)

    def test_corrupt_digest_rejected(self):
        tampered = bytearray(self.data)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'identity'):
            subject.verify_identity(tampered)

    def test_truncated_artifact_rejected(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            subject.verify_identity(self.data[:64])

    def test_corrupt_selected_body_rejected(self):
        tampered = self.edited(0x14cb268, b'\x90')
        with self.assertRaisesRegex(ValueError, 'FDE bytes'):
            subject.inspect(tampered, authenticate=False)

    def test_corrupt_prior_handoff_rejected(self):
        tampered = self.edited(0x13ad213, b'\x90')
        with self.assertRaisesRegex(ValueError, 'context byte'):
            subject.inspect(tampered, authenticate=False)

    def test_corrupt_field_bytes_rejected(self):
        tampered = self.edited(0x21bc13, b'X')
        with self.assertRaisesRegex(ValueError, 'field name'):
            subject.inspect(tampered, authenticate=False)

    def test_corrupt_field_table_rejected(self):
        tampered = self.edited(0x20fae4, b'\x00\x00\x00\x00')
        with self.assertRaisesRegex(ValueError, 'field arm'):
            subject.inspect(tampered, authenticate=False)

    def test_wrong_but_valid_table_destination_rejected(self):
        base, index = 0x210cc4, 0xc4
        # The replacement names another real instruction in the same FDE.
        valid_other = 0x13b6cdb
        tampered = self.edited(base + index * 4, struct.pack('<i', valid_other - base))
        with self.assertRaisesRegex(ValueError, 'dispatch table bytes'):
            subject.inspect(tampered, authenticate=False)

    def test_map_header_wrong_valid_destination_rejected(self):
        base, index = 0x215104, 0x1e
        replacement = 0x13bf6c0  # Real selected instruction, but the wrong count width.
        tampered = self.edited(base + index * 4, struct.pack('<i', replacement - base))
        with self.assertRaisesRegex(ValueError, 'dispatch table bytes'):
            subject.inspect(tampered, authenticate=False)

    def test_corrupt_exception_header_rejected(self):
        tampered = self.edited(0x91ece8, b'\xfe')
        with self.assertRaisesRegex(ValueError, 'LSDA header'):
            subject.inspect(tampered, authenticate=False)

    def test_relocation_type_corruption_rejected(self):
        rows = self.rows('relocations.tsv')
        row = next(row for row in rows if row['slot_va'] == '0x576e488')
        pos = int(row['record_file_offset'], 16)
        tampered = bytearray(self.data)
        tampered[pos + 8:pos + 16] = struct.pack('<Q', 8)
        with self.assertRaisesRegex(ValueError, 'key comparison relocation'):
            subject.inspect(tampered, authenticate=False)

    def test_bad_fde_record_rejected(self):
        _, funcs = subject.load_functions(self.view)
        fde = next(f for role, f, _, _ in funcs if role == 'binary_ip_map')
        offset = self.view.offset(fde['fde'], 4)
        tampered = bytearray(self.data)
        tampered[offset:offset + 4] = b'\xff\xff\xff\xff'
        with self.assertRaises(ValueError):
            subject.inspect(tampered, authenticate=False)

    def test_unmapped_range_rejected(self):
        for addr, size in ((-1, 1), (0, 0), (1 << 64, 1), (0x13bf580, -1)):
            with self.subTest(addr=addr, size=size), self.assertRaises(ValueError):
                self.view.offset(addr, size)

    def test_nobits_not_file_backed(self):
        sections = [{'name': 'bss', 'type': 8, 'flags': 2, 'address': 100, 'offset': 0, 'size': 16}]
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            subject.View(b'\0' * 16, secs=sections).offset(100, 1)

    def test_ambiguous_file_mapping_rejected(self):
        sec = {'name': 'a', 'type': 1, 'flags': 2, 'address': 100, 'offset': 0, 'size': 16}
        with self.assertRaisesRegex(ValueError, 'unique'):
            subject.View(b'\0' * 16, secs=[sec, dict(sec)]).offset(100, 1)

    def test_truncated_file_backed_mapping_rejected(self):
        sec = {'name': 'a', 'type': 1, 'flags': 2, 'address': 100, 'offset': 12, 'size': 16}
        with self.assertRaisesRegex(ValueError, 'truncated'):
            subject.View(b'\0' * 16, secs=[sec]).offset(105, 2)

    def test_decoder_rejects_truncated_branch(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            subject.decode_one(b'\xe9\x01\x02', 0, 0x100)

    def test_decoder_rejects_branch_into_instruction(self):
        with self.assertRaisesRegex(ValueError, 'branch into'):
            subject.decode_body(b'\x75\x01\x48\x89\xc0\xc3', 0x100)

    def test_decoder_rejects_unknown_opcode(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            subject.decode_one(b'\xc5\x00', 0, 0x100)

    def test_selected_boundaries_and_counts(self):
        self.assertEqual(self.summary['selected_fdes'], 8)
        self.assertEqual(self.summary['selected_bytes'], 12567)
        self.assertEqual(self.summary['linear_instructions'], 2990)
        functions = self.rows('functions.tsv')
        self.assertEqual({int(row['start_va'], 16) for row in functions}, {f[1] for f in subject.FUNCTIONS})
        self.assertTrue(all(int(row['end_va_exclusive'], 16) > int(row['start_va'], 16) for row in functions))

    def test_previous_field_handoffs(self):
        anchors = {row['label']: row for row in self.rows('prior-handoffs.tsv')}
        self.assertEqual(anchors['field_name']['bytes'], b'internal_ips'.hex())
        self.assertEqual(anchors['value_diagnostic']['bytes'], b'IPv4 address'.hex())
        self.assertEqual(anchors['previous_binary_field_table']['target_va'], '0x13ad1e4')
        self.assertEqual(anchors['previous_binary_visitor_call']['target_va'], '0x13bf580')
        self.assertEqual(anchors['json_value_handoff']['target_va'], '0x14bdbe0')
        self.assertEqual(anchors['json_pair_insert_handoff']['target_va'], '0x14cb140')

    def test_c4_state_dispatch(self):
        rows = self.rows('dispatch-tables.tsv')
        c4 = next(row for row in rows if row['table'] == 'other_state' and row['index'] == '196')
        c5 = next(row for row in rows if row['table'] == 'other_state' and row['index'] == '197')
        self.assertEqual(c4['target_va'], '0x13b6d09')
        self.assertEqual(c5['target_va'], '0x13b6cdb')
        self.assertEqual(len(rows), 825)

    def test_map_header_dispatch_boundaries(self):
        rows = self.rows('dispatch-tables.tsv')
        entries = {int(r['index']): r['target_va'] for r in rows if r['table'] == 'map_marker_c0_df'}
        self.assertEqual(entries[0x1e], '0x13bf718')
        self.assertEqual(entries[0x1f], '0x13bf6c0')

    def test_all_selected_table_targets_are_instruction_starts(self):
        starts = {row['va'] for row in self.rows('instructions.tsv')}
        self.assertTrue(all(row['target_va'] in starts for row in self.rows('dispatch-tables.tsv')))

    def test_critical_direct_targets(self):
        rows = {row['label']: row for row in self.rows('contracts.tsv')}
        expected = {'text_value_reader_call': '0x13b7e20', 'other_value_reader_call': '0x13b6c50',
                    'insert_decoded_pair': '0x14cb140', 'nonempty_insert_helper': '0x1398430',
                    'drop_on_key_error': '0x14da680', 'drop_iterator_call': '0x14ce920'}
        for label, target in expected.items():
            with self.subTest(label=label):
                self.assertEqual(rows[label]['target_va'], target)

    def test_new_ipv4_diagnostic_pool_reference(self):
        rows = {row['label']: row for row in self.rows('contracts.tsv')}
        self.assertEqual(rows['value_diagnostic_length']['bytes'], 'b90c000000')
        self.assertEqual(rows['value_diagnostic_pool_reference']['target_va'], '0x21b07f')
        self.assertEqual(rows['value_diagnostic_pool_reference']['file_offset'], '0x13bea0a')

    def test_cfg_propositions_include_failure_boundaries(self):
        rows = {row['claim']: row['reachable_assuming_calls_return'] for row in self.rows('cfg.tsv')}
        self.assertEqual(len(rows), 26)
        self.assertEqual(rows['equal_key_bypasses_increment'], 'false')
        self.assertEqual(rows['value_failure_can_drop_map'], 'true')
        self.assertEqual(rows['raw_payload_requires_fourth_byte'], 'false')
        self.assertEqual(rows['map_depth_decrement_required'], 'false')
        self.assertEqual(rows['map_depth_overflow_check_required'], 'false')
        self.assertEqual(rows['parent_can_accept_split'], 'true')
        self.assertEqual(rows['full_parent_can_allocate'], 'true')
        self.assertEqual(rows['missing_parent_can_allocate_root'], 'true')
        self.assertEqual(rows['root_publish_requires_alloc_check'], 'false')

    def test_parent_and_root_split_byte_boundaries(self):
        rows = {row['label']: row for row in self.rows('contracts.tsv')}
        self.assertEqual(rows['split_no_parent_branch']['target_va'], '0x1398bf6')
        self.assertEqual(rows['parent_nonfull_branch']['target_va'], '0x1398cf2')
        self.assertEqual(rows['parent_loop_branch']['target_va'], '0x13987b0')
        self.assertEqual(rows['full_parent_node_allocation_size']['bytes'], 'bfa0010000')
        self.assertEqual(rows['new_root_allocation_size']['bytes'], 'bfa0010000')
        self.assertEqual(rows['root_height_overflow_branch']['target_va'], '0x1398fe9')

    def test_new_root_publish_corruption_rejected(self):
        tampered = self.edited(0x1398c7e, b'\x90')
        with self.assertRaisesRegex(ValueError, 'FDE bytes'):
            subject.inspect(tampered, authenticate=False)

    def test_exception_intervals_cover_reader_calls(self):
        rows = self.rows('lsda-sites.tsv')
        matched = [row for row in rows if '0x13bfa17' in row['calls_in_range'].split(',')]
        self.assertEqual(len(matched), 1)
        self.assertIn('0x13bfa26', matched[0]['calls_in_range'].split(','))
        self.assertEqual(matched[0]['landing_va'], '0x13bff64')

    def test_exception_calls_exclude_indirect_jumps(self):
        transfers = {row['site_va']: row['kind'] for row in self.rows('transfers.tsv')}
        for row in self.rows('lsda-sites.tsv'):
            for site in filter(None, row['calls_in_range'].split(',')):
                with self.subTest(site=site):
                    self.assertIn(transfers[site], ('call', 'indirect_call'))

    def test_indirect_jumps_do_not_have_fallthrough(self):
        rows = self.rows('transfers.tsv')
        self.assertTrue(any(row['kind'] == 'indirect_jump' for row in rows))
        for row in rows:
            with self.subTest(site=row['site_va']):
                self.assertEqual(bool(row['fallthrough_va']), row['kind'] != 'indirect_jump')

    def test_key_order_matches_independent_byte_oracle(self):
        for left in range(256):
            for right in range(256):
                self.assertEqual(subject.compare_keys(bytes([left]), bytes([right])),
                                 (left > right) - (left < right))
        for left, right in ((b'a', b'aa'), (b'a\0', b'a'), (b'abc', b'abd'), (b'', b'')):
            self.assertEqual(subject.compare_keys(left, right), (left > right) - (left < right))

    def test_key_order_rejects_nonbytes(self):
        with self.assertRaises(ValueError):
            subject.compare_keys('a', b'a')

    def test_text_gate_all_length_and_status_boundaries(self):
        for length in range(256):
            for flag in (0, 1):
                for remaining in (0, 1, 2):
                    expected = length < 16 and bool(flag) and remaining == 0
                    self.assertEqual(subject.value_gate(length, flag, remaining, 15), expected)

    def test_text_gate_rejects_invalid_status(self):
        for args in ((-1, 1, 0, 15), (4, 2, 0, 15), (4, 1, -1, 15)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.value_gate(*args)

    def test_c4_payload_boundaries_and_trailing_bytes(self):
        data = bytes(range(8))
        for n in range(0, 10):
            result, consumed, remaining, value = subject.c4_value_model(data, n)
            expected = 'short_payload' if n > 8 else ('short_four_byte_value' if n < 4 else 'success')
            self.assertEqual(result, expected)
            self.assertEqual(consumed, 0 if n > 8 else n)
            self.assertEqual(remaining, 8 - consumed)
            self.assertEqual(value, data[:4].hex() if n >= 4 and n <= 8 else '')

    def test_c4_in_bounds_controls_across_all_length_bytes(self):
        for n in range(256):
            data = bytes((x & 255 for x in range(n)))
            outcome, used, remaining, value = subject.c4_value_model(data, n)
            self.assertEqual(outcome, 'success' if n >= 4 else 'short_four_byte_value')
            self.assertEqual((used, remaining), (n, 0))
            self.assertEqual(value, data[:4].hex() if n >= 4 else '')

    def test_fresh_map_header_all_marker_bytes(self):
        self.assertEqual(subject.map_header_model(b''), ('short_marker', 0, None))
        for marker in range(256):
            outcome, used, count = subject.map_header_model(bytes([marker]))
            expected = 'map_count' if 0x80 <= marker < 0x90 else ('short_count' if marker in (0xde, 0xdf) else 'other_route')
            self.assertEqual((outcome, used, count), (expected, 1, marker & 15 if expected == 'map_count' else None))

    def test_map_header_big_endian_count_and_truncation(self):
        for marker, width in ((0xde, 2), (0xdf, 4)):
            for n in range(width):
                self.assertEqual(subject.map_header_model(bytes([marker]) + bytes(n)), ('short_count', 1 + n, None))
            for count in (0, 1, (1 << (width * 8)) - 1):
                payload = bytes([marker]) + count.to_bytes(width, 'big') + b'\xaa'
                self.assertEqual(subject.map_header_model(payload), ('map_count', width + 1, count))
        with self.assertRaises(ValueError):
            subject.map_header_model('not bytes')

    def test_map_depth_unsigned_boundaries(self):
        cases = (('enter', 0, ('zero_depth_boundary', 0)),
                 ('enter', 1, ('return_tag_8', 0)),
                 ('enter', 2, ('continue', 1)),
                 ('enter', 65535, ('continue', 65534)),
                 ('restore', 65534, ('continue', 65535)),
                 ('restore', 65535, ('overflow_boundary', 65535)))
        for phase, value, expected in cases:
            with self.subTest(phase=phase, value=value):
                self.assertEqual(subject.map_depth_model(phase, value), expected)
        for phase, value in (('enter', -1), ('restore', 65536), ('other', 1)):
            with self.subTest(phase=phase, value=value), self.assertRaises(ValueError):
                subject.map_depth_model(phase, value)

    def test_c4_rejects_invalid_model_inputs(self):
        for payload, declared in ((b'', -1), (b'', 256), ('bad', 1)):
            with self.subTest(declared=declared), self.assertRaises(ValueError):
                subject.c4_value_model(payload, declared)

    def test_split_all_positions(self):
        expected = [(4, 0, i) for i in range(5)] + [(5, 0, 5), (5, 1, 0)] + [(6, 1, i) for i in range(5)]
        actual = [subject.split_model(i, 11, 5, 6, 4, 5, 6) for i in range(12)]
        self.assertEqual(actual, expected)
        for invalid in (-1, 12):
            with self.assertRaises(ValueError):
                subject.split_model(invalid, 11, 5, 6, 4, 5, 6)

    def test_generated_outputs_match_second_inspection(self):
        self.assertEqual(subject.inspect(self.data), self.evidence)

    def test_main_writes_only_evidence_files(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(subject.main(['--out', directory]), 0)
            output = Path(directory)
            self.assertEqual({p.name for p in output.iterdir()}, set(self.evidence))
            self.assertEqual((output / 'summary.json').read_bytes(), self.evidence['summary.json'])


if __name__ == '__main__':
    unittest.main()
