"""Static corruption controls for the selected node-94 evidence path."""
import json
import math
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import config_storage_read94 as m


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        m.authenticate(cls.data)
        cls.secs = m.sections(cls.data)
        cls.generated = m.collect(cls.data)

    def test_failed_identity_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            with patch.object(m.TARGET.__class__, 'read_bytes', return_value=b'bad'):
                with self.assertRaises(m.EvidenceError):
                    m.main(['--out', str(output)])
            self.assertFalse(output.exists())

    def test_target_digest_and_size(self):
        self.assertEqual(len(self.data), m.SIZE)
        m.authenticate(self.data)

    def test_short_artifact_rejected_before_parsing(self):
        with self.assertRaisesRegex(m.EvidenceError, 'size mismatch'):
            m.authenticate(memoryview(self.data)[:-1])

    def test_corrupt_digest_rejected(self):
        with patch.object(m, 'SHA256', '0' * 64):
            with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
                m.authenticate(self.data)

    def test_collect_authenticates_before_sections(self):
        with patch.object(m, 'sections', side_effect=AssertionError('must not parse')):
            with self.assertRaises(m.EvidenceError):
                m.collect(b'bad')

    def test_selected_body_hashes(self):
        for _, start, end, digest in m.BODIES:
            with self.subTest(start=hex(start)):
                m.validate_body(m.read_va(self.data, self.secs, start, end - start), digest)

    def test_body_byte_corruption_rejected(self):
        _, start, end, digest = m.BODIES[0]
        body = bytearray(m.read_va(self.data, self.secs, start, end - start))
        body[len(body) // 2] ^= 1
        with self.assertRaisesRegex(m.EvidenceError, 'body hash'):
            m.validate_body(body, digest)

    def test_va_zero_span_is_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.map_span(self.data, self.secs, 0x203950, 0)

    def test_va_outside_is_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.read_va(self.data, self.secs, 1 << 60, 1)

    def test_section_end_is_exclusive(self):
        fake = [{'type': 1, 'size': 4, 'address': 16, 'offset': 0}]
        self.assertEqual(m.read_va(b'abcd', fake, 19, 1), b'd')
        with self.assertRaises(m.EvidenceError):
            m.read_va(b'abcd', fake, 19, 2)

    def test_nobits_never_maps_to_file(self):
        fake = [{'type': 8, 'size': 4, 'address': 16, 'offset': 0}]
        with self.assertRaises(m.EvidenceError):
            m.read_va(b'abcd', fake, 16, 1)

    def test_ambiguous_sections_rejected(self):
        fake = [{'type': 1, 'size': 4, 'address': 16, 'offset': 0},
                {'type': 1, 'size': 4, 'address': 16, 'offset': 0}]
        with self.assertRaises(m.EvidenceError):
            m.read_va(b'abcd', fake, 16, 1)

    def test_file_boundary_rejected(self):
        fake = [{'type': 1, 'size': 5, 'address': 16, 'offset': 0}]
        with self.assertRaises(m.EvidenceError):
            m.read_va(b'abcd', fake, 20, 1)

    def test_raw_window_corruption_rejected(self):
        fake = [{'type': 1, 'size': 3, 'address': 16, 'offset': 0}]
        with self.assertRaisesRegex(m.EvidenceError, 'byte mismatch'):
            m.exact_bytes(b'abc', fake, 16, b'abd')

    def test_relative_call_negative_displacement(self):
        self.assertEqual(m.decode_relative(bytes.fromhex('e8fbffffff'), 0x100), ('call', 0x100))

    def test_relative_short_conditional_backward(self):
        self.assertEqual(m.decode_relative(bytes.fromhex('75fc'), 0x100), ('jcc-5', 0xfe))

    def test_relative_long_conditional_forward(self):
        self.assertEqual(m.decode_relative(bytes.fromhex('0f8401000000'), 0x100), ('jcc-4', 0x107))

    def test_relative_truncation_rejected(self):
        for raw in (b'', b'\xe8', b'\xe8\x00\x00\x00', b'\x0f\x84\x00'):
            with self.subTest(raw=raw), self.assertRaises(m.EvidenceError):
                m.decode_relative(raw, 0x100)

    def test_relative_non_branch_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.decode_relative(bytes.fromhex('9090909090'), 0x100)

    def test_config_slow_paths_rejoin_result(self):
        for site, target in ((0x27b6487, 0x27b6402), (0x27b648d, 0x27b6416),
                             (0x27b64ca, 0x27b6416), (0x27b62f3, 0x27b631b)):
            with self.subTest(site=hex(site)):
                self.assertEqual(m.transfer(self.data, self.secs, site, target)[1], target)

    def test_real_call_and_changed_target(self):
        kind, target, _ = m.transfer(self.data, self.secs, 0x1f70768, 0x27b6080)
        self.assertEqual((kind, target), ('call', 0x27b6080))
        with self.assertRaisesRegex(m.EvidenceError, 'changed transfer target'):
            m.transfer(self.data, self.secs, 0x1f70768, 0x27b6081)

    def test_corrupt_relative_operand_is_detected(self):
        fake = [{'type': 1, 'size': 5, 'address': 0x100, 'offset': 0}]
        m.transfer(bytes.fromhex('e800000000'), fake, 0x100, 0x105)
        with self.assertRaises(m.EvidenceError):
            m.transfer(bytes.fromhex('e801000000'), fake, 0x100, 0x105)

    def test_rip_wrong_opcode_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.rip_reference(self.data, self.secs, 0x27b63eb, '488d1d', 0x576e928)

    def test_rip_wrong_target_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.rip_reference(self.data, self.secs, 0x27b63eb, '488b1d', 0x576e929)

    def test_rip_truncated_operand_rejected(self):
        fake = [{'type': 1, 'size': 6, 'address': 0x100, 'offset': 0}]
        with self.assertRaises(m.EvidenceError):
            m.rip_reference(bytes.fromhex('488b1d000000'), fake, 0x100, '488b1d', 0x107)

    @staticmethod
    def rela_section(size):
        return {'type': 4, 'offset': 0, 'size': size}

    def test_rela_relative_addend(self):
        raw = struct.pack('<QQq', 0x200, 8, 0x300)
        rows = m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})
        self.assertEqual(rows[0x200]['addend_va'], '0x300')

    def test_rela_bad_type_rejected(self):
        raw = struct.pack('<QQq', 0x200, 1, 0x300)
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})

    def test_rela_symbol_index_rejected(self):
        raw = struct.pack('<QQq', 0x200, (1 << 32) | 8, 0x300)
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})

    def test_rela_changed_addend_rejected(self):
        raw = struct.pack('<QQq', 0x200, 8, 0x301)
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})

    def test_rela_duplicate_rejected(self):
        raw = struct.pack('<QQq', 0x200, 8, 0x300) * 2
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})

    def test_rela_missing_rejected(self):
        raw = struct.pack('<QQq', 0x201, 8, 0x300)
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(raw, self.rela_section(len(raw)), {0x200: 0x300})

    def test_rela_nobits_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(bytes(24), {'type': 8, 'offset': 0, 'size': 24}, {})

    def test_rela_truncation_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.selected_relocations(bytes(23), self.rela_section(23), {})

    def test_fields_aliases_and_exact_length(self):
        fields = {'address': b'address', 'index': b'index', 'blockId': b'blockId', 'block_id': b'block_id'}
        self.assertEqual(m.select_fields(b'address', fields), 'address')
        self.assertEqual(m.select_fields(b'index', fields), 'index')
        self.assertEqual(m.select_fields(b'blockId', fields), 'block')
        self.assertEqual(m.select_fields(b'block_id', fields), 'block')
        for bad in (b'Address', b'addressx', b'blockid', b'blockId\x00', b' index', b''):
            with self.subTest(bad=bad):
                self.assertEqual(m.select_fields(bad, fields), 'unknown')

    def test_all_single_byte_field_mutations_miss(self):
        fields = {'address': b'address', 'index': b'index', 'blockId': b'blockId', 'block_id': b'block_id'}
        for word in fields.values():
            for i in range(len(word)):
                changed = word[:i] + bytes([word[i] ^ 1]) + word[i + 1:]
                self.assertEqual(m.select_fields(changed, fields), 'unknown')

    def test_vtable_layout_and_initial_file_word(self):
        self.assertEqual(struct.unpack('<QQ', m.read_va(self.data, self.secs, 0x56918d8, 16)), (8, 8))
        self.assertEqual(struct.unpack('<I', m.read_va(self.data, self.secs, 0x577b2d8, 4))[0], 3)

    def test_secondary_once_boundary_and_relocation(self):
        for site, prefix, target in ((0x27b640c, '8b05', 0x577ab98),
                                     (0x27b648f, '488d05', 0x577ab80),
                                     (0x27b64a0, '488d3d', 0x577ab98),
                                     (0x27b64bf, 'ff15', 0x576e8b8)):
            with self.subTest(site=hex(site)):
                self.assertEqual(m.rip_reference(self.data, self.secs, site, prefix, target)[1], target)
                with self.assertRaises(m.EvidenceError):
                    m.rip_reference(self.data, self.secs, site, prefix, target + 1)
        rows = json.loads(self.generated['relocations.json'])
        addends = {row['slot_va']: row['addend_va'] for row in rows}
        self.assertEqual(addends['0x577ab80'], '0x143ef30')
        self.assertEqual(struct.unpack('<I', m.read_va(self.data, self.secs, 0x577ab98, 4))[0], 3)

    def test_gate_all_256_name_bytes(self):
        admitted = [i for i in range(256) if m.name_gate(i, 4.0, 31, 0x803c6000, 3.0)]
        self.assertEqual(admitted, [13, 14, 18, 19, 20, 21, 31])

    def test_gate_default_and_bound(self):
        self.assertTrue(m.name_gate(31, 4.0, 31, 0x803c6000, 3.0))
        self.assertFalse(m.name_gate(32, 4.0, 31, 0x803c6000, 3.0))
        self.assertFalse(m.name_gate(76, 4.0, 31, 0x803c6000, 3.0))

    def test_gate_ordered_floating_boundary(self):
        for value in (-math.inf, 2.0, 3.0, math.nan):
            self.assertFalse(m.name_gate(13, value, 31, 0x803c6000, 3.0))
        self.assertTrue(m.name_gate(13, math.nextafter(3.0, math.inf), 31, 0x803c6000, 3.0))
        self.assertTrue(m.name_gate(13, math.inf, 31, 0x803c6000, 3.0))

    def test_gate_requires_byte(self):
        for value in (-1, 256, True, 32.0):
            with self.subTest(value=value), self.assertRaises(m.EvidenceError):
                m.name_gate(value, 4.0, 31, 0x803c6000, 3.0)

    def test_null_prefix_success_and_trailing_byte(self):
        self.assertEqual(m.nullable_model(b'null', 0x100002600, b'null'), ('tag-2', 4))
        self.assertEqual(m.nullable_model(b'nullx', 0x100002600, b'null'), ('tag-2', 4))
        self.assertEqual(m.nullable_model(b'\t\r\n null', 0x100002600, b'null'), ('tag-2', 8))

    def test_null_prefix_each_whitespace_and_control(self):
        for byte in (9, 10, 13, 32):
            with self.subTest(byte=byte):
                self.assertEqual(m.nullable_model(bytes([byte]) + b'null', 0x100002600, b'null'), ('tag-2', 5))
        for byte in (0, 11, 12, 31):
            with self.subTest(byte=byte):
                self.assertEqual(m.nullable_model(bytes([byte]) + b'null', 0x100002600, b'null'), ('delegate', 0))

    def test_null_prefix_truncation_cursor(self):
        for value in (b'n', b'nu', b'nul'):
            with self.subTest(value=value):
                self.assertEqual(m.nullable_model(value, 0x100002600, b'null'), ('truncated', len(value)))

    def test_null_prefix_bad_byte_cursor(self):
        for value in (b'nx', b'nux', b'nulx'):
            with self.subTest(value=value):
                self.assertEqual(m.nullable_model(value, 0x100002600, b'null'), ('bad-literal', len(value)))

    def test_null_prefix_non_n_is_delegated(self):
        self.assertEqual(m.nullable_model(b' true', 0x100002600, b'null'), ('delegate', 1))
        self.assertEqual(m.nullable_model(b'', 0x100002600, b'null'), ('delegate', 0))
        self.assertEqual(m.nullable_model(b'\x0bnull', 0x100002600, b'null'), ('delegate', 0))

    def test_null_comparison_corruption_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.nullable_model(b'null', 0x100002600, b'nulx')

    def test_hex_scalar_all_byte_values(self):
        alphabet = b'0123456789abcdef'
        for value in range(256):
            data = bytes([value]) * 32
            self.assertEqual(m.scalar_hex(data, alphabet), ('0x' + data.hex()).encode())

    def test_hex_length_and_alphabet_controls(self):
        with self.assertRaises(m.EvidenceError):
            m.scalar_hex(bytes(31), b'0123456789abcdef')
        with self.assertRaises(m.EvidenceError):
            m.scalar_hex(bytes(32), b'0000000000000000')

    def test_shuffle_on_distinct_bytes(self):
        raw = bytes(range(32))
        self.assertEqual(m.shuffle_storage_word(raw), raw[::-1])

    def test_shuffle_each_byte_position(self):
        for i in range(32):
            raw = bytes(1 if j == i else 0 for j in range(32))
            self.assertEqual(m.shuffle_storage_word(raw), raw[::-1])

    def test_shuffle_short_value_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.shuffle_storage_word(bytes(31))

    def test_error_table_codes_and_boundary(self):
        rows, adjacent = m.table_error_rows(self.data, self.secs, 0x3f5d9c, 0x29798e8)
        self.assertEqual([r[-1] for r in rows], ['-32700', '-32007', '-32600', '-32601', '-32009', '-32602', '-32603', 'inherited'])
        self.assertEqual(adjacent['target_va'], '0x297b864')

    def test_error_table_out_of_range_target_rejected(self):
        original = m.read_va
        def corrupted(data, secs, va, size):
            if va == 0x3f5d9c:
                return bytes(4)
            return original(data, secs, va, size)
        with patch.object(m, 'read_va', side_effect=corrupted):
            with self.assertRaises(m.EvidenceError):
                m.table_error_rows(self.data, self.secs, 0x3f5d9c, 0x29798e8)

    def test_error_table_corrupt_arm_rejected(self):
        original = m.read_va
        def corrupted(data, secs, va, size):
            raw = original(data, secs, va, size)
            if va == 0x2979758:
                return b'\x90' + raw[1:]
            return raw
        with patch.object(m, 'read_va', side_effect=corrupted):
            with self.assertRaises(m.EvidenceError):
                m.table_error_rows(self.data, self.secs, 0x3f5d9c, 0x29798e8)

    def test_selected_unwind_table_covers_both_lookups(self):
        lines = self.generated['unwind-callsites.tsv'].decode().splitlines()
        self.assertEqual(len(lines) - 1, 68)
        rows = [line.split('\t') for line in lines[1:]]
        row = next(row for row in rows if row[0] == 'storage_query' and row[7] == '0x27b6196')
        self.assertEqual(row[8:], ['0x27b6256', '0x27b6500', '0'])
        for call in (0x27b61e9, 0x27b6251):
            self.assertLessEqual(int(row[7], 16), call)
            self.assertLess(call, int(row[8], 16))
        m.exact_bytes(self.data, self.secs, 0x27b6500, '48c7c1f0ffffff488b542410f0480fc10a')
        m.transfer(self.data, self.secs, 0x27b651c, 0x27b6526)
        m.transfer(self.data, self.secs, 0x27b6521, 0x5660110)

    def test_unwind_table_rejects_corrupt_headers_ranges_and_overlaps(self):
        fde = {'lsda': 0x20, 'start': 0x1000, 'end': 0x1020}
        def parse(hex_bytes):
            raw = bytes.fromhex(hex_bytes)
            sec = {'name': '.gcc_except_table', 'type': 1, 'size': len(raw),
                   'address': 0x20, 'offset': 0}
            return m.lsda_callsites(raw, [sec], fde, 0x20 + len(raw))
        row, = parse('ffff010400040800')
        self.assertEqual(row[6:], ('0x1000', '0x1004', '0x1008', 0))
        for raw in ('ff7f010400040800', 'ffff010500040800',
                    'ffff010400400800', 'ffff010400044000',
                    'ffff01080004080003040800'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw)

    def test_generated_evidence_matches_retained_files(self):
        directory = m.ROOT / 'research/work-items/RE-015-config-storage-read-94'
        self.assertEqual(len(self.generated), 10)
        for filename, value in self.generated.items():
            with self.subTest(filename=filename):
                self.assertEqual((directory / filename).read_bytes(), value)


if __name__ == '__main__':
    unittest.main()
