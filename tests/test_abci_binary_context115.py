import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

from tools import abci_binary_context115 as subject


class BinaryContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.TARGET.read_bytes()
        subject.authenticate(cls.image)
        cls.secs = subject.sections(cls.image)

    @classmethod
    def patched(cls, va, replacement):
        _, off = subject.read_va(cls.image, cls.secs, va, len(replacement))
        image = bytearray(cls.image)
        image[off:off + len(replacement)] = replacement
        return image

    def test_real_digest_and_wrong_digest(self):
        self.assertEqual(subject.authenticate(self.image), subject.DIGEST)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(b'not the target')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.build(b'not the target')

    def test_digest_failure_creates_no_output(self):
        with tempfile.TemporaryDirectory() as parent:
            target = Path(parent) / 'bad'
            target.write_bytes(b'bad')
            out = Path(parent) / 'uncreated'
            with mock.patch.object(subject, 'TARGET', target), \
                    mock.patch.object(sys, 'argv', ['extractor', '--out', str(out)]):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.main()
            self.assertFalse(out.exists())

    def test_name_aliases_and_all_selected_fields(self):
        names = ('initial_height', 'hardfork_height', 'hardfork', 'height',
                 'tx_index', 'round', 'consensus_round', 'time', 'prev_time',
                 'next_oid', 'next_lid', 'next_twap_id', 'system_nonce',
                 'use_system_nonce', 'mac')
        expected = (0, 0, 1, 2, 3, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        for name, result in zip(names, expected):
            with self.subTest(name=name):
                key = name.encode('ascii')
                self.assertEqual(subject.classify_context(self.image, self.secs, key), result)
                changed = bytes([key[0] ^ 1]) + key[1:]
                self.assertNotEqual(subject.classify_context(self.image, self.secs, changed), result)

    def test_unknown_empty_and_truncated_names(self):
        for key in (b'', b'heigh', b'heightx', b'HEIGHT', b'hardfork_heigh', b'\x00' * 6):
            with self.subTest(key=key):
                self.assertEqual(subject.classify_context(self.image, self.secs, key), 13)
        self.assertEqual(subject.classify_exchange(self.image, self.secs, b'locus'), 0)
        for key in (b'locu', b'locusx', b'Locus', b'locut', b''):
            self.assertNotEqual(subject.classify_exchange(self.image, self.secs, key), 0)

    def test_selected_locus_key_arm(self):
        self.assertEqual(subject.classify_locus_ctx(self.image, self.secs, b'ctx'), 0)
        self.assertEqual(subject.classify_locus_ctx(self.image, self.secs, b'ctr'), 10)
        self.assertEqual(subject.classify_locus_ctx(self.image, self.secs, b'ctz'), 16)
        self.assertIsNone(subject.classify_locus_ctx(self.image, self.secs, b'Ctx'))
        self.assertIsNone(subject.classify_locus_ctx(self.image, self.secs, b'ctxx'))
        for value in range(256):
            if value != ord('x'):
                self.assertNotEqual(subject.classify_locus_ctx(self.image, self.secs,
                                                               b'ct' + bytes([value])), 0)

    def test_real_dispatch_targets(self):
        rows, table = subject.table_rows(self.image, self.secs)
        self.assertEqual(len(rows), 209)
        self.assertEqual(table[('exchange_field_index', 0)], 0x2fd78c1)
        self.assertEqual(table[('locus_field_index', 0)], 0x332c7e9)
        self.assertEqual(table[('context_field_index', 0)], 0x30d219a)
        self.assertEqual(table[('context_field_index', 2)], 0x30d23a6)
        self.assertEqual(table[('context_field_index', 13)], 0x30d20b1)

    def test_thirteen_field_guards_and_boundary_controls(self):
        _, table = subject.table_rows(self.image, self.secs)
        rows = subject.field_rows(self.image, self.secs, table)
        self.assertEqual(len(rows), 13)
        self.assertEqual(rows[0][1], 'initial_height|hardfork_height')
        self.assertEqual(rows[2][2], '0x30d23a6')
        self.assertEqual(rows[2][7], '0x30d3aa4')
        self.assertEqual(rows[2][11], '0x64e2580')
        self.assertEqual(rows[12][11], '0x64dfeb0')
        changed = self.patched(0x30d253a, b'\x90')
        with self.assertRaisesRegex(ValueError, 'instruction bytes differ'):
            subject.field_rows(changed, self.secs, table)
        changed = self.patched(0x30d24a7 + 2, b'\x00\x00\x00\x00')
        with self.assertRaisesRegex(ValueError, 'duplicate branch differs'):
            subject.field_rows(changed, self.secs, table)
        changed = self.patched(0x30d24a7 + 1, b'\x85')
        with self.assertRaisesRegex(ValueError, 'duplicate branch differs'):
            subject.field_rows(changed, self.secs, table)
        changed = self.patched(0x30d250b, b'\x90')
        with self.assertRaisesRegex(ValueError, 'transfer opcode differs'):
            subject.field_rows(changed, self.secs, table)

    def test_historical_digest_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.check_historical(b'not the historical target', self.image)

    def test_missing_field_routes_and_corruption_controls(self):
        rows = subject.missing_rows(self.image, self.secs)
        self.assertEqual([row[0] for row in rows],
                         ['hardfork_height', 'height', 'time', 'prev_time',
                          'next_oid', 'next_lid'])
        self.assertEqual(rows[1][7], 'present')
        self.assertEqual(rows[5][19], '0x30d3792')
        changed = self.patched(0x30d3748, b'\x74')
        self.assertEqual(subject.transfer(changed, self.secs, 0x30d3748, 'jcc8')[0], 0x30d3792)
        with self.assertRaisesRegex(ValueError, 'missing-field route differs'):
            subject.missing_rows(changed, self.secs)
        changed = self.patched(0x30d3749, b'\x00')
        with self.assertRaisesRegex(ValueError, 'missing-field route differs'):
            subject.missing_rows(changed, self.secs)
        changed = self.patched(0x459e8c, b'X')
        with self.assertRaisesRegex(ValueError, 'missing-field route differs'):
            subject.missing_rows(changed, self.secs)
        changed = self.patched(0x30d34b9, b'\x90')
        with self.assertRaisesRegex(ValueError, 'instruction bytes differ'):
            subject.missing_rows(changed, self.secs)

    def test_sequence_count_checks_and_corruption_controls(self):
        rows = subject.sequence_rows(self.image, self.secs)
        self.assertEqual([row[0] for row in rows], [0, 1, 2, 3, 4, 5])
        self.assertEqual([row[11] for row in rows], [0, 2, 2, 5, 5, 5])
        changed = self.patched(0x30d32f7, b'\x75')
        with self.assertRaisesRegex(ValueError, 'sequence count branch differs'):
            subject.sequence_rows(changed, self.secs)
        changed = self.patched(0x30d3834 + 3, b'\x04')
        with self.assertRaisesRegex(ValueError, 'instruction bytes differ'):
            subject.sequence_rows(changed, self.secs)
        changed = self.patched(0x30d39fc, b'\x06')
        with self.assertRaisesRegex(ValueError, 'formatter operands differ'):
            subject.sequence_rows(changed, self.secs)

    def test_numeric_key_clamps_and_table_boundaries(self):
        _, table = subject.table_rows(self.image, self.secs)
        rows = subject.numeric_key_rows(self.image, self.secs, table)
        self.assertEqual([row[5] for row in rows], [59, 16, 13])
        self.assertEqual(rows[2][10:], ['0x30d219a', '0x30d20b1'])
        changed = self.patched(0x348ecf8 + 10, b'\x0c')
        with self.assertRaisesRegex(ValueError, 'clamp bytes differ'):
            subject.numeric_key_rows(changed, self.secs, table)
        bad_table = dict(table)
        del bad_table[('context_field_index', 13)]
        with self.assertRaisesRegex(ValueError, 'clamp and table bounds disagree'):
            subject.numeric_key_rows(self.image, self.secs, bad_table)
        changed = self.patched(0x30d2172 + 2, b'\x00\x00\x00\x00')
        with self.assertRaisesRegex(ValueError, 'call slot differs'):
            subject.numeric_key_rows(changed, self.secs, table)

    def test_selector_rejects_corrupt_opcode(self):
        changed = self.patched(0x41fc115, b'\xff')
        with self.assertRaisesRegex(ValueError, 'unsupported selector'):
            subject.classify_context(changed, self.secs, b'height')

    def test_selector_changed_table_changes_classification(self):
        table = 0x7c7160
        bad_delta = struct.pack('<i', 0x41fc477 - table)
        changed = self.patched(table + 3 * 4, bad_delta)
        self.assertEqual(subject.classify_context(changed, self.secs, b'height'), 13)
        self.assertEqual(subject.classify_context(self.image, self.secs, b'height'), 2)

    def test_changed_window_is_rejected(self):
        changed = self.patched(0x30d23a6, b'\x90')
        with self.assertRaisesRegex(ValueError, 'instruction bytes differ'):
            subject.selected_windows(changed, self.secs)

    def test_changed_branch_is_rejected(self):
        changed = self.patched(0x30d23af + 2, b'\x00\x00\x00\x00')
        with self.assertRaisesRegex(ValueError, 'transfer target differs'):
            subject.edge_rows(changed, self.secs)
        changed = self.patched(0x30d2499 + 1, b'\x00\x00\x00\x00')
        with self.assertRaisesRegex(ValueError, 'transfer target differs'):
            subject.edge_rows(changed, self.secs)

    def test_changed_operand_is_rejected(self):
        changed = self.patched(0x30d31ba + 3, b'\x29')
        with self.assertRaisesRegex(ValueError, 'operand value differs'):
            subject.operand_rows(changed, self.secs)

    def test_changed_fde_body_is_rejected_even_with_new_input_hash(self):
        changed = self.patched(0x30d31ba, b'\x90')
        digest = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError, 'FDE body mismatch'):
            subject.build(changed, expected_digest=digest)

    def test_duplicate_and_wrong_relocations_are_rejected(self):
        rela = subject.named_section(self.secs, '.rela.dyn')
        first = rela['offset']
        original_slot = struct.unpack_from('<Q', self.image, first)[0]
        self.assertNotIn(original_slot, (0x64e2580, 0x64df508, 0x64767a8))
        duplicate = bytearray(self.image)
        struct.pack_into('<Q', duplicate, first, 0x64e2580)
        with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
            subject.selected_relocations(duplicate, self.secs)
        del duplicate
        _, found = subject.selected_relocations(self.image, self.secs)
        wrong = bytearray(self.image)
        pos = found[0x64e2580][3]
        struct.pack_into('<Q', wrong, pos + 8, 7)
        with self.assertRaisesRegex(ValueError, 'relative relocation differs'):
            subject.selected_relocations(wrong, self.secs)

    def test_copy_symbol_name_is_checked(self):
        dynstr = subject.named_section(self.secs, '.dynstr')
        start = dynstr['offset']
        pos = self.image.find(b'memcpy\x00', start, start + dynstr['size'])
        self.assertGreaterEqual(pos, start)
        changed = bytearray(self.image)
        changed[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'copy symbol name differs'):
            subject.selected_relocations(changed, self.secs)

    def test_location_line_corruption_is_rejected(self):
        changed = self.patched(0x64767a8 + 16, b'\x7c\x00\x00\x00')
        _, relocs = subject.selected_relocations(changed, self.secs)
        with self.assertRaisesRegex(ValueError, 'Location record differs'):
            subject.location_row(changed, self.secs, relocs)

    def test_file_backed_range_controls(self):
        data = b'abcdef'
        row = {'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0, 'size': 6}
        self.assertEqual(subject.read_va(data, [row], 0x100, 6)[0], data)
        for va, size in ((0x106, 1), (0x105, 2), (0x100, 0), (-1, 1), ((1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    subject.read_va(data, [row], va, size)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            subject.read_va(data, [row, dict(row)], 0x100, 1)
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            subject.read_va(data, [dict(row, type=8)], 0x100, 1)
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            subject.read_va(data, [dict(row, flags=0)], 0x100, 1)

    def test_name_sections_are_unique_and_file_backed(self):
        row = {'name': '.x', 'type': 1}
        self.assertEqual(subject.named_section([row], '.x'), row)
        with self.assertRaises(ValueError):
            subject.named_section([row, dict(row)], '.x')
        with self.assertRaises(ValueError):
            subject.named_section([dict(row, type=8)], '.x')

    def test_layout_identity_and_negative_controls(self):
        rows, values = subject.operand_rows(self.image, self.secs)
        self.assertEqual(len(rows), 62)
        record = subject.derive_flow(values)
        self.assertEqual(record['context_height_offset'], '0x28')
        self.assertEqual(record['outer_allocated_initial_offset'], '0x10')
        self.assertEqual(subject.verify_wrapper_initial(values), 6)
        self.assertEqual(subject.verify_sequence_flow(values), 6)
        for key in ('locus_height_local_d', 'exchange_height_source_a',
                    'wrapper_height_dest', 'outer_source'):
            altered = dict(values)
            altered[key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.derive_flow(altered)
        altered = dict(values)
        altered['wrapper_initial_dest'] += 1
        with self.assertRaises(ValueError):
            subject.verify_wrapper_initial(altered)
        altered = dict(values)
        altered['sequence_height_output'] += 1
        with self.assertRaises(ValueError):
            subject.verify_sequence_flow(altered)

    def test_scalar_boundaries_and_sign(self):
        examples = [(0x00, b'', ('tag9', 0, 0)),
                    (0x7f, b'', ('tag9', 127, 0)),
                    (0xcc, b'\xff', ('tag9', 255, 1)),
                    (0xcd, b'\x80\x00', ('tag9', 32768, 2)),
                    (0xce, b'\xff' * 4, ('tag9', (1 << 32) - 1, 4)),
                    (0xcf, b'\xff' * 8, ('tag9', (1 << 64) - 1, 8)),
                    (0xd0, b'\x7f', ('tag9', 127, 1)),
                    (0xd0, b'\x80', ('negative_format_boundary', -128, 1)),
                    (0xd3, b'\x80' + b'\x00' * 7, ('negative_format_boundary', -(1 << 63), 8)),
                    (0xff, b'', ('negative_format_boundary', -1, 0)),
                    (0xc0, b'', ('other_marker_boundary', None, 0))]
        for marker, payload, expected in examples:
            with self.subTest(marker=marker, payload=payload):
                self.assertEqual(subject.scalar_model(marker, payload), expected)

    def test_scalar_short_payload_at_every_width(self):
        for marker, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8),
                              (0xd0, 1), (0xd1, 2), (0xd2, 4), (0xd3, 8)):
            for n in range(width):
                with self.subTest(marker=marker, length=n):
                    self.assertEqual(subject.scalar_model(marker, bytes(n)), ('short_tag1', None, n))
            self.assertEqual(subject.scalar_model(marker, bytes(width + 1)), ('tag9', 0, width))

    def test_scalar_invalid_inputs_are_rejected(self):
        for marker, payload in ((-1, b''), (256, b''), (1, 'x'), (True, b'')):
            with self.subTest(marker=marker, payload=payload), self.assertRaises(ValueError):
                subject.scalar_model(marker, payload)

    def test_full_extraction_selected_metrics(self):
        import json
        result = subject.build(self.image)
        self.assertEqual(len(result), 17)
        summary = json.loads(result['summary.json'])
        self.assertEqual(summary['selected_fdes'], 9)
        self.assertEqual(summary['relative_table_cells'], 209)
        self.assertEqual(summary['context_field_guards'], 13)
        self.assertEqual(summary['context_missing_checks'], 6)
        self.assertEqual(summary['context_sequence_count_checks'], 6)
        self.assertEqual(summary['numeric_key_clamps'], 3)
        self.assertEqual(summary['context_single_byte_substitutions'], 36465)
        self.assertEqual(summary['exchange_single_byte_substitutions'], 1275)
        self.assertEqual(summary['synthetic_scalar_cases'], 67)
        self.assertIn(b'hardfork_height\t15\t0', result['keys.tsv'])


if __name__ == '__main__':
    unittest.main()
