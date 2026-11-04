"""Negative controls for the selected static node-115 handoff extractor."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_snapshot_handoff115 as probe


class TargetEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing target is an error, not a skipped test.
        cls.data = probe.TARGET.read_bytes()
        cls.secs = probe.sections(cls.data)
        _, cls.fdes, _ = probe.fde_extents(cls.data)
        cls.relocs = probe.read_relocations(cls.data, cls.secs)

    def test_digest_matches_and_corrupt_input_fails(self):
        probe.authenticate(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            probe.authenticate(self.data[:-1])
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            probe.check_historical(b'not a historical node')

    def test_bad_digest_cannot_create_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'results'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                probe.generate(b'corrupted input', out)
            self.assertFalse(out.exists())

    def test_all_selected_windows_and_one_byte_corruption(self):
        for label, va, expected in probe.WINDOWS:
            with self.subTest(label=label):
                actual = probe.read(self.data, self.secs, va, len(expected))
                probe.check_window(actual, expected)
                damaged = bytearray(actual)
                damaged[len(damaged) // 2] ^= 1
                with self.assertRaisesRegex(ValueError, 'window changed'):
                    probe.check_window(damaged, expected)

    def test_all_selected_transfer_targets(self):
        sizes = {'call': 5, 'slot': 6, 'lea': 7, 'movrip': 7,
                 'jcc32': 6, 'jcc8': 2, 'jmp32': 5, 'jmp8': 2}
        for label, va, kind, target in probe.TRANSFERS:
            with self.subTest(label=label):
                raw = probe.read(self.data, self.secs, va, sizes[kind])
                self.assertEqual(probe.decode_transfer(va, raw, kind), target)
                damaged = bytearray(raw)
                damaged[-1] ^= 1
                self.assertNotEqual(probe.decode_transfer(va, damaged, kind), target)

    def test_wrong_instruction_form_fails(self):
        for kind, data in [('call', bytes.fromhex('e900000000')),
                           ('jmp32', bytes.fromhex('e800000000')),
                           ('jcc32', bytes.fromhex('0f9000000000')),
                           ('slot', bytes.fromhex('ff2500000000')),
                           ('movrip', bytes.fromhex('4c8b2500000000'))]:
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    probe.decode_transfer(0x1000, data, kind)

    def test_selected_fde_ranges_and_callback_landing(self):
        choices = probe.check_fdes(self.fdes)
        self.assertEqual(len(choices), len(probe.SELECTED))
        fde = dict(choices)['snapshot_callback']
        rows = probe.decode_lsda(self.data, self.secs, fde)
        matches = [r for r in rows if r[1] <= 0x56691a9 < r[2]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][3:], (0x56693a8, 3))

    def test_parent_dispatches_have_same_recorded_landing(self):
        fde = dict(probe.check_fdes(self.fdes))['owner_snapshot_entry']
        rows = probe.decode_lsda(self.data, self.secs, fde)
        for site in (0x4fc2450, 0x4fc2577):
            matches = [r for r in rows if r[1] <= site < r[2]]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0][3], 0x4fc28f7)

    def test_all_operands_and_layout(self):
        vals = {label: probe.immediate(self.data, self.secs, va, prefix, width)
                for label, va, prefix, width in probe.OPERANDS}
        probe.validate_layout(vals)
        self.assertEqual(vals['owner_context_first'] + vals['builder_state_slot'], 0xb00)
        self.assertEqual(vals['outer_owner_adjust'] + vals['middle_mode_offset'], 0x150)
        self.assertEqual(vals['encoder_success_tag'], vals['serializer_marker'] + 4)
        self.assertEqual(3 * vals['builder_chunk_size_1'], vals['builder_chunk_allocation'])
        for label in ('owner_context_first', 'builder_chunk_2', 'builder_chunk_size_3',
                      'owner_guard_release_mask_signed_byte', 'encoder_success_tag',
                      'scheduler_done_status', 'writer_flags', 'record_height_stack',
                      'record_marker_value', 'record_copy_length', 'top_counter_reset_value',
                      'top_bucket_store_offset', 'top_message_length'):
            with self.subTest(label=label):
                corrupt = dict(vals)
                corrupt[label] ^= 1
                with self.assertRaisesRegex(ValueError, 'layout relations'):
                    probe.validate_layout(corrupt)

    def test_immediate_rejects_wrong_opcode_and_truncation(self):
        sec = [{'name': 'x', 'type': 1, 'address': 0x100, 'size': 4, 'offset': 0}]
        self.assertEqual(probe.immediate(b'\xba\x01\x00\x00', sec, 0x100, 'ba', 3), 1)
        with self.assertRaisesRegex(ValueError, 'instruction changed'):
            probe.immediate(b'\xbb\x01\x00\x00', sec, 0x100, 'ba', 3)
        with self.assertRaises(ValueError):
            probe.immediate(b'\xba\x01', sec, 0x100, 'ba', 3)

    def test_location_and_relocation_anchors(self):
        rows = probe.check_locations(self.data, self.secs, self.relocs)
        self.assertEqual([(r[6], r[7]) for r in rows], [(123, 37), (161, 83)])
        self.assertEqual(probe.unique_relocation(self.relocs, 0x64e61d0)[2], 0x38c2e00)
        symbol = probe.dynamic_copy_anchor(self.data, self.secs, self.relocs)
        self.assertEqual((symbol[0], symbol[-1]), ('anchor-only', 'memcpy'))

    def test_copy_symbol_bad_type_missing_and_duplicate(self):
        rows = list(self.relocs)
        target = next(r for r in rows if r[0] == 0x64df508)
        with self.assertRaises(ValueError):
            probe.dynamic_copy_anchor(self.data, self.secs, [r for r in rows if r != target])
        with self.assertRaises(ValueError):
            probe.dynamic_copy_anchor(self.data, self.secs, rows + [target])
        corrupt = [((a, (b & ~0xffffffff) | 8, c) if a == target[0] else (a, b, c))
                   for a, b, c in rows]
        with self.assertRaises(ValueError):
            probe.dynamic_copy_anchor(self.data, self.secs, corrupt)


class SyntheticNegativeControls(unittest.TestCase):
    def test_range_excludes_fileless_and_ambiguous_sections(self):
        real = {'name': 'x', 'type': 1, 'address': 0x1000, 'offset': 2, 'size': 4}
        bss = {'name': 'bss', 'type': 8, 'address': 0x1004, 'offset': 6, 'size': 4}
        self.assertEqual(probe.file_range([real, bss], 0x1001, 2), 3)
        for va, size in [(0x1004, 1), (0xfff, 1), (0x1003, 2), (0x1000, 0), (-1, 1)]:
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    probe.file_range([real, bss], va, size)
        with self.assertRaises(ValueError):
            probe.file_range([real, dict(real)], 0x1000, 1)
        with self.assertRaises(ValueError):
            probe.read(b'\x00', [real], 0x1000, 1)

    def test_unique_section_rejects_missing_duplicate_and_bss(self):
        sec = {'name': 'a', 'type': 1}
        self.assertEqual(probe.unique_section([sec], 'a'), sec)
        for sections in ([], [sec, dict(sec)], [{'name': 'a', 'type': 8}]):
            with self.assertRaises(ValueError):
                probe.unique_section(sections, 'a')

    def test_relative_relocations_reject_bad_controls(self):
        row = (0x100, 8, 0x200)
        self.assertEqual(probe.unique_relocation([row], 0x100), row)
        for rows in ([], [row, row], [(0x100, 7, 0x200)], [(0x100, 8, -1)]):
            with self.assertRaises(ValueError):
                probe.unique_relocation(rows, 0x100)

    def test_copy_symbol_name_and_bounds_corruption(self):
        data = bytearray(55)
        struct.pack_into('<IBBHQQ', data, 24, 0, 0x12, 0, 0, 0, 0)
        data[48:] = b'memcpy\0'
        secs = [
            {'name': '.dynsym', 'type': 11, 'offset': 0, 'size': 48},
            {'name': '.dynstr', 'type': 3, 'offset': 48, 'size': 7},
        ]
        rows = [(0x64df508, (1 << 32) | 6, 0)]
        self.assertEqual(probe.dynamic_copy_anchor(data, secs, rows)[-1], 'memcpy')
        for offset in (24, 28, 30, 48, 54):
            with self.subTest(offset=offset):
                damaged = bytearray(data)
                damaged[offset] ^= 1
                with self.assertRaises(ValueError):
                    probe.dynamic_copy_anchor(damaged, secs, rows)
        with self.assertRaises(ValueError):
            probe.dynamic_copy_anchor(data, secs, [(0x64df508, (2 << 32) | 6, 0)])

    def test_synthetic_fde_extent_controls(self):
        valid = {'start': 0x1000, 'end': 0x1010, 'index': 0}
        selected = (('entry', 0x1000, 0x1010),)
        self.assertEqual(probe.check_fdes([valid], selected), [('entry', valid)])
        for fdes in ([], [valid, dict(valid)],
                     [{'start': 0x1000, 'end': 0x100f, 'index': 0}],
                     [{'start': 0x1000, 'end': 0x1010}],
                     [valid, {'start': 0x100f, 'end': 0x1011, 'index': 1}]):
            with self.assertRaises(ValueError):
                probe.check_fdes(fdes, selected)

    @staticmethod
    def lsda_fixture(data):
        sec = [{'name': '.gcc_except_table', 'type': 1, 'address': 0x3000,
                'offset': 0, 'size': len(data)}]
        fde = {'lsda': 0x3000, 'start': 0x1000, 'end': 0x1010}
        return sec, fde

    def test_synthetic_lsda_entry(self):
        data = bytes.fromhex('ffff010400010200')
        sec, fde = self.lsda_fixture(data)
        self.assertEqual(probe.decode_lsda(data, sec, fde), [(4, 0x1000, 0x1001, 0x1002, 0)])
        self.assertEqual(probe.decode_lsda(data, sec, dict(fde, lsda=None)), [])

    def test_lsda_rejects_corrupt_headers_and_tables(self):
        fixtures = [
            '00ff010400010200',  # unexpected base encoding
            'ff00010400010200',  # unsupported type encoding
            'ffff020400010200',  # unsupported call-site encoding
            'ffff017f',          # truncated table
            'ffff010180',        # truncated ULEB
            'ffff010400110200',  # extent past FDE
            'ffff010400017f00',  # landing past FDE
            'ffff01080002020001010300',  # overlapping records
        ]
        for text in fixtures:
            data = bytes.fromhex(text)
            sec, fde = self.lsda_fixture(data)
            with self.subTest(data=text):
                with self.assertRaises(ValueError):
                    probe.decode_lsda(data, sec, fde)

    def test_location_rejects_wrong_length_line_column_and_path(self):
        data = bytearray(68)
        struct.pack_into('<QQII', data, 0, 0, 20, 123, 37)
        struct.pack_into('<QQII', data, 24, 0, 20, 161, 83)
        data[48:] = b'l1/src/abci/state.rs'
        secs = [
            {'name': 'a', 'type': 1, 'address': 0x64767a8, 'offset': 0, 'size': 24},
            {'name': 'b', 'type': 1, 'address': 0x649d9f8, 'offset': 24, 'size': 24},
            {'name': 'str', 'type': 1, 'address': 0x1000, 'offset': 48, 'size': 20},
        ]
        rows = [(0x64767a8, 8, 0x1000), (0x649d9f8, 8, 0x1000)]
        self.assertEqual(len(probe.check_locations(data, secs, rows)), 2)
        for offset in (8, 16, 20, 48):
            with self.subTest(offset=offset):
                bad = bytearray(data)
                bad[offset] ^= 1
                with self.assertRaises(ValueError):
                    probe.check_locations(bad, secs, rows)

    def test_result_and_replacement_tag_boundaries(self):
        marker = 1 << 63
        cases = [(0, 'refcount', 'inline'), (marker - 1, 'refcount', 'inline'),
                 (marker, 'refcount', 'inline'), (marker + 1, 'skip', 'diagnostic'),
                 (marker + 2, 'refcount', 'inline'), (marker + 3, 'vtable', 'helper'),
                 (marker + 4, 'vtable', 'diagnostic'), ((1 << 64) - 1, 'vtable', 'diagnostic')]
        for word, cleanup, result in cases:
            with self.subTest(word=word):
                self.assertEqual(probe.classify_old_word(word), cleanup)
                self.assertEqual(probe.classify_result_word(word), result)
        for word in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                probe.tag_number(word)

    def test_guard_acquisition_and_wakeup_boundaries(self):
        for word in (0, 7, 16, (1 << 64) - 32):
            with self.subTest(word=word):
                self.assertTrue(probe.owner_guard_fast(word, True))
                self.assertFalse(probe.owner_guard_fast(word, False))
        for word in (8, 15, (1 << 64) - 16, (1 << 64) - 1):
            with self.subTest(word=word):
                self.assertFalse(probe.owner_guard_fast(word, True))
        for word in (0x12, 0x13, 0x16, 0x17, 0x1a, 0x1b, 0x1e, 0x1f):
            self.assertTrue(probe.owner_guard_wakes(word))
        for word in (0, 0x10, 0x20, 0x112):
            self.assertFalse(probe.owner_guard_wakes(word))
        with self.assertRaises(ValueError):
            probe.owner_guard_fast(-1, True)
        with self.assertRaises(ValueError):
            probe.owner_guard_fast(0, 1)
        with self.assertRaises(ValueError):
            probe.owner_guard_wakes(1 << 64)

    def test_owner_counter_quotient_and_saturation(self):
        cases = [
            ((100, 10, 9, 123), ('div32', 10, 1, True)),
            ((99, 10, 9, 123), ('div32', 9, 124, False)),
            (((1 << 32) - 1, 1, 0, 0), ('div32', (1 << 32) - 1, 1, True)),
            ((1 << 32, 1, 0, 0), ('div64', 1 << 32, 1, True)),
            ((10, 1 << 32, 0, 0), ('div64', 0, 1, False)),
            ((0, 1, 0, (1 << 64) - 2), ('div32', 0, (1 << 64) - 1, False)),
            ((0, 1, 0, (1 << 64) - 1), ('div32', 0, (1 << 64) - 1, False)),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(probe.owner_counter_step(*args), expected)

    def test_owner_counter_rejects_zero_divisor_and_bad_ranges(self):
        with self.assertRaises(ZeroDivisionError):
            probe.owner_counter_step(0, 0, 0, 0)
        for args in ((-1, 1, 0, 0), (1 << 63, 1, 0, 0), (0, -1, 0, 0),
                     (0, 1 << 64, 0, 0), (0, 1, -1, 0), (0, 1, 0, 1 << 64)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    probe.owner_counter_step(*args)


if __name__ == '__main__':
    unittest.main()
