"""Negative controls for the selected node #115 static evidence."""

from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_entry_checkpoint115 as packet


class EntryCheckpointEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The authenticated artifact is required; a missing file is an error.
        cls.data = packet.TARGET.read_bytes()
        packet.authenticate(cls.data)
        cls.secs = packet.sections(cls.data)
        cls.relocs = packet.read_relocations(cls.data, cls.secs)
        packet.verify_windows(cls.data, cls.secs)
        cls.values, _ = packet.extract_fields(cls.data, cls.secs)

    def test_target_digest(self):
        self.assertEqual(packet.authenticate(self.data), packet.TARGET_SHA256)

    def test_wrong_hash_and_changed_input_fail(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            packet.authenticate(b'')
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            packet.authenticate(changed)

    def test_bad_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bad = base / 'bad-node'
            bad.write_bytes(b'not an ELF')
            out = base / 'must-not-exist'
            with mock.patch.object(packet, 'TARGET', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_every_window_rejects_a_changed_byte(self):
        for label, scope, va, expected in packet.WINDOWS:
            with self.subTest(label=label):
                raw = bytearray.fromhex(expected)
                section = [{'name': '.text', 'type': 1, 'flags': 4,
                            'address': va, 'offset': 0, 'size': len(raw)}]
                spec = [(label, scope, va, expected)]
                self.assertEqual(len(packet.verify_windows(raw, section, spec)), 1)
                for index in {0, len(raw) - 1, len(raw) // 2}:
                    bad = raw.copy()
                    bad[index] ^= 1
                    with self.assertRaises(ValueError):
                        packet.verify_windows(bad, section, spec)

    def test_mapping_rejects_nobits_ambiguity_and_overrun(self):
        raw = bytes(32)
        good = {'name': '.text', 'type': 1, 'flags': 4,
                'address': 0x1000, 'offset': 0, 'size': 16}
        nobits = dict(good, name='.bss', type=8)
        self.assertEqual(packet.file_offset(raw, [good, nobits], 0x1008, 8, True), 8)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [nobits], 0x1000, 1)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [good, dict(good)], 0x1000, 1)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [good], 0x100f, 2)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [good], -1, 1)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [good], 0x1000, 0)
        with self.assertRaises(ValueError):
            packet.file_offset(raw, [dict(good, flags=2)], 0x1000, 1, True)

    def test_all_selected_transfer_targets(self):
        edges = packet.extract_edges(self.data, self.secs)
        self.assertEqual(len(edges), len(packet.EDGES))
        by_name = {e['label']: e['target_va'] for e in edges}
        self.assertEqual(by_name['entry_main_address'], '0x2cef8f0')
        self.assertEqual(by_name['worker_result_sink'], '0x595a6b0')
        self.assertEqual(by_name['sink_flag_nonzero'], '0x595aac0')

    def test_each_edge_rejects_changed_displacement(self):
        for label, va, kind, target in packet.EDGES:
            with self.subTest(label=label):
                raw, actual = packet.decode_edge(self.data, self.secs, va, kind)
                self.assertEqual(actual, target)
                altered = bytearray(raw)
                altered[-1] ^= 1
                section = [{'name': '.text', 'type': 1, 'flags': 4,
                            'address': va, 'offset': 0, 'size': len(raw)}]
                with self.assertRaises(ValueError):
                    packet.extract_edges(altered, section, [(label, va, kind, target)])

    def test_edge_rejects_wrong_opcode(self):
        section = [{'name': '.text', 'type': 1, 'flags': 4,
                    'address': 0x1000, 'offset': 0, 'size': 5}]
        with self.assertRaises(ValueError):
            packet.decode_edge(b'\x90\0\0\0\0', section, 0x1000, 'call')

    def test_relocations_and_symbol(self):
        self.assertEqual(len(self.relocs), len(packet.RELOCATIONS))
        self.assertEqual(packet.dynamic_symbol(self.data, self.secs, 1), '__libc_start_main')
        with self.assertRaises(ValueError):
            packet.dynamic_symbol(self.data, self.secs, -1)

    def test_relocation_type_addend_and_duplicate_controls(self):
        slot = 0x5000
        expected = [('probe', slot, 8, 0, 0x2200)]
        def fixture(entries):
            raw = b''.join(struct.pack('<QQq', *entry) for entry in entries) + bytes(8)
            secs = [{'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0x1000,
                     'offset': 0, 'size': 24 * len(entries)},
                    {'name': '.got', 'type': 1, 'flags': 2, 'address': slot,
                     'offset': 24 * len(entries), 'size': 8}]
            return raw, secs
        raw, secs = fixture([(slot, 8, 0x2200)])
        self.assertEqual(packet.read_relocations(raw, secs, expected)[0]['addend'], '0x2200')
        for entries in [[(slot, 7, 0x2200)], [(slot, 8, 0x2201)],
                        [(slot, 8, 0x2200), (slot, 8, 0x2200)], []]:
            with self.subTest(entries=entries):
                data, sections = fixture(entries)
                with self.assertRaises(ValueError):
                    packet.read_relocations(data, sections, expected)

    def test_location_anchor_and_corruptions(self):
        location = packet.verify_location(self.data, self.secs, self.relocs)
        self.assertEqual((location['path'], location['line'], location['column']),
                         ('l1/src/abci/state.rs', 123, 37))
        altered = [dict(r) for r in self.relocs]
        for row in altered:
            if row['label'] == 'source_location_path':
                row['addend'] = '0x0'
        with self.assertRaises(ValueError):
            packet.verify_location(self.data, self.secs, altered)

    def test_selected_function_extents_match_header(self):
        secs, table = packet.unwind_index(self.data)
        _, fdes = packet.eh_frame_records(self.data, secs)
        rows = packet.selected_fdes(self.data, secs, table, fdes)
        self.assertEqual(len(rows), 5)
        body = {row['label']: row for row in rows}
        self.assertEqual(body['function_pointer_thunk']['body_hex'], '50ffd758c3')
        runtime = next(f for f in fdes if f['start'] == 0x5c99970)
        sites = packet.lsda_rows(self.data, secs, runtime)
        hit = [x for x in sites if int(x['start_va'], 16) <= 0x5c99e21 < int(x['end_va_exclusive'], 16)]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]['landing_va'], '0x5c99f54')

    def test_fde_overlap_and_header_mismatch_rejected(self):
        data = b'\x90\xc3\xcc\xcc'
        secs = [{'name': '.text', 'type': 1, 'flags': 4, 'address': 0x1000,
                 'offset': 0, 'size': len(data)}]
        fde = {'start': 0x1000, 'end': 0x1002, 'fde': 0x2000, 'cie': 0x2100, 'lsda': None}
        row = {'start': 0x1000, 'fde': 0x2000, 'index': 1}
        with mock.patch.object(packet, 'NEW_FUNCTIONS', [('one', 0x1000)]):
            self.assertEqual(len(packet.selected_fdes(data, secs, [row], [fde])), 1)
            with self.assertRaises(ValueError):
                packet.selected_fdes(data, secs, [dict(row, fde=0x2001)], [fde])
            overlap = dict(fde, start=0x1001, end=0x1003, fde=0x2004)
            with self.assertRaises(ValueError):
                packet.selected_fdes(data, secs, [row], [fde, overlap])

    def test_lsda_truncation_and_range_controls(self):
        data = bytes.fromhex('ffff010400010000')
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x1000, 'offset': 0, 'size': len(data)}
        fde = {'start': 0x2000, 'end': 0x2010, 'lsda': 0x1000}
        rows = packet.lsda_rows(data, [sec], fde)
        self.assertEqual(rows[0]['start_va'], '0x2000')
        with self.assertRaises(ValueError):
            packet.lsda_rows(data[:-1], [dict(sec, size=len(data)-1)], fde)
        bad = bytearray(data)
        bad[5] = 0x20
        with self.assertRaises(ValueError):
            packet.lsda_rows(bad, [sec], fde)
        bad = bytearray(data)
        bad[2] = 3
        with self.assertRaises(ValueError):
            packet.lsda_rows(bad, [sec], fde)

    def test_dispatch_rows_and_selected_cases(self):
        rows = packet.dispatch_tables(self.data, self.secs)
        self.assertEqual(len(rows), 27)
        table = {(r['table'], r['index']): int(r['target_va'], 16) for r in rows}
        self.assertEqual(table['poll_command', 0], 0x2cde67c)
        self.assertEqual(table['poll_command', 1], 0x2cdf519)
        self.assertEqual(table['poll_state', 3], 0x2cdf57e)
        self.assertEqual(table['poll_state', 4], 0x2cde6e7)

    def test_corrupted_dispatch_entry_rejected(self):
        original = packet.read_va
        def damaged(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == 0x60bfc0 and size > 4:
                raw = bytes([raw[0] ^ 1]) + raw[1:]
            return raw
        with mock.patch.object(packet, 'read_va', side_effect=damaged):
            with self.assertRaises(ValueError):
                packet.dispatch_tables(self.data, self.secs)

    def test_projection_links_both_fields(self):
        stages = packet.projection(self.values)
        self.assertEqual((stages[4]['height'], stages[4]['flag']), ('0x780', '0x788'))
        self.assertEqual((stages[6]['height'], stages[6]['flag']), ('0x5e8', '0x5f0'))
        self.assertEqual(int(stages[6]['height'], 16) - self.values['worker_sink_offset'], 0x68)
        self.assertEqual(int(stages[6]['flag'], 16) - self.values['worker_sink_offset'], 0x70)

    def test_projection_rejects_broken_joins(self):
        for key in ['copy_a_length', 'copy_b_length', 'copy_c_source', 'parent_source',
                    'callback_parent_length', 'allocation_size', 'allocation_stack_source',
                    'worker_sink_offset', 'sink_marker_offset', 'sink_flag_offset',
                    'parent_mode_saved', 'builder_stack_argument']:
            with self.subTest(key=key):
                values = dict(self.values)
                values[key] = 0 if 'length' in key else values[key] + 1
                with self.assertRaises(ValueError):
                    packet.projection(values)

    def test_copy_boundary_and_out_of_range(self):
        self.assertEqual(packet.map_copy(0x110, 0x100, 0x200, 0x18, 8), 0x210)
        for pos, width in [(0xff, 1), (0x111, 8), (0x118, 1), (0x100, 0)]:
            with self.subTest(pos=pos, width=width):
                with self.assertRaises(ValueError):
                    packet.map_copy(pos, 0x100, 0x200, 0x18, width)

    def test_bucket_matches_independent_unsigned_division(self):
        v = self.values
        maximum = (1 << 64) - 1
        cases = [0, 1, 9999, 10000, 10001, 10002, 19999, 20000, 20001,
                 maximum, maximum - 1, maximum - 9999, maximum - 10000]
        state = 0x123456789abcdef0
        for _ in range(20000):
            state = (state * 6364136223846793005 + 1442695040888963407) & maximum
            cases.append(state)
        for n in cases:
            with self.subTest(n=n):
                got = packet.bucket_formula(n, v['sink_multiplier'], v['sink_shift'], v['sink_period'])
                want = (max(n - 1, 0) // 10000) * 10000
                self.assertEqual(got, want)
        with self.assertRaises(ValueError):
            packet.bucket_formula(-1, v['sink_multiplier'], v['sink_shift'], v['sink_period'])
        with self.assertRaises(ValueError):
            packet.bucket_formula(1 << 64, v['sink_multiplier'], v['sink_shift'], v['sink_period'])
        self.assertNotEqual(packet.bucket_formula(10001, 0, v['sink_shift'], v['sink_period']), 10000)

    def test_mode_and_bucket_order_counterexamples(self):
        # Synthetic model of the pinned branch order; no machine code runs.
        def route(mode, current, n, disabled):
            if disabled:
                return 'disabled'
            candidate = (max(n - 1, 0) // 10000) * 10000
            if candidate <= current:
                return 'direct'
            return 'consider-extra' if mode == 2 else 'bypass-extra'
        self.assertEqual(route(1, 0, 10000, False), 'direct')
        self.assertEqual(route(1, 0, 10001, False), 'bypass-extra')
        self.assertEqual(route(2, 0, 10001, False), 'consider-extra')
        self.assertEqual(route(2, 10000, 10001, False), 'direct')
        self.assertEqual(route(2, 0, 10001, True), 'disabled')
        for mode in range(256):
            self.assertEqual(route(mode, 0, 10001, False) == 'consider-extra', mode == 2)

    def test_row_pipeline_count_and_stride_boundaries(self):
        values = self.values
        self.assertEqual(values['row32_count_cutoff'], 21)
        self.assertEqual(values['row24_count_cutoff'], 21)
        self.assertEqual(1 << values['row32_stride_shift'], 32)
        # Compare operands at the 24-byte path's two LEA instructions.
        self.assertEqual(packet.read_va(self.data, self.secs, 0x15b5a41, 8, True),
                         bytes.fromhex('4b8d0c76498d0ccf'))
        def branch(count, cutoff):
            if count == 0:
                return 'empty'
            if count == 1:
                return 'single'
            return 'large' if count >= cutoff else 'small'
        for count, expected in [(0, 'empty'), (1, 'single'), (2, 'small'),
                                (20, 'small'), (21, 'large'), (22, 'large')]:
            self.assertEqual(branch(count, values['row32_count_cutoff']), expected)
            self.assertEqual(branch(count, values['row24_count_cutoff']), expected)
        self.assertNotEqual(branch(20, 20), branch(20, values['row32_count_cutoff']))

    def test_historical_wrong_digest_fails_before_elf_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad-historical'
            path.write_bytes(b'wrong release')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                packet.check_historical(path)


if __name__ == '__main__':
    unittest.main()
