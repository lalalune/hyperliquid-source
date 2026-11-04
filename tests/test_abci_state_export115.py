"""Controls for the selected static ABCI state export evidence."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_state_export115 as m


class StateExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        m.authenticate(cls.data)
        cls.secs = m.unique_sections(cls.data)
        cls.wanted = set(m.RELOCATION_PINS) | {0x64767d8, 0x64767c0}
        cls.relocs = m.selected_relocations(cls.data, cls.secs, cls.wanted)
        cls.sink, _, cls.suffix = m.extract_constants(cls.data, cls.secs)

    def alter(self, va, fn):
        pos = m.file_offset(self.secs, va, 1)
        original = self.data[pos]
        try:
            self.data[pos] ^= 1
            with self.assertRaises(ValueError):
                fn(self.data)
        finally:
            self.data[pos] = original

    def test_authentication_and_no_output_on_bad_digest(self):
        m.authenticate(self.data)
        pos = m.file_offset(self.secs, 0x422ed70, 1)
        self.data[pos] ^= 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / 'no-output'
                with self.assertRaises(ValueError):
                    m.generate(self.data, dest)
                self.assertFalse(dest.exists())
        finally:
            self.data[pos] ^= 1
        with self.assertRaises(ValueError):
            m.authenticate(b'not the target')

    def test_all_pinned_windows_reject_corruption(self):
        self.assertEqual(len(m.selected_windows(self.data, self.secs)), 62)
        for label, start, _, _ in m.WINDOWS:
            with self.subTest(window=label):
                self.alter(start, lambda data: m.selected_windows(data, self.secs))

    def test_all_selected_transfers_reject_displacement_corruption(self):
        rows = m.selected_edges(self.data, self.secs, self.relocs)
        self.assertEqual(len(rows), 90)
        for row in rows:
            site = row['site'] + len(bytes.fromhex(row['bytes'])) - 1
            with self.subTest(edge=row['label']):
                self.alter(site, lambda data: m.selected_edges(data, self.secs, self.relocs))

    def test_all_selected_transfer_opcodes_reject_corruption(self):
        for label, site, _, _ in m.EDGE_PINS:
            with self.subTest(edge=label):
                self.alter(site, lambda data: m.selected_edges(data, self.secs, self.relocs))

    def test_all_dispatch_table_entries_reject_corruption(self):
        rows = m.selected_tables(self.data, self.secs)
        self.assertEqual(len(rows), 54)
        for row in rows:
            with self.subTest(table=row['label'], index=row['index']):
                self.alter(row['entry'], lambda data: m.selected_tables(data, self.secs))

    def test_dispatch_selected_command_and_resume(self):
        rows = {(r['label'], r['index']): r['target'] for r in m.selected_tables(self.data, self.secs)}
        self.assertEqual(rows['a_resume', 0], 0x2ae420b)
        self.assertEqual(rows['a_command', 2], 0x2ae4ebc)
        self.assertEqual(rows['b_resume', 0], 0x2cde4b0)
        self.assertEqual(rows['b_command', 2], 0x2cdefb5)
        self.assertNotEqual(rows['a_command', 1], rows['a_command', 2])
        self.assertNotEqual(rows['b_command', 3], rows['b_command', 2])

    def test_bad_transfer_opcode_and_out_of_range(self):
        with self.assertRaises(ValueError):
            m.transfer(self.data, self.secs, 0)
        self.alter(0x422ee34, lambda data: m.selected_edges(data, self.secs, self.relocs))

    def test_alternate_wrapper_guard_and_result_bytes(self):
        for site, raw in ((0x2b404be, '48837f0800'),
                          (0x2b40573, '488b7d00'),
                          (0x2b4057c, '89c5'),
                          (0x2b405e0, '89ea'),
                          (0x2b405f0, 'c3'),
                          (0x2b40617, '0f0b')):
            with self.subTest(site=hex(site)):
                self.assertEqual(m.read(self.data, self.secs, site, len(bytes.fromhex(raw))),
                                 bytes.fromhex(raw))
                self.alter(site, lambda data: m.selected_windows(data, self.secs))

    def test_selected_relocations_reject_bad_records(self):
        def record(slot, info, addend):
            return struct.pack('<QQq', slot, info, addend)
        slot = 0x111
        row = record(slot, 8, 0x222)
        def sec(size, typ=4):
            return [{'name': '.rela.dyn', 'type': typ, 'offset': 0, 'size': size}]
        self.assertEqual(m.selected_relocations(row, sec(24), {slot})[slot]['target'], 0x222)
        with self.assertRaises(ValueError):
            m.selected_relocations(row + row, sec(48), {slot})
        with self.assertRaises(ValueError):
            m.selected_relocations(record(slot, 7, 0x222), sec(24), {slot})
        with self.assertRaises(ValueError):
            m.selected_relocations(record(slot, (3 << 32) | 8, 0x222), sec(24), {slot})
        with self.assertRaises(ValueError):
            m.selected_relocations(row, sec(23), {slot})
        with self.assertRaises(ValueError):
            m.selected_relocations(row, sec(24), {slot + 1})
        with self.assertRaises(ValueError):
            m.selected_relocations(row, sec(24, 8), {slot})

    def test_dynamic_import_record_corruption(self):
        rows = m.selected_imports(self.data, self.secs)
        self.assertEqual({row['name'] for row in rows}, {'memcpy', 'write', '__errno_location', 'close'})
        for row in rows:
            for offset in (row['relocation_offset'] + 8, row['symbol_offset'], row['name_offset']):
                original = self.data[offset]
                try:
                    self.data[offset] ^= 1
                    with self.assertRaises(ValueError):
                        m.selected_imports(self.data, self.secs)
                finally:
                    self.data[offset] = original

    def test_location_coordinates_and_path_corruption(self):
        locs = m.selected_locations(self.data, self.secs, self.relocs)
        self.assertEqual([(x['line'], x['column']) for x in locs], [(102, 40), (113, 9)])
        for va in (0x64767d8 + 16, 0x64767c0 + 20, locs[0]['path_va']):
            with self.subTest(va=hex(va)):
                self.alter(va, lambda data: m.selected_locations(data, self.secs, self.relocs))

    def test_all_location_reference_opcodes_and_displacements(self):
        rows = m.selected_location_refs(self.data, self.secs)
        self.assertEqual(len(rows), 4)
        for row in rows:
            for site in (row['site'], row['site'] + 6):
                with self.subTest(site=hex(site)):
                    self.alter(site, lambda data: m.selected_location_refs(data, self.secs))

    def test_all_selected_scalar_operand_shapes_and_values(self):
        rows = m.selected_operands(self.data, self.secs)
        self.assertEqual(len(rows), 16)
        for (label, site, prefix, _, _, _), row in zip(m.OPERAND_PINS, rows):
            self.assertEqual(row['label'], label)
            for addr in (site, site + len(bytes.fromhex(prefix))):
                with self.subTest(site=hex(addr)):
                    self.alter(addr, lambda data: m.selected_operands(data, self.secs))

    def test_all_name_literals_reject_corruption(self):
        rows = m.selected_names(self.data, self.secs)
        self.assertEqual(len(rows), 27)
        for row in rows:
            with self.subTest(name=row['name']):
                self.alter(row['literal_va'], lambda data: m.selected_names(data, self.secs))

    def test_selected_field_offsets(self):
        names = m.selected_names(self.data, self.secs)
        fields = {x['name']: x for x in m.selected_fields(self.data, self.secs, names)}
        self.assertEqual(len(fields), 10)
        self.assertEqual(fields['cls']['state_offset'], 0x7c0)
        self.assertEqual(fields['spot_infos']['state_offset'], 0x90)
        self.assertEqual(fields['allow_duplicate_token_names']['state_offset'], 0x3e8)
        self.assertEqual(fields['address_to_nonce_set']['state_offset'], 0x20a8)
        for _, site, _ in m.FIELD_PINS:
            with self.subTest(site=hex(site)):
                self.alter(site, lambda data: m.selected_fields(data, self.secs, names))

    def test_bad_address_nobits_and_ambiguous_section(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        a = text['address']
        self.assertEqual(m.file_offset([text], a, 1), text['offset'])
        nobits = dict(text, type=8)
        with self.assertRaises(ValueError):
            m.file_offset([nobits], a, 1)
        with self.assertRaises(ValueError):
            m.file_offset([text, dict(text)], a, 1)
        with self.assertRaises(ValueError):
            m.file_offset([text], -1, 1)
        with self.assertRaises(ValueError):
            m.file_offset([text], a, 0)
        with self.assertRaises(ValueError):
            m.file_offset([text], a + text['size'], 1)

    def test_duplicate_and_overlap_fdes_rejected(self):
        start, end, fde, _ = m.FDE_PINS[0]
        frame = {'start': start, 'end': end, 'fde': fde, 'cie': 1, 'lsda': None}
        hdr = [{'start': start, 'fde': fde}]
        for extra in (dict(frame), dict(frame, start=start + 1, fde=fde + 1)):
            with self.subTest(extra=extra['start']):
                with mock.patch.object(m, 'eh_frame_records', return_value=({}, [frame, extra])):
                    with mock.patch.object(m, 'unwind_index', return_value=(self.secs, hdr)):
                        with self.assertRaises(ValueError):
                            m.selected_fdes(self.data, self.secs)

    def test_corrupt_unwind_header_rejected(self):
        section = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        self.alter(section['address'], lambda data: m.selected_fdes(data, self.secs))

    def test_exact_sink_and_all_byte_negative_controls(self):
        self.assertEqual(len(self.sink), 9)
        self.assertEqual(m.route_case(self.sink, 9, b'x.rmp', self.sink, self.suffix), 'sink')
        for i in range(len(self.sink)):
            changed = bytearray(self.sink)
            changed[i] ^= 1
            self.assertNotEqual(m.route_case(bytes(changed), 9, b'x.rmp', self.sink, self.suffix), 'sink')
        self.assertNotEqual(m.route_case(self.sink + b'x', 9, b'x.rmp', self.sink, self.suffix), 'sink')
        self.assertNotEqual(m.route_case(self.sink[:-1], 9, b'x.rmp', self.sink, self.suffix), 'sink')

    def test_all_ascii_case_variants_and_neighbors(self):
        for mask in range(8):
            ext = bytes(c - 32 if mask & (1 << i) else c for i, c in enumerate(self.suffix))
            self.assertEqual(m.route_case(b'x.' + ext, 9, b'x.' + ext, self.sink, self.suffix), 'binary')
        for component in (b'', b'.rmp', b'rmp', b'x.', b'..', b'x.rm', b'x.rmps', b'x.rmq'):
            self.assertEqual(m.route_case(component, 9, component, self.sink, self.suffix), 'text')
        self.assertEqual(m.route_case(b'x..rmp', 9, b'x..rmp', self.sink, self.suffix), 'binary')
        self.assertEqual(m.route_case(b'x.rmp', 8, b'x.rmp', self.sink, self.suffix), 'text')

    def test_scalar_folding_exhaustive_against_independent_oracle(self):
        for value in range(256):
            self.assertEqual(m.fold_ascii(value), bytes([value]).lower()[0])
        for position in range(3):
            for value in range(256):
                ext = bytearray(self.suffix)
                ext[position] = value
                comp = b'x.' + bytes(ext)
                expected = 'binary' if bytes(ext).lower() == self.suffix else 'text'
                self.assertEqual(m.route_case(comp, 9, comp, self.sink, self.suffix), expected)

    def test_format_constants_and_corruption(self):
        self.assertEqual(m.format_constants(self.data, self.secs),
                         {'binary_config_le_hex': '00040001', 'outer_requested_entries': 1,
                          'inner_requested_entries': 59, 'text_open_hex': '7b',
                          'text_separator_hex': '3a20', 'text_close_hex': '7d'})
        for site in (0x422ee5f, 0x3c1398f, 0x3c13a11, 0x3c1372e, 0x3c13785, 0x3c13869):
            with self.subTest(site=hex(site)):
                self.alter(site, lambda data: m.format_constants(data, self.secs))

    def test_map_header_boundaries(self):
        self.assertEqual(m.map_header(0), bytes.fromhex('80'))
        self.assertEqual(m.map_header(1), bytes.fromhex('81'))
        self.assertEqual(m.map_header(15), bytes.fromhex('8f'))
        self.assertEqual(m.map_header(16), bytes.fromhex('de0010'))
        self.assertEqual(m.map_header(59), bytes.fromhex('de003b'))
        self.assertEqual(m.map_header(65535), bytes.fromhex('deffff'))
        self.assertEqual(m.map_header(65536), bytes.fromhex('df00010000'))
        self.assertEqual(m.map_header(0xffffffff), bytes.fromhex('dfffffffff'))
        for bad in (-1, 1 << 32, 1.5, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.map_header(bad)
        for site in (0x3d4f6de, 0x3d4f6e9):
            self.alter(site, lambda data: m.map_cases(data, self.secs))

    def test_command_index_boundaries(self):
        self.assertEqual([m.command_index(x) for x in (0, 1, 2, 3, 4, 14, 15)],
                         [12, 12, 0, 1, 2, 12, 13])
        self.assertEqual(m.command_index((1 << 64) - 1), (1 << 64) - 3)
        for tag in (-1, 1 << 64, True):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                m.command_index(tag)

    def test_write_loop_boundaries(self):
        sentinel = (1 << 64) - 1
        self.assertEqual(m.write_step(0, 0, 0), ('done', 0, 0))
        self.assertEqual(m.write_step(8, 3, 0), ('again', 5, 3))
        self.assertEqual(m.write_step(8, 8, 0), ('done', 0, 8))
        self.assertEqual(m.write_step(8, 0, 0), ('error', 8, 0))
        self.assertEqual(m.write_step(8, sentinel, 4), ('retry', 8, 0))
        self.assertEqual(m.write_step(8, sentinel, 5), ('error', 8, 0))
        self.assertEqual(m.write_step(8, 9, 0), ('trap', 8, 0))
        for args in ((-1, 0, 0), (8, -1, 0), (8, 1 << 64, 0), (8, 0, 1 << 32)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.write_step(*args)

    def test_bad_historical_digest_rejected(self):
        with self.assertRaises(ValueError):
            m.check_historical(b'wrong release')

    def test_generated_files_match_recorded_evidence(self):
        expected = m.ROOT / 'research/work-items/RE-009-abci-state-export-115'
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'regenerated'
            summary = m.generate(self.data, dest)
            self.assertEqual(summary['selected_fdes'], 14)
            self.assertEqual(summary['locations'], 2)
            generated = sorted(path.name for path in dest.iterdir())
            self.assertEqual(len(generated), 17)
            for name in generated:
                with self.subTest(file=name):
                    self.assertEqual((dest / name).read_bytes(), (expected / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
