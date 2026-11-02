# SPDX-License-Identifier: MIT
"""Controls for the selected static linked-state path; no target execution."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_linked_commit115 as packet


class LinkedCommitEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(packet.TARGET.read_bytes())
        cls.secs = packet.sections(cls.data)
        cls.relocs = packet.read_relocations(cls.data, cls.secs, packet.RELOCS)
        cls.constants = packet.encoding_constants(cls.data, cls.secs)
        cls.files = packet.extract(cls.data)
        cls.evidence = packet.ROOT / 'research/work-items/RE-017-abci-linked-commit-115'

    def flip(self, va, width=1):
        off, _ = packet.file_mapping(self.secs, va, width)
        self.data[off] ^= 1
        self.addCleanup(lambda: self.data.__setitem__(off, self.data[off] ^ 1))
        return off

    def test_artifact_digest_and_release(self):
        self.assertEqual(packet.authenticate(self.data), packet.SHA256)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.SHA256)
        with self.assertRaises(ValueError):
            packet.authenticate(b'incorrect')
        with self.assertRaises(ValueError):
            packet.check_history(b'incorrect historical file')

    def test_public_identity_failure_precedes_output(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            bad = root / 'input'
            bad.write_bytes(b'not the captured node')
            out = root / 'not-created'
            with mock.patch.object(packet, 'TARGET', bad):
                with self.assertRaises(ValueError):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_same_length_target_corruption_fails_authentication(self):
        self.flip(0x5485f80)
        with self.assertRaises(ValueError):
            packet.authenticate(self.data)

    def test_generated_files_match_packet(self):
        self.assertEqual(len(self.files), 16)
        for name, expected in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((self.evidence / name).read_bytes(), expected)

    def test_windows_reject_every_selected_endpoint_corruption(self):
        for label, _scope, va, pin in packet.WINDOWS:
            size = len(bytes.fromhex(pin))
            for point in {va, va + size - 1}:
                with self.subTest(label=label, point=hex(point)):
                    off, _ = packet.file_mapping(self.secs, point, 1)
                    self.data[off] ^= 1
                    try:
                        with self.assertRaises(ValueError):
                            packet.checked_windows(self.data, self.secs)
                    finally:
                        self.data[off] ^= 1

    def test_every_transfer_is_completely_pinned(self):
        for name, _scope, va, form, target in packet.EDGES:
            with self.subTest(name=name):
                decoded, raw = packet.decode_edge(self.data, self.secs, va, form)
                self.assertEqual(decoded, target)
                self.assertTrue(any(start <= va and va + len(raw) <= start + len(bytes.fromhex(pin))
                                    for _, _, start, pin in packet.WINDOWS))

    def test_transfer_displacement_corruption_rejected(self):
        for name, _scope, va, form, _target in packet.EDGES:
            _decoded, raw = packet.decode_edge(self.data, self.secs, va, form)
            with self.subTest(name=name):
                off, _ = packet.file_mapping(self.secs, va + len(raw) - 1, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.checked_edges(self.data, self.secs)
                finally:
                    self.data[off] ^= 1

    def test_transfer_opcode_corruption_rejected_by_pinned_windows(self):
        for name, _scope, va, _form, _target in packet.EDGES:
            with self.subTest(name=name):
                off, _ = packet.file_mapping(self.secs, va, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.checked_windows(self.data, self.secs)
                finally:
                    self.data[off] ^= 1

    def test_actual_fde_range_corruption_rejected(self):
        _, entries = packet.eh_frame_records(self.data, self.secs)
        fde = next(f for f in entries if f['start'] == 0x5485f80)
        self.flip(fde['fde'] + 12)
        with self.assertRaises(ValueError):
            packet.checked_fdes(self.data, self.secs)

    def test_context_fde_range_corruption_rejected(self):
        _, entries = packet.eh_frame_records(self.data, self.secs)
        fde = next(f for f in entries if f['start'] == 0x5a6bfb0)
        self.flip(fde['fde'] + 12)
        with self.assertRaises(ValueError):
            packet.checked_fdes(self.data, self.secs)

    def test_context_fde_overlap_rejected(self):
        cies, entries = packet.eh_frame_records(self.data, self.secs)
        overlapping = {'start': 0x5a6bfb1, 'end': 0x5a6bfb2, 'fde': 0}
        with mock.patch.object(packet, 'eh_frame_records', return_value=(cies, entries + [overlapping])):
            with self.assertRaises(ValueError):
                packet.checked_fdes(self.data, self.secs)

    def test_header_fde_pointer_corruption_rejected(self):
        _s, entries = packet.unwind_index(self.data)
        entry = next(r for r in entries if r['start'] == 0x5485f80)
        header = packet.unique_section(self.secs, '.eh_frame_hdr')
        off = header['offset'] + 12 + entry['index'] * 8 + 4
        self.data[off] ^= 1
        self.addCleanup(lambda: self.data.__setitem__(off, self.data[off] ^ 1))
        with self.assertRaises(ValueError):
            packet.checked_fdes(self.data, self.secs)

    def test_file_mapping_rejects_nobits_ambiguity_and_overflow(self):
        sec = {'name': 'data', 'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0, 'size': 16}
        bss = dict(sec, name='bss', type=8)
        self.assertEqual(packet.file_mapping([sec, bss], 0x100, 4), (0, 'data'))
        with self.assertRaises(ValueError):
            packet.file_mapping([bss], 0x100, 1)
        with self.assertRaises(ValueError):
            packet.file_mapping([sec, dict(sec, name='duplicate')], 0x100, 1)
        with self.assertRaises(ValueError):
            packet.file_mapping([sec], 0x10f, 2)
        with self.assertRaises(ValueError):
            packet.file_mapping([sec], 0x100, 0)
        with self.assertRaises(ValueError):
            packet.file_mapping([sec], 0x100, 1, executable=True)

    def test_relocation_type_symbol_and_addend_corruption(self):
        off = self.relocs[0x64e09e8][3]
        for relative in (8, 12, 16):
            with self.subTest(relative=relative):
                self.data[off + relative] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.read_relocations(self.data, self.secs, packet.RELOCS)
                finally:
                    self.data[off + relative] ^= 1

    def test_duplicate_selected_relocation_is_rejected(self):
        sec = packet.unique_section(self.secs, '.rela.dyn', 4)
        off = next(o for o in range(sec['offset'], sec['offset'] + sec['size'], 24)
                   if struct.unpack_from('<Q', self.data, o)[0] not in packet.RELOCS)
        saved = bytes(self.data[off:off + 8])
        struct.pack_into('<Q', self.data, off, 0x64e09e8)
        try:
            with self.assertRaises(ValueError):
                packet.read_relocations(self.data, self.secs, packet.RELOCS)
        finally:
            self.data[off:off + 8] = saved

    def test_location_data_and_path_corruption(self):
        rows = packet.checked_locations(self.data, self.secs, self.relocs)
        self.assertIn(('0x64aa230', '0x64a8230', 'l1/src/abci/state.rs', 20, 201, 9), rows)
        off, _ = packet.file_mapping(self.secs, 0x64aa230 + 16, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                packet.checked_locations(self.data, self.secs, self.relocs)
        finally:
            self.data[off] ^= 1
        self.flip(0x443168)
        with self.assertRaises(ValueError):
            packet.checked_locations(self.data, self.secs, self.relocs)

    def test_literal_and_reference_corruption(self):
        for name, va, raw in packet.LITERALS:
            with self.subTest(name=name):
                off, _ = packet.file_mapping(self.secs, va, len(raw))
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.checked_literals(self.data, self.secs)
                finally:
                    self.data[off] ^= 1
        self.flip(0x4d9311c + 3)
        with self.assertRaises(ValueError):
            packet.checked_fields(self.data, self.secs)

    def test_selected_field_offsets_and_writer(self):
        rows = packet.checked_fields(self.data, self.secs)
        by_name = {row[0]: row for row in rows}
        self.assertEqual(by_name['height'][5:], ('0x28', '0x4d93145', 'e866cfa300', '0x57d00b0'))
        self.assertEqual(by_name['hardfork_height'][5], '0x10')
        self.assertEqual(by_name['round'][5], '0x30')
        self.assertEqual(by_name['time'][5], '0x60')
        self.assertEqual(by_name['prev_time'][5], '0x6c')

    def test_field_offset_corruption(self):
        self.flip(0x4d93114)
        with self.assertRaises(ValueError):
            packet.checked_fields(self.data, self.secs)

    def test_every_selected_operand_pin_detects_corruption(self):
        for name, va, _pin, at, _size, _value in packet.OPERANDS:
            with self.subTest(name=name):
                off, _ = packet.file_mapping(self.secs, va + at, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.checked_operands(self.data, self.secs)
                finally:
                    self.data[off] ^= 1

    def test_bootstrap_tail_stores_and_selector_handoff(self):
        rows = packet.checked_operands(self.data, self.secs)
        values = {name: int(value, 16) for name, _va, _raw, _at, _size, value in rows}
        # The saved slot is a previously researched contextual input. Only the
        # subsequent stores and selector call are newly checked here.
        inherited_slot_end = 0x1690 + 8
        for name in ('bootstrap_tail_qword', 'bootstrap_tail_dword', 'bootstrap_tail_byte'):
            self.assertGreaterEqual(values[name], inherited_slot_end)
        dest, raw = packet.decode_edge(self.data, self.secs, 0x5a6c16a, 'call')
        self.assertEqual((dest, raw.hex()), (0x5a08720, 'e8b1c5f9ff'))
        self.assertEqual(packet.read_va(self.data, self.secs, 0x5a6c167, 3, True),
                         bytes.fromhex('4c89f6'))
        self.flip(0x5a6c140 + 4)
        with self.assertRaises(ValueError):
            packet.checked_operands(self.data, self.secs)

    def test_import_symbol_and_out_of_range_symbol(self):
        self.assertEqual(packet.symbol_name(self.data, self.secs, 7), 'memcpy')
        with self.assertRaises(ValueError):
            packet.symbol_name(self.data, self.secs, 10**9)

    def test_lsda_selected_calls_and_landings(self):
        fdes, _ = packet.checked_fdes(self.data, self.secs)
        rows, count = packet.checked_unwind(self.data, self.secs, fdes)
        self.assertEqual(count, 65)
        by_name = {row[0]: row for row in rows}
        self.assertEqual(by_name['link_capture'][6], '0x54863ba')
        self.assertEqual(by_name['snapshot_encode_simple'][6], '0x4e36636')
        self.assertEqual(by_name['serialize_state'][6], '0x4e4b800')
        self.assertEqual(by_name['output_state'][6], '0x4e4b7e1')
        self.assertEqual(by_name['digest_update_input'][6], '')

    def test_all_lsda_records_cover_selected_witnesses(self):
        fdes, _ = packet.checked_fdes(self.data, self.secs)
        witnesses, count = packet.checked_unwind(self.data, self.secs, fdes)
        records = packet.all_unwind_records(self.data, self.secs, fdes)
        self.assertEqual(len(records), count)
        by_entry_offset = {row[2]: row for row in records}
        self.assertEqual(len(by_entry_offset), count)
        for label, start, site, off, begin, end, landing, action in witnesses:
            with self.subTest(label=label):
                row = by_entry_offset[off]
                self.assertEqual((row[0], row[3], row[4], row[5], row[6]),
                                 (start, begin, end, landing, action))
                self.assertLessEqual(int(begin, 16), int(site, 16))
                self.assertLess(int(site, 16), int(end, 16))

    def test_malformed_lsda_is_rejected(self):
        self.flip(0x3aad88)
        with self.assertRaises(ValueError):
            packet.parse_lsda(self.data, self.secs, 0x5485f80, 0x548649f, 0x3aad88)

    def test_snapshot_key_and_all_single_byte_counterfactuals(self):
        selector = packet.checked_selector(self.data, self.secs, self.relocs)
        original = b'abci_state'
        self.assertEqual(packet.select_suffix(original, selector), 'rmp')
        for index in range(len(original)):
            for byte in range(256):
                candidate = original[:index] + bytes((byte,)) + original[index + 1:]
                expected = 'rmp' if byte == original[index] else 'json'
                self.assertEqual(packet.select_suffix(candidate, selector), expected)
        for key in (b'', original[:-1], original + b'x', b'ABCI_STATE'):
            self.assertEqual(packet.select_suffix(key, selector), 'json')
        with self.assertRaises(ValueError):
            packet.select_suffix('abci_state', selector)

    def test_snapshot_descriptor_and_comparison_corruption(self):
        for va in (0x64aa228, 0x929ae3, 0x5942899, 0x59428ab):
            with self.subTest(va=hex(va)):
                off, _ = packet.file_mapping(self.secs, va, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.checked_selector(self.data, self.secs, self.relocs)
                finally:
                    self.data[off] ^= 1

    def test_nested_named_prefix_is_conditional_model(self):
        model = packet.synthetic_models(self.constants)
        self.assertEqual(model['conditional_prefix_hex'],
                         '81a865786368616e6765de003ba56c6f637573de0011a36374788d')
        self.assertEqual(model['height_key_hex'], 'a6686569676874')
        self.assertNotIn(model['height_key_hex'], model['conditional_prefix_hex'])

    def test_height_unsigned_width_boundaries(self):
        expected = {
            0: '00', 127: '7f', 128: 'cc80', 255: 'ccff', 256: 'cd0100',
            65535: 'cdffff', 65536: 'ce00010000', (1 << 32) - 1: 'ceffffffff',
            1 << 32: 'cf0000000100000000', (1 << 64) - 1: 'cfffffffffffffffff',
        }
        for value, text in expected.items():
            with self.subTest(value=value):
                self.assertEqual(packet.encode_uint(value, self.constants).hex(), text)
        for value in (-1, 1 << 64, True, 1.0):
            with self.assertRaises(ValueError):
                packet.encode_uint(value, self.constants)

    def test_map_header_boundaries(self):
        expected = {0: '80', 15: '8f', 16: 'de0010', 59: 'de003b',
                    65535: 'deffff', 65536: 'df00010000'}
        for count, text in expected.items():
            self.assertEqual(packet.map_header(count, self.constants).hex(), text)
        for count in (-1, 1 << 32, False):
            with self.assertRaises(ValueError):
                packet.map_header(count, self.constants)

    def test_short_string_bounds(self):
        self.assertEqual(packet.short_string(b'height', self.constants).hex(), 'a6686569676874')
        self.assertEqual(packet.short_string(b'x' * 31, self.constants)[0], 0xbf)
        with self.assertRaises(ValueError):
            packet.short_string(b'x' * 32, self.constants)

    def test_changed_integer_and_map_constants_fail(self):
        for va in (0x57d00be + 3, 0x57d0109 + 3, 0x57d027a + 3,
                   0x57d053a + 3, 0x57ce117 + 1, 0x54819a6 + 1):
            with self.subTest(va=hex(va)):
                off, _ = packet.file_mapping(self.secs, va, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        packet.encoding_constants(self.data, self.secs)
                finally:
                    self.data[off] ^= 1

    def test_root_digest_order_is_backed_by_pinned_windows(self):
        self.assertEqual(packet.OPERANDS[-2][-1], 32)
        self.assertEqual(packet.OPERANDS[-1][-1], 32)
        labels = {row[0]: row for row in packet.WINDOWS}
        raw = bytes.fromhex(labels['digest_second'][3])
        self.assertIn(bytes.fromhex('ba200000004c89e74c89eeffd5'), raw)
        self.assertEqual(raw.count(bytes.fromhex('ba200000004c89e74c89eeffd5')), 2)
        self.assertIn(bytes.fromhex('660f114b10660f1103'), raw)
        self.flip(0x457d171 + 1)
        with self.assertRaises(ValueError):
            packet.checked_windows(self.data, self.secs)

    def test_serializer_preserves_returned_buffer_across_local_reuse(self):
        labels = {row[0]: bytes.fromhex(row[3]) for row in packet.WINDOWS}
        setup = labels['serializer_setup']
        self.assertIn(bytes.fromhex('4889442408'), setup)
        self.assertIn(bytes.fromhex('48897c2420'), setup)
        self.assertIn(bytes.fromhex('4989c7'), setup)
        self.assertEqual(labels['serializer_clear_owner'], bytes.fromhex('4c897c2478'))
        self.assertIn(bytes.fromhex('4c39fe7415'), labels['serializer_result'])
        self.flip(0x4e4b5ad)
        with self.assertRaises(ValueError):
            packet.checked_windows(self.data, self.secs)


if __name__ == '__main__':
    unittest.main()
