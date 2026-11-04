"""Offline controls for selected node 115 balance-read witnesses."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import re011_balance_read115 as subject


class BalanceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        subject.authenticate(cls.data)
        cls.image = subject.Image(cls.data)
        cls.files, cls.summary = subject.collect(cls.data)
        cls.names = subject.field_names(cls.image)
        cls.guard = subject.read_guard_constants(cls.image)

    def test_artifact_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.NODE_SHA256)
        self.assertEqual(len(self.data), 105896032)

    def test_digest_rejects_corruption(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(b'changed target')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(self.data, '0' * 64)

    def test_bad_cli_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / 'bad'
            bad.write_bytes(b'not a captured node')
            out = root / 'never-created'
            with mock.patch.object(subject, 'BINARY', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_all_selected_windows_reject_mutation(self):
        for label, va, expected in subject.WINDOWS:
            expected_bytes = bytes.fromhex(expected)
            actual = self.image.read(va, len(expected_bytes), executable=True)
            subject.check_witness(actual, expected_bytes)
            changed = bytearray(actual)
            changed[len(changed) // 2] ^= 1
            with self.subTest(window=label), self.assertRaises(ValueError):
                subject.check_witness(changed, expected_bytes)

    def test_all_transfers_reject_corruption(self):
        for label, va, expected, target, kind in subject.TRANSFERS:
            raw = bytes.fromhex(expected)
            self.assertEqual(subject.checked_transfer(va, raw, expected, target, kind), (kind, target))
            changed = bytearray(raw)
            changed[-1] ^= 1
            with self.subTest(transfer=label), self.assertRaises(ValueError):
                subject.checked_transfer(va, changed, expected, target, kind)

    def test_transfer_forms_and_bounds(self):
        self.assertEqual(subject.decode_transfer(0x100, bytes.fromhex('e8fbffffff')), ('call', 0x100))
        self.assertEqual(subject.decode_transfer(0x100, bytes.fromhex('75fe')), ('jcc', 0x100))
        self.assertEqual(subject.decode_transfer(0x100, bytes.fromhex('0f84faffffff')), ('jcc', 0x100))
        self.assertEqual(subject.decode_transfer(0x100, bytes.fromhex('ff150a000000')), ('indirect', 0x110))
        for raw in (b'', b'\xe8\x00', b'\x90', b'\x0f\x90\x00\x00\x00\x00'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.decode_transfer(0x100, raw)
        with self.assertRaises(ValueError):
            subject.decode_transfer(0, bytes.fromhex('e8faffffff'))
        with self.assertRaises(ValueError):
            subject.checked_transfer(0x100, bytes.fromhex('75fe'), '75fe', 0x101, 'jcc')

    def test_rip_references_and_corruption(self):
        for label, va, target, literal in subject.REFERENCES:
            raw = self.image.read(va, 7, executable=True)
            self.assertEqual(subject.decode_lea(va, raw), target, label)
            if literal is not None:
                self.assertEqual(self.image.read(target, len(literal)), literal)
            changed = bytearray(raw)
            changed[3] ^= 1
            self.assertNotEqual(subject.decode_lea(va, changed), target)
            changed[0] = 0x90
            with self.assertRaises(ValueError):
                subject.decode_lea(va, changed)

    def test_method_literal_and_length(self):
        self.assertEqual(self.image.read(0x602416, 14), b'eth_getBalance')
        self.assertEqual(self.image.read(0x2a060c8, 5, executable=True), bytes.fromhex('b90e000000'))
        self.assertEqual(subject.decode_transfer(0x2a060cd, self.image.read(0x2a060cd, 5, executable=True)),
                         ('call', 0x2cff4e0))

    def test_vtable_relative_callback_slots(self):
        records = subject.selected_relocations(self.data, self.image.section('.rela.dyn'), subject.RELATIVE_SLOTS)
        self.assertEqual(records[0x64506e0][2], 0x2dd5c60)
        self.assertEqual(records[0x64506e8][2], 0x2d009f0)
        self.assertEqual(records[0x64506f0][2], 0x2d009f0)
        self.assertEqual(records[0x64e1e48][2], 0x167a9c0)

    def test_relocation_missing_duplicate_type_and_addend(self):
        wanted = {0x200: 0x1234}
        valid = struct.pack('<QQq', 0x200, 8, 0x1234)
        sec = {'type': 4, 'offset': 0, 'size': 24}
        self.assertEqual(subject.selected_relocations(valid, sec, wanted)[0x200][2], 0x1234)
        for raw, section in ((b'', sec),
                             (valid + valid, dict(sec, size=48)),
                             (struct.pack('<QQq', 0x200, 7, 0x1234), sec),
                             (struct.pack('<QQq', 0x200, 8, 0x1235), sec),
                             (struct.pack('<QQq', 0x201, 8, 0x1234), sec),
                             (valid, dict(sec, size=23)),
                             (valid, dict(sec, type=8))):
            with self.subTest(raw=raw.hex(), section=section), self.assertRaises(ValueError):
                subject.selected_relocations(raw, section, wanted)

    def test_address_mapping_excludes_nobits_and_ambiguity(self):
        sec = {'type': 1, 'flags': 4, 'address': 100, 'size': 10, 'offset': 200, 'name': 'text'}
        bss = {'type': 8, 'flags': 4, 'address': 100, 'size': 10, 'offset': 0, 'name': 'bss'}
        self.assertEqual(subject.map_offset([sec, bss], 100, 10, executable=True), (200, 'text'))
        for sections, va, size in (([bss], 100, 1), ([sec, dict(sec)], 100, 1),
                                   ([sec], 99, 1), ([sec], 109, 2), ([sec], 100, 0),
                                   ([sec], -1, 1), ([sec], (1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                subject.map_offset(sections, va, size)
        with self.assertRaises(ValueError):
            subject.map_offset([dict(sec, flags=2)], 100, 1, executable=True)

    def test_unwind_records_and_ranges(self):
        rows = self.files['functions.tsv'].decode('ascii').splitlines()
        self.assertEqual(len(rows) - 1, 15)
        for row in rows[1:]:
            cells = row.split('\t')
            start, end, file_offset, size = int(cells[1], 16), int(cells[2], 16), int(cells[3], 16), int(cells[4])
            self.assertEqual(end - start, size)
            self.assertEqual(self.image.offset(start, size, executable=True), file_offset)
            self.assertEqual(hashlib.sha256(self.data[file_offset:file_offset+size]).hexdigest(), cells[-1])
            self.assertGreater(len(bytes.fromhex(cells[12])), 8)
            self.assertGreater(len(bytes.fromhex(cells[13])), 8)

    def test_selected_frame_mismatches(self):
        start, fde_va = 0x100, 0x200
        entries = {start: {'fde': fde_va}}
        frames = {fde_va: {'start': start, 'end': start + 1}}
        self.assertEqual(subject.selected_frame(start, entries, frames)[1]['end'], start + 1)
        for given_start, table, records in ((start + 1, entries, frames),
                                            (start, entries, {}),
                                            (start, entries, {fde_va: {'start': start + 1, 'end': start + 2}}),
                                            (start, entries, {fde_va: {'start': start, 'end': start}})):
            with self.subTest(start=given_start, records=records), self.assertRaises(ValueError):
                subject.selected_frame(given_start, table, records)

    def test_unwind_record_range_rejection(self):
        with self.assertRaises(ValueError):
            subject.table_record_bytes(self.image, (1 << 64) - 1)
        class Tiny:
            def read(self, _va, _size):
                return bytes.fromhex('ffffffff')
        with self.assertRaisesRegex(ValueError, 'frame length'):
            subject.table_record_bytes(Tiny(), 0)

    def test_selected_exception_call_site_records(self):
        headers = self.files['lsda-headers.tsv'].decode('ascii').splitlines()
        sites = self.files['lsda-call-sites.tsv'].decode('ascii').splitlines()
        self.assertEqual(len(headers) - 1, 13)
        self.assertEqual(len(sites) - 1, 95)
        self.assertIn('conditional_metric_update\t0\t0x4771f97\t0x4771fa1\t'
                      '0x47721c1\t0\t270ad10400', sites)
        for row in sites[1:]:
            role, _, start, end, landing, _, _ = row.split('\t')
            frame = next(line.split('\t') for line in
                         self.files['functions.tsv'].decode('ascii').splitlines()[1:]
                         if line.split('\t')[0] == role)
            fde_start, fde_end = int(frame[1], 16), int(frame[2], 16)
            self.assertLessEqual(fde_start, int(start, 16))
            self.assertLessEqual(int(start, 16), int(end, 16))
            self.assertLessEqual(int(end, 16), fde_end)
            if landing:
                self.assertLessEqual(fde_start, int(landing, 16))
                self.assertLess(int(landing, 16), fde_end)

    def test_exception_call_site_synthetic_encodings(self):
        for raw in (bytes.fromhex('ffff010400010000'),
                    bytes.fromhex('ff9b06010400010000')):
            header, rows = subject.parse_lsda(raw, 0, len(raw), 0x100, 0x110)
            self.assertEqual(header['table_size'], 4)
            self.assertEqual(rows, [(0, 1, 0, 0, '00010000')])

    def test_exception_call_site_negative_controls(self):
        bad = (
            '00ff010400010000',  # unsupported LPStart encoding
            'ff9c010400010000',  # unsupported type encoding
            'ffff020400010000',  # unsupported call-site encoding
            'ffff010500010000',  # truncated call-site table
            'ffff010180',        # truncated ULEB
            'ffff010400110000',  # protected extent exceeds the FDE
            'ffff010400011000',  # landing pad is past the FDE
            'ff9b01010400010000',  # type table overlaps the call-site table
        )
        for hex_string in bad:
            raw = bytes.fromhex(hex_string)
            with self.subTest(raw=hex_string), self.assertRaises(ValueError):
                subject.parse_lsda(raw, 0, len(raw), 0x100, 0x110)
        with self.assertRaises(ValueError):
            subject.parse_lsda(b'', 0, 0, 0x100, 0x110)
        with self.assertRaises(ValueError):
            subject.parse_lsda(bytes.fromhex('ffff0100'), 0, 4, 0x110, 0x110)

    def test_dynamic_symbol_relocation_and_negative_controls(self):
        result = subject.selected_bcmp(self.image)
        self.assertEqual(result['symbol_name'], 'bcmp')
        self.assertEqual(bytes.fromhex(result['symbol_name_hex']), b'bcmp\x00')
        self.assertEqual(len(bytes.fromhex(result['symbol_record_hex'])), 24)
        self.assertEqual(result['symbol_index'], 11)
        self.assertEqual(result['slot_va'], '0x64df9f8')
        self.assertEqual(len(result['register_calls']), 2)
        slot = 0x200
        sec = {'type': 4, 'offset': 0, 'size': 24}
        good = struct.pack('<QQq', slot, (11 << 32) | 6, 0)
        self.assertEqual(subject.dynamic_relocation(good, sec, slot)[1], 11)
        for record, section in ((good + good, dict(sec, size=48)),
                                (good[:-1], sec),
                                (struct.pack('<QQq', slot, (11 << 32) | 8, 0), sec),
                                (struct.pack('<QQq', slot, 6, 0), sec),
                                (struct.pack('<QQq', slot, (11 << 32) | 6, 1), sec),
                                (struct.pack('<QQq', slot + 1, (11 << 32) | 6, 0), sec),
                                (good, dict(sec, offset=-1))):
            with self.subTest(record=record.hex(), section=section), self.assertRaises(ValueError):
                subject.dynamic_relocation(record, section, slot)

    def test_selected_dynamic_name_and_call_corruption(self):
        with mock.patch.object(subject, 'dynamic_symbol', return_value=('other', 0, 0)):
            with self.assertRaisesRegex(ValueError, 'symbol name'):
                subject.selected_bcmp(self.image)
        class Changed:
            def __init__(self, base, address):
                self.base, self.address, self.data = base, address, base.data
            def read(self, va, size, **kwargs):
                raw = bytearray(self.base.read(va, size, **kwargs))
                if va <= self.address < va + size:
                    raw[self.address - va] ^= 1
                return bytes(raw)
            def section(self, name):
                return self.base.section(name)
            def offset(self, *args, **kwargs):
                return self.base.offset(*args, **kwargs)
        for address in (0x476f2bd, 0x476f2c0, 0x476f368, 0x476f3a5):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                subject.selected_bcmp(Changed(self.image, address))

    def test_dynamic_symbol_name_bounds(self):
        class Fake:
            def __init__(self, string_table, name_offset=0):
                self.data = bytes(24) + struct.pack('<IBBHQQ', name_offset, 0, 0, 0, 0, 0) + string_table
            def section(self, name):
                if name == '.dynsym':
                    return {'type': 11, 'offset': 0, 'size': 48}
                return {'type': 3, 'offset': 48, 'size': len(self.data) - 48}
        self.assertEqual(subject.dynamic_symbol(Fake(b'bcmp\x00'), 1)[0], 'bcmp')
        with self.assertRaises(ValueError):
            subject.dynamic_symbol(Fake(b'bcmp'), 1)
        with self.assertRaises(ValueError):
            subject.dynamic_symbol(Fake(b'bcmp\x00', 5), 1)
        with self.assertRaises(ValueError):
            subject.dynamic_symbol(Fake(b'bcmp\x00'), 2)

    def test_element_wrapper_selected_tags(self):
        self.assertEqual(subject.element_wrapper_model(1, 1, 0), (1, None))
        self.assertEqual(subject.element_wrapper_model(0, 0, 1), (0, 0))
        self.assertEqual(subject.element_wrapper_model(0, 1, 1), (1, None))
        self.assertEqual(subject.element_wrapper_model(0, 1, 0), (0, 1))
        with self.assertRaises(ValueError):
            subject.element_wrapper_model(2, 1, 0)
        size = subject.selected_expected_size(self.image)
        self.assertEqual((size['first_word'], size['second_word']), (20, 40))
        self.assertIn(b'exactly ', bytes.fromhex(size['format_bytes']))

    def test_descriptor_metadata_and_relocations(self):
        rels = subject.selected_relocations(self.data, self.image.section('.rela.dyn'), subject.RELATIVE_SLOTS)
        rows = subject.descriptor_rows(self.image, rels)
        self.assertEqual(len(rows), 6)
        self.assertEqual([row[4] for row in rows[:3]], [0, 8, 8])
        self.assertEqual([row[-1] for row in rows[3:]], ['0x2dd5c60', '0x2d009f0', '0x2d009f0'])
        class Mutated:
            def __init__(self, base):
                self.base = base
            def read(self, va, size, **kwargs):
                value = bytearray(self.base.read(va, size, **kwargs))
                if va <= 0x64506d0 < va + size:
                    value[0x64506d0 - va] ^= 1
                return bytes(value)
            def offset(self, *args, **kwargs):
                return self.base.offset(*args, **kwargs)
        with self.assertRaises(ValueError):
            subject.descriptor_rows(Mutated(self.image), rels)

    def test_parameter_shape_and_empty_array_normalization(self):
        constants = subject.parameter_constants(self.image)
        self.assertEqual(constants, (0x8000000000000001, b'{', b'[]'))
        f = lambda word, data: subject.parameter_shape(word, data, constants)
        self.assertEqual(f(constants[0], b'{anything'), 'sentinel_empty')
        self.assertEqual(f(0, b''), 'positional_empty')
        self.assertEqual(f(0, b'{}'), 'object')
        self.assertEqual(f(0, b'[]'), 'positional_normalized_empty')
        self.assertEqual(f(0, b'[ ]'), 'positional')
        self.assertEqual(f(0, b' {}'), 'positional')
        self.assertEqual(f(0, b'[] '), 'positional')
        with self.assertRaises(ValueError):
            f(-1, b'[]')
        with self.assertRaises(ValueError):
            f(0, '[]')

    def test_positional_address_cursor_and_error_arguments(self):
        c = subject.positional_constants(self.image)
        self.assertEqual((c['comma'], c['open'], c['close']), (44, 91, 93))
        self.assertEqual(c['continuation_upper'], 0xc0)
        self.assertEqual([i for i in range(64) if (c['whitespace_mask'] >> i) & 1],
                         [9, 10, 13, 32])
        self.assertEqual((c['error_title'], c['error_body'], c['title_length'], c['error_code_i32']),
                         ('Invalid params', 'No more params', 14, -32602))
        self.assertEqual(subject.decode_transfer(0x2d0f9d3, self.image.read(0x2d0f9d3, 5, executable=True)),
                         ('call', 0x1d6b370))
        self.assertEqual(subject.decode_transfer(0x1d6b3f7, self.image.read(0x1d6b3f7, 5, executable=True)),
                         ('call', 0x298d2f0))

    def test_positional_cursor_conditional_branches(self):
        c = subject.positional_constants(self.image)
        f = lambda data: subject.positional_model(data, c)
        for raw, expected in ((b'', 'no_more_params'),
                              (b']extra', 'closing_delimiter_no_more_params'),
                              (b'[ \t\r\n', 'nested_empty_no_more_params'),
                              (b'["x"', 'nested_address_composite'),
                              (b', [', 'nested_address_composite'),
                              (b'[0', 'nested_address_other'),
                              (b' [', 'unexpected_delimiter_formatter'),
                              (b'[\x7f', 'nested_address_other'),
                              (b'[\x80', 'slice_boundary_helper'),
                              (b'[\xbf', 'slice_boundary_helper'),
                              (b'[\xc0', 'nested_address_other')):
            with self.subTest(raw=raw):
                self.assertEqual(f(raw), expected)
        with self.assertRaises(ValueError):
            f('[')

    def test_positional_immediates_reject_corruption(self):
        class Changed:
            def __init__(self, base, address):
                self.base, self.address = base, address
            def read(self, va, size, **kwargs):
                raw = bytearray(self.base.read(va, size, **kwargs))
                if va <= self.address < va + size:
                    raw[self.address - va] ^= 1
                return bytes(raw)
        for address in (0x2d0f92e, 0x2d0f95e, 0x1d6b393, 0x2d0fb89,
                        0x2d0fb97, 0x2d0fbce, 0x6167a1):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                subject.positional_constants(Changed(self.image, address))

    def test_field_names_from_immediates(self):
        self.assertEqual(self.names, (b'address', b'blockId', b'block_id'))
        self.assertEqual(subject.classify_field(b'address', self.names), 'address')
        self.assertEqual(subject.classify_field(b'blockId', self.names), 'block')
        self.assertEqual(subject.classify_field(b'block_id', self.names), 'block')
        for v in (b'Address', b'blockid', b'block-id', b'address\x00', b''):
            self.assertEqual(subject.classify_field(v, self.names), 'other')

    def test_field_name_single_byte_negative_controls(self):
        for name in self.names:
            for i, original in enumerate(name):
                for replacement in range(256):
                    if original != replacement:
                        other = name[:i] + bytes([replacement]) + name[i+1:]
                        self.assertEqual(subject.classify_field(other, self.names), 'other')

    def test_conditional_field_flows(self):
        f = lambda *names: subject.field_flow(names, self.names)
        self.assertEqual(f(), 'missing_address')
        self.assertEqual(f(b'blockId'), 'missing_address')
        self.assertEqual(f(b'address'), 'address_default_block')
        self.assertEqual(f(b'other', b'address', b'blockId'), 'address_and_block')
        self.assertEqual(f(b'block_id', b'address'), 'address_and_block')
        self.assertEqual(f(b'address', b'address'), 'duplicate_address')
        self.assertEqual(f(b'blockId', b'address', b'block_id'), 'duplicate_block')
        self.assertEqual(f(b'block_id', b'blockId'), 'duplicate_block')

    def test_callback_copies_address_and_block_pointer(self):
        arg_window = dict((name, bytes.fromhex(raw)) for name, _, raw in subject.WINDOWS)['adapter_input']
        self.assertIn(bytes.fromhex('488d9424e0000000'), arg_window)
        self.assertIn(bytes.fromhex('488d8c24b0000000'), arg_window)
        handler_prefix = self.image.read(0x2a2b8a1, 22, executable=True)
        self.assertEqual(handler_prefix, bytes.fromhex('4889fb4c8ba6d8030000498d442410488d0d2774bdfd'))
        self.assertEqual(subject.decode_lea(0x2a2b8b0, handler_prefix[-7:]), 0x602cde)

    def test_callback_hands_selected_result_to_response_boundary(self):
        windows = {name: bytes.fromhex(raw) for name, _, raw in subject.WINDOWS}
        handoff = windows['response_handoff']
        self.assertIn(bytes.fromhex('4889ac2420010000'), handoff)
        self.assertIn(bytes.fromhex('0f11842430010000'), handoff)
        self.assertIn(bytes.fromhex('0f118c2440010000'), handoff)
        self.assertIn(bytes.fromhex('488d942410010000'), handoff)
        self.assertEqual(subject.decode_transfer(0x2d00d04, handoff[-5:]), ('call', 0x22d02d0))
        self.assertIn(bytes.fromhex('410f1107'), windows['response_output_copy'])

    def test_address_array_dispatch_and_twenty_stores(self):
        dispatch = subject.address_dispatch(self.image)
        self.assertEqual(len(dispatch), 33)
        self.assertEqual(next(row[-1] for row in dispatch if row[0] == '0x5b'), '0x298d3e7')
        records = subject.selected_array_elements(self.image)
        self.assertEqual([row[0] for row in records], list(range(20)))
        self.assertEqual([row[-1] for row in records], list(range(20)))
        stores = subject.array_output_stores(self.image)
        self.assertEqual([row[-1] for row in stores], list(range(1, 21)))
        self.assertEqual([row[5] for row in stores[5:]], [hex(i) for i in range(0x2f, 0x20, -1)])

    def test_array_probe_models_boundary_cases(self):
        present = ['present'] * 20
        self.assertEqual(subject.array_model(present, 'absent'), ('success', None))
        self.assertEqual(subject.array_model(present, 'present'), ('length_argument', 21))
        self.assertEqual(subject.array_model(present, 'error'), ('success_after_cleanup', None))
        for i in range(20):
            states = present.copy()
            states[i] = 'absent'
            self.assertEqual(subject.array_model(states, 'absent'), ('length_argument', i))
            states[i] = 'error'
            self.assertEqual(subject.array_model(states, 'absent'), ('propagate_element_error', i))
        with self.assertRaises(ValueError):
            subject.array_model(present[:-1], 'absent')
        with self.assertRaises(ValueError):
            subject.array_model(present, 'unknown')
        with self.assertRaises(ValueError):
            subject.array_model(['unknown'] + present[1:], 'absent')

    def test_array_element_branch_and_store_corruption(self):
        class Changed:
            def __init__(self, base, address):
                self.base, self.address = base, address
            def read(self, va, size, **kwargs):
                raw = bytearray(self.base.read(va, size, **kwargs))
                if va <= self.address < va + size:
                    raw[self.address - va] ^= 1
                return bytes(raw)
            def offset(self, *args, **kwargs):
                return self.base.offset(*args, **kwargs)
        for call, guard in subject.ARRAY_ELEMENTS:
            for address in (call + 1, guard - 1, guard + 2):
                with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                    subject.selected_array_elements(Changed(self.image, address))
        for row in subject.array_output_stores(self.image):
            address = int(row[1], 16)
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                subject.array_output_stores(Changed(self.image, address))
        with self.assertRaises(ValueError):
            subject.address_dispatch(Changed(self.image, 0x600524))

    def test_twenty_byte_fixed_decoder_width(self):
        self.assertEqual(self.image.read(0x298d513, 6, executable=True), bytes.fromhex('41b814000000'))
        self.assertEqual(subject.decode_transfer(0x298d519, self.image.read(0x298d519, 6, executable=True)),
                         ('indirect', 0x64e1e48))
        self.assertEqual(subject.RELATIVE_SLOTS[0x64e1e48], 0x167a9c0)

    def test_guard_constants_and_boundary_cases(self):
        self.assertEqual(self.guard, (8, (1 << 64) - 16, 16, (1 << 64) - 14, 18))
        self.assertEqual(subject.acquire_model(0, True, self.guard), ('fast', 16))
        self.assertEqual(subject.acquire_model(7, True, self.guard), ('fast', 23))
        self.assertEqual(subject.acquire_model(8, True, self.guard), ('slow', None))
        self.assertEqual(subject.acquire_model(16, False, self.guard), ('slow', None))
        self.assertEqual(subject.acquire_model((1 << 64) - 25, True, self.guard),
                         ('fast', (1 << 64) - 9))
        self.assertEqual(subject.acquire_model((1 << 64) - 16, True, self.guard), ('slow', None))
        self.assertEqual(subject.acquire_model((1 << 64) - 1, True, self.guard), ('slow', None))
        for invalid in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.acquire_model(invalid, True, self.guard)
        with self.assertRaises(ValueError):
            subject.acquire_model(1, 1, self.guard)

    def test_guard_release_wake_and_underflow(self):
        self.assertEqual(subject.release_model(18, self.guard), (2, True))
        self.assertEqual(subject.release_model(19, self.guard), (3, True))
        self.assertEqual(subject.release_model(26, self.guard), (10, True))
        self.assertEqual(subject.release_model(16, self.guard), (0, False))
        self.assertEqual(subject.release_model(0, self.guard), ((1 << 64) - 16, False))
        with self.assertRaises(ValueError):
            subject.release_model(-1, self.guard)

    def test_selected_state_layout_and_corruption(self):
        layout = subject.selected_layout(self.image)
        self.assertEqual(layout['account_guard_context_offset'], 0x6a8)
        self.assertEqual(layout['account_state_base_context_offset'], 0xb00)
        self.assertEqual(layout['account_state_inner_offset'], 0x1c98)
        self.assertEqual(layout['metric_gate_context_offset'], 0x128)
        self.assertEqual(layout['metric_gate_constant'], 1000000000)
        self.assertEqual(layout['metric_object_context_offset'], 0x28)
        self.assertEqual(layout['metric_count_entry_end_offset_signed'], -0x18)
        self.assertEqual(layout['metric_sum_entry_end_offset_signed'], -0x10)
        self.assertEqual(layout['metric_max_entry_end_offset_signed'], -0x08)
        class Changed:
            def read(self, va, size, **kwargs):
                raw = bytearray(BalanceEvidenceTests.image.read(va, size, **kwargs))
                if va <= 0x477211f < va + size:
                    raw[0x477211f - va] ^= 1
                return bytes(raw)
        with self.assertRaises(ValueError):
            subject.selected_layout(Changed())

    def test_conditional_metric_count_saturates(self):
        self.assertEqual(subject.metric_count_model(0), 1)
        self.assertEqual(subject.metric_count_model(10), 11)
        self.assertEqual(subject.metric_count_model((1 << 64) - 2), (1 << 64) - 1)
        self.assertEqual(subject.metric_count_model((1 << 64) - 1), (1 << 64) - 1)
        for invalid in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                subject.metric_count_model(invalid)

    def test_metric_call_relocation_and_scalar_writes(self):
        rels = subject.selected_relocations(self.data, self.image.section('.rela.dyn'), subject.RELATIVE_SLOTS)
        self.assertEqual(rels[0x64e7058][2], 0x4771f70)
        self.assertEqual(subject.decode_transfer(0x2a3e9dd, self.image.read(0x2a3e9dd, 6, executable=True)),
                         ('indirect', 0x64e7058))
        self.assertEqual(self.image.read(0x477210e, 18, executable=True),
                         bytes.fromhex('48ffc648c7c2ffffffff480f45d6488951e8'))
        self.assertEqual(self.image.read(0x477213d, 9, executable=True),
                         bytes.fromhex('f20f5fc3f20f1141f8'))

    def test_selected_result_tags_and_cleanup(self):
        payload = bytes(range(32))
        self.assertEqual(subject.outcome_model(1, 4, 1, payload), ('copy', 'none', payload))
        self.assertEqual(subject.outcome_model(0, 4, 1, payload), ('zero', 'none', bytes(32)))
        self.assertEqual(subject.outcome_model(2, 1, 1, payload), ('zero', 'none', bytes(32)))
        self.assertEqual(subject.outcome_model(2, 2, 1, payload), ('zero', 'indirect_drop', bytes(32)))
        self.assertEqual(subject.outcome_model(2, 3, 0, payload), ('zero', 'none', bytes(32)))
        self.assertEqual(subject.outcome_model(2, 3, 1, payload), ('zero', 'deallocate', bytes(32)))
        for tag, length in ((3, 32), (-1, 32), (1, 31), (2, 33)):
            with self.subTest(tag=tag, length=length), self.assertRaises(ValueError):
                subject.outcome_model(tag, 0, 0, bytes(length))
        with self.assertRaises(ValueError):
            subject.outcome_model(2, -1, 0, payload)
        with self.assertRaises(ValueError):
            subject.outcome_model(2, 2, 0, payload)

    def test_fork_tokens_are_file_backed(self):
        rows = subject.find_fork_tokens(self.image)
        self.assertEqual(len(rows), 43)
        for token, va, offset, raw in rows:
            self.assertEqual(self.image.offset(int(va, 16), len(token)), int(offset, 16))
            self.assertEqual(bytes.fromhex(raw), token.encode('ascii'))

    def test_public_input_hashes(self):
        manifest = (subject.ROOT / 'upstream/hyper-evm-sync/Cargo.toml').read_bytes()
        lock = (subject.ROOT / 'upstream/hyper-evm-sync/Cargo.lock').read_bytes()
        self.assertEqual(subject.digest(manifest), subject.SYNC_TOML_SHA256)
        self.assertEqual(subject.digest(lock), subject.SYNC_LOCK_SHA256)
        with self.assertRaises(ValueError):
            subject.authenticate(manifest + b'\n', subject.SYNC_TOML_SHA256)
        self.assertEqual(subject.public_fork_context()['manifest_dependencies']['revm']['version'], '=19.2.0')

    def test_output_inventory_and_synthetic_counts(self):
        self.assertEqual(len(self.files), 27)
        self.assertEqual(self.summary['selected_fde_count'], 15)
        self.assertEqual(self.summary['selected_lsda_headers'], 13)
        self.assertEqual(self.summary['selected_lsda_call_sites'], 95)
        self.assertEqual(self.summary['selected_window_count'], 105)
        self.assertEqual(self.summary['selected_transfer_count'], 179)
        self.assertEqual(self.summary['positional_cursor_vectors'], 19)
        self.assertEqual(self.summary['field_name_vectors'], 5613)
        self.assertEqual(self.summary['field_flow_vectors'], 341)
        self.assertEqual(self.summary['guard_vectors'], 38)
        self.assertEqual(self.summary['result_tag_vectors'], 58)
        self.assertEqual(self.summary['array_element_count'], 20)
        self.assertEqual(self.summary['array_output_store_count'], 20)
        self.assertEqual(self.summary['array_case_vectors'], 43)
        self.assertEqual(self.summary['address_dispatch_entries'], 33)
        self.assertEqual(self.summary['parameter_shape_vectors'], 18)
        self.assertEqual(self.summary['descriptor_slots'], 6)
        self.assertEqual(self.summary['metric_count_vectors'], 6)
        self.assertEqual(self.summary['element_wrapper_vectors'], 8)
        self.assertEqual(self.summary['selected_relative_relocation_count'], 21)
        for name, value in self.files.items():
            self.assertFalse(name.startswith('/'))
            self.assertTrue(value.endswith(b'\n'), name)


if __name__ == '__main__':
    unittest.main()
