# SPDX-License-Identifier: MIT
"""Target-grounded controls for selected state-root serialization evidence."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_root_tree115 as tree


class RootTreeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The acceptance environment contains the authenticated target.  A
        # missing target is a test error, not a skip.
        cls.data = tree.TARGET.read_bytes()
        cls.secs = tree.sections(cls.data)
        cls.evidence = tree.collect(cls.data)
        cls.constants = cls.evidence['constants']
        cls.fdes = cls.evidence['fdes']

    def changed(self, va, size=1):
        data = bytearray(self.data)
        off = tree.mapping(self.secs, va, size)
        data[off] ^= 1
        return data

    def test_target_identity_and_selected_inventory(self):
        self.assertEqual(tree.authenticate(self.data), tree.TARGET_SHA)
        self.assertEqual(len(self.fdes), 18)
        self.assertEqual(len(self.evidence['transfers']), len(tree.TRANSFERS))
        self.assertEqual(len(self.evidence['windows']), len(tree.WINDOWS))
        self.assertEqual(self.evidence['location']['line'], 123)
        self.assertEqual(self.evidence['location']['column'], 37)

    def test_bad_and_missing_digest_fail_before_emission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination, candidate = root / 'out', root / 'candidate'
            candidate.write_bytes(b'corrupt target')
            with mock.patch.object(tree, 'TARGET', candidate):
                with self.assertRaises(ValueError):
                    tree.main(['--out', str(destination)])
            self.assertFalse(destination.exists())
            candidate.unlink()
            with mock.patch.object(tree, 'TARGET', candidate):
                with self.assertRaises(OSError):
                    tree.main(['--out', str(destination)])
            self.assertFalse(destination.exists())
        with self.assertRaises(ValueError):
            tree.authenticate(b'')
        with self.assertRaises(ValueError):
            tree.historical_check(b'not the historical target')

    def test_corruption_in_each_selected_function_is_rejected(self):
        mutable = bytearray(self.data)
        for fde in self.fdes:
            off = fde['file_offset']
            with self.subTest(role=fde['role']):
                mutable[off] ^= 1
                with self.assertRaises(ValueError):
                    tree.validate_body(mutable, self.secs, fde['start'], fde['end'], fde['body_sha256'])
                mutable[off] ^= 1
        del mutable

    def test_context_corruption_is_not_accepted_as_a_new_boundary(self):
        mutable = bytearray(self.data)
        for va in (0x41c5233, 0x2eabb70, 0x2eabc29, 0x41c61f2, 0x41c643a, 0x4dd49ba):
            with self.subTest(va=hex(va)):
                off = tree.mapping(self.secs, va, 1)
                mutable[off] ^= 1
                with self.assertRaisesRegex(ValueError, 'context boundary'):
                    tree.selected_windows(mutable, self.secs, self.fdes)
                mutable[off] ^= 1

    def test_every_selected_displacement_detects_corruption(self):
        mutable = bytearray(self.data)
        for row in self.evidence['transfers']:
            va = row['va']
            raw = bytes.fromhex(row['bytes'])
            off = tree.mapping(self.secs, va, len(raw), True) + len(raw) - 1
            with self.subTest(label=row['label']):
                mutable[off] ^= 1
                with self.assertRaises(ValueError):
                    tree.validate_transfer(mutable, self.secs, va, row['target'])
                mutable[off] ^= 1
        del mutable

    def test_wrong_transfer_kind_and_out_of_bounds_rejected(self):
        with self.assertRaises(ValueError):
            tree.decode_transfer(self.data, self.secs, 0x41444a0)
        with self.assertRaises(ValueError):
            tree.decode_transfer(self.data, self.secs, (1 << 64) - 1)

    def test_unwind_extent_corruption_is_rejected(self):
        fde = next(f for f in self.fdes if f['role'] == 'array_writer')
        mutable = bytearray(self.data)
        off = tree.mapping(self.secs, fde['fde'], 16)
        mutable[off + 12] ^= 1
        with self.assertRaises(ValueError):
            tree.selected_fdes(mutable, self.secs)

    def test_unwind_index_fde_pointer_corruption_is_rejected(self):
        _, table = tree.unwind_index(self.data)
        selected = next(row for row in table if row['start'] == 0x41444a0)
        header = tree.one_section(self.secs, '.eh_frame_hdr')
        offset = header['offset'] + 12 + selected['index'] * 8 + 4
        mutable = bytearray(self.data)
        mutable[offset] ^= 1
        with self.assertRaises(ValueError):
            tree.selected_fdes(mutable, self.secs)

    def test_lsda_header_corruption_is_rejected(self):
        fde = next(f for f in self.fdes if f['role'] == 'pair_writer')
        self.assertTrue(tree.lsda_call_sites(self.data, self.secs, fde))
        mutable = self.changed(fde['lsda'])
        with self.assertRaises(ValueError):
            tree.lsda_call_sites(mutable, self.secs, fde)

    def test_lsda_witnesses_preserve_known_landings(self):
        rows = {x['label']: x for x in self.evidence['witnesses']}
        self.assertEqual(rows['array_pair']['landing_va'], 0x41446fc)
        self.assertEqual(rows['pair_index']['landing_va'], 0x41c7af8)
        self.assertEqual(rows['pair_finish_alt_header']['landing_va'], 0x41d4126)
        self.assertEqual(rows['index_direct_write']['coverage'], 'no_lsda')

    def test_fileless_outside_and_ambiguous_mappings_fail(self):
        fake = {'name': '.bss', 'type': 8, 'flags': 6, 'address': 0x5000,
                'offset': 0, 'size': 16}
        with self.assertRaises(ValueError):
            tree.mapping([fake], 0x5000, 1)
        file_backed = dict(fake, type=1)
        with self.assertRaises(ValueError):
            tree.mapping([file_backed, file_backed.copy()], 0x5000, 1)
        with self.assertRaises(ValueError):
            tree.mapping(self.secs, -1, 1)
        with self.assertRaises(ValueError):
            tree.mapping(self.secs, 0x41444a0, 0)
        with self.assertRaises(ValueError):
            tree.mapping(self.secs, (1 << 64) - 1, 2)

    def test_location_record_and_pointer_are_checked(self):
        data = self.changed(0x64767a8 + 16)
        with self.assertRaises(ValueError):
            tree.location(data, self.secs)
        location = self.evidence['location']
        self.assertEqual(location['va'], '0x64767a8')
        self.assertEqual(location['path'], 'l1/src/abci/state.rs')
        self.assertEqual(location['relocation']['addend_va'], '0x443168')

    def test_relocation_type_and_duplicate_slot_are_rejected(self):
        slot = 0x64e4d08
        record = tree.find_relocation(self.data, self.secs, slot)
        mutable = bytearray(self.data)
        offset = int(record['record_file_offset'], 16)
        mutable[offset + 8] ^= 1
        with self.assertRaises(ValueError):
            tree.find_relocation(mutable, self.secs, slot)
        rel = struct.pack('<QQq', slot, 8, 0x2eabb50)
        fake_secs = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 48}]
        with self.assertRaises(ValueError):
            tree.find_relocation(rel + rel, fake_secs, slot)

    def test_existing_reducer_and_digest_bindings_are_rechecked(self):
        boundaries = tree.boundary_relocations(self.data, self.secs)
        self.assertEqual(boundaries['reducer']['addend_va'], '0x141a250')
        self.assertEqual(boundaries['digest']['addend_va'], '0x41c5140')
        for name in ('reducer', 'digest', 'formatter'):
            with self.subTest(name=name):
                mutable = bytearray(self.data)
                off = int(boundaries[name]['record_file_offset'], 16)
                mutable[off + 16] ^= 1
                with self.assertRaises(ValueError):
                    tree.boundary_relocations(mutable, self.secs)

    def test_extracted_markers_and_sentinels(self):
        c = self.constants
        self.assertEqual((c['array_fix_base'], c['array16_marker'], c['array32_marker']), (0x90, 0xdc, 0xdd))
        self.assertEqual((c['array_fix_limit'], c['array16_limit'], c['root_capture_slots']), (16, 65536, 59))
        self.assertEqual((c['pair_marker'], c['string_marker']), (0x92, 0xd9))
        self.assertEqual((c['uint8_marker'], c['uint16_marker'], c['uint32_marker'], c['uint64_marker']),
                         (0xcc, 0xcd, 0xce, 0xcf))
        self.assertEqual((c['leaf_bytes'], c['formatted_length'], c['row_stride']), (32, 66, 48))
        self.assertEqual(c['sentinel'] + c['success_delta'], 0x8000000000000004)

    def test_marker_and_alphabet_corruption_fail_closed(self):
        with self.assertRaises(ValueError):
            tree.extracted_constants(self.changed(0x41c7875), self.secs)
        with self.assertRaises(ValueError):
            tree.extracted_constants(self.changed(0x455d40), self.secs)

    def test_wrong_historical_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            historical, destination = root / 'old', root / 'out'
            historical.write_bytes(b'wrong historic target')
            with self.assertRaises(ValueError):
                tree.main(['--historical', str(historical), '--out', str(destination)])
            self.assertFalse(destination.exists())

    def test_array_header_boundaries(self):
        examples = {0: '90', 2: '92', 15: '9f', 16: 'dc0010',
                    59: 'dc003b', 65535: 'dcffff', 65536: 'dd00010000',
                    0xffffffff: 'ddffffffff'}
        for count, expected in examples.items():
            with self.subTest(count=count):
                self.assertEqual(tree.array_header(count, self.constants).hex(), expected)
        for bad in (-1, 1 << 32, True):
            with self.subTest(count=bad), self.assertRaises(ValueError):
                tree.array_header(bad, self.constants)

    def test_unsigned_index_boundaries_and_endianness(self):
        examples = {0: '00', 127: '7f', 128: 'cc80', 255: 'ccff',
                    256: 'cd0100', 65535: 'cdffff', 65536: 'ce00010000',
                    0xffffffff: 'ceffffffff', 0x100000000: 'cf0000000100000000',
                    0xffffffffffffffff: 'cfffffffffffffffff'}
        for value, expected in examples.items():
            with self.subTest(value=value):
                self.assertEqual(tree.unsigned(value, self.constants).hex(), expected)
        for bad in (-1, 1 << 64, True):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                tree.unsigned(bad, self.constants)

    def test_captured_root_indices_do_not_use_the_cc_failure_example(self):
        # Conditional on the prior capture's unchanged 59-slot length, only a
        # nested or different input can reach the selected 128..255 case.
        count = self.constants['root_capture_slots']
        self.assertEqual(count, 59)
        for index in range(count):
            with self.subTest(index=index):
                self.assertEqual(tree.unsigned(index, self.constants), bytes([index]))
        self.assertEqual(tree.unsigned(128, self.constants), bytes.fromhex('cc80'))

    def test_synthetic_empty_one_leaf_and_nested_preimages(self):
        zero = bytes(32)
        high = bytes([0xf0]) * 32
        self.assertEqual(tree.tree_preimage([], self.constants), b'\x90')
        one = b'\x91\x92\x00\xd9\x42' + b'0x' + b'00' * 32
        self.assertEqual(tree.tree_preimage([(0, zero)], self.constants), one)
        nested = (b'\x92\x92\x01\x91\x92\x02\xd9\x42' + b'0x' + b'f0' * 32
                  + b'\x92\x07\xd9\x42' + b'0x' + b'00' * 32)
        self.assertEqual(tree.tree_preimage([(1, [(2, high)]), (7, zero)], self.constants), nested)

    def test_synthetic_order_and_sparse_indexes_are_preserved(self):
        a, b = bytes(32), bytes([1]) * 32
        forward = tree.tree_preimage([(0, a), (7, b)], self.constants)
        reversed_rows = tree.tree_preimage([(7, b), (0, a)], self.constants)
        self.assertNotEqual(forward, reversed_rows)
        self.assertTrue(forward.startswith(bytes.fromhex('929200d942')))
        self.assertIn(bytes.fromhex('9207d942'), forward)

    def test_synthetic_tree_rejects_malformed_values_and_cycles(self):
        for rows in [[(0, bytes(31))], [(0, bytes(33))], [(-1, bytes(32))],
                     [(1 << 64, bytes(32))], [('bad', bytes(32))], [(0, None)], [[0, bytes(32)]]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                tree.tree_preimage(rows, self.constants)
        cycle = []
        cycle.append((0, cycle))
        with self.assertRaises(ValueError):
            tree.tree_preimage(cycle, self.constants)

    def test_buffered_normal_markers_match_direct_path(self):
        # These windows belong to a distinct, target-backed writer family.
        # They are checked independently of the Python encoding model.
        expected = {
            0x3d51458: '4881fa00010000', 0x3d514ac: '42c6040fcd',
            0x3d514b8: '66c1c208', 0x3d51508: '42c6040fce',
            0x3d51514: '0fca', 0x3d51554: '42c60409cc',
            0x3d5159a: '42c6040fcf', 0x3d515a6: '480fca',
            0x41c66a9: '42c60427d9', 0x41b935e: 'c6043092',
            0x41772fc: '4983c430',
        }
        for va, raw in expected.items():
            with self.subTest(va=hex(va)):
                tree.exact(self.data, self.secs, va, bytes.fromhex(raw))
                self.assertNotEqual(tree.read_va(self.changed(va), self.secs, va, len(bytes.fromhex(raw)), True).hex(), raw)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x4177272)[1], 0x3d50540)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x41772e9)[1], 0x41b9330)

    def test_direct_and_buffered_tag_checks_are_not_conflated(self):
        c = self.constants
        for buffered in (False, True):
            self.assertEqual(tree.child_kind(0, buffered, c), 'leaf')
            self.assertEqual(tree.child_kind(1, buffered, c), 'nested')
        self.assertEqual(tree.child_kind(2, False, c), 'nested')
        self.assertEqual(tree.child_kind(2, True, c), 'leaf')
        with self.assertRaises(ValueError):
            tree.child_kind(256, False, c)

    def test_partial_writer_failure_has_selected_return_chain(self):
        # The marker and cursor write precede the realloc call and its failure
        # edge.  This is a control-flow observation, not a runtime trace.
        tree.exact(self.data, self.secs, 0x3d51925, bytes.fromhex('c60430cc'))
        tree.exact(self.data, self.secs, 0x3d51934, bytes.fromhex('49897610'))
        for site, target in ((0x3d519a5, 0x3d5194c), (0x41d2752, 0x41d275a),
                             (0x41c785b, 0x41c78c5), (0x4144696, 0x414457a),
                             (0x41c51b7, 0x41c5233)):
            with self.subTest(site=hex(site)):
                self.assertEqual(tree.decode_transfer(self.data, self.secs, site)[1], target)
        tree.exact(self.data, self.secs, 0x41c526c, bytes.fromhex('0f57c00f1143100f1103'))

    def test_existing_end_handoff_is_a_contextual_boundary(self):
        # The already studied caller passes the output buffer onward without
        # a conditional transfer between these two call sites.
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x5a0882e)[1], 0x548d8c0)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x5a08845)[1], 0x5a03fa0)
        tree.exact(self.data, self.secs, 0x5a08833,
                   bytes.fromhex('498dbe00040000488d9424300100004c89fe'))

    def test_history_insert_binds_key_value_and_node_writes(self):
        # This checks actual instruction windows and displacements.  The
        # 0..count index condition and no-alias assumptions remain explicit.
        c = self.constants
        self.assertEqual((c['history_nonfull_cutoff'], c['history_node_count_offset'],
                          c['history_node_keys_offset'], c['history_value_shift']),
                         (11, 0x1c2, 0x168, 5))
        self.assertEqual(c['history_empty_allocation'], 0x1c8)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x4dd49ba)[1], 0x51f32f0)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x51f3338)[1], 0x4c5f1b0)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x4c5f1d9)[1], 0x4c5f1fb)
        self.assertEqual(tree.decode_transfer(self.data, self.secs, 0x4c5f1f1)[1], 0x4c5f228)
        for va, encoded in ((0x4c5f1f3, '488928'),
                            (0x4c5f261, '498984ed68010000'),
                            (0x4c5f2a0, '410f100424410f104c2410'),
                            (0x4c5f2ab, '410f114c0510410f11440500'),
                            (0x4c5f2b7, '6641899dc2010000'),
                            (0x51f33c5, '49ff442410')):
            with self.subTest(va=hex(va)):
                tree.exact(self.data, self.secs, va, bytes.fromhex(encoded))

    def test_history_move_binding_and_allocation_failure_controls(self):
        binding = tree.dynamic_binding(self.data, self.secs, 0x64df568, 'memmove')
        self.assertEqual(binding['symbol'], 'memmove')
        for site in (0x4c5f256, 0x4c5f289):
            self.assertEqual(tree.decode_transfer(self.data, self.secs, site)[1], 0x64df568)
        for site, target in ((0x51f3362, 0x51f33eb), (0x51f33f5, 0x64df490),
                             (0x4c5f323, 0x4c5fcfb), (0x4c5fd05, 0x64df490)):
            with self.subTest(site=hex(site)):
                self.assertEqual(tree.decode_transfer(self.data, self.secs, site)[1], target)
        mutable = bytearray(self.data)
        name = int(binding['name_file_offset'], 16)
        mutable[name] ^= 1
        with self.assertRaises(ValueError):
            tree.dynamic_binding(mutable, self.secs, 0x64df568, 'memmove')
        mutable[name] ^= 1
        relocation = int(binding['record_file_offset'], 16)
        mutable[relocation + 8] ^= 1
        with self.assertRaises(ValueError):
            tree.dynamic_binding(mutable, self.secs, 0x64df568, 'memmove')

    def test_two_emissions_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / 'one', Path(tmp) / 'two'
            tree.emit(first, self.evidence)
            tree.emit(second, self.evidence)
            expected = {'functions.json', 'constants.json', 'windows.tsv', 'transfers.tsv',
                        'lsda.tsv', 'unwind-witnesses.tsv', 'summary.json'}
            self.assertEqual({p.name for p in first.iterdir()}, expected)
            self.assertEqual({p.name for p in second.iterdir()}, expected)
            for name in sorted(expected):
                with self.subTest(name=name):
                    a, b = (first / name).read_bytes(), (second / name).read_bytes()
                    self.assertEqual(a, b)
                    self.assertEqual(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
            summary = json.loads((first / 'summary.json').read_text())
            self.assertEqual(summary['target_sha256'], tree.TARGET_SHA)


if __name__ == '__main__':
    unittest.main()
