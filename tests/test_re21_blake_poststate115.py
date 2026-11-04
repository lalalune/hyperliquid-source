import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re21_blake_poststate115 as packet
from elf_index import sections


class PostStateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.sec = sections(cls.data)
        cls.files = packet.collect(cls.data)
        cls.constants = {}
        for label, address, expected in packet.LITERALS:
            cls.constants[label] = packet.match_window(cls.data, cls.sec, address, bytes.fromhex(expected))[0]

    def test_digest_and_historical_negative_controls(self):
        packet.authenticate(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.authenticate(self.data[:4096])
        with self.assertRaisesRegex(ValueError, 'historical target SHA-256'):
            packet.cross_release_check(self.data, b'not the historical binary')

    def test_selected_ranges_and_unwind_records(self):
        rows = json.loads(self.files['functions.json'])
        self.assertEqual(len(rows), 11)
        self.assertEqual(sum(x['byte_count'] for x in rows), 7519)
        self.assertEqual(len({x['start_va'] for x in rows}), 11)
        self.assertEqual(next(x['end_va'] for x in rows if x['start_va'] == '0x29714f0'), '0x2971759')
        self.assertTrue(all(x['fde_hex'] and x['cie_hex'] and x['section'] == '.text' for x in rows))

    def test_missing_and_duplicate_fde_fail_closed(self):
        target = packet.FUNCTIONS[0][1]
        fake = {'start': target, 'end': packet.FUNCTIONS[0][2], 'fde': 1, 'cie': 2, 'lsda': None}
        with mock.patch.object(packet, 'eh_frame_records', return_value=({}, [])):
            with self.assertRaisesRegex(ValueError, 'missing selected FDE'):
                packet.selected_frames(b'', [])
        with mock.patch.object(packet, 'eh_frame_records', return_value=({}, [fake, fake])):
            with self.assertRaisesRegex(ValueError, 'duplicate or changed'):
                packet.selected_frames(b'', [])
        wrong = dict(fake, end=fake['end'] + 1)
        with mock.patch.object(packet, 'eh_frame_records', return_value=({}, [wrong])):
            with self.assertRaisesRegex(ValueError, 'duplicate or changed'):
                packet.selected_frames(b'', [])

    def test_file_backed_mapping_rejects_nobits_crossing_and_ambiguity(self):
        raw = b'abcd'
        good = {'name': '.test', 'type': 1, 'size': 4, 'address': 0x1000, 'offset': 0}
        self.assertEqual(packet.read_va(raw, [good], 0x1001, 2)[0], b'bc')
        with self.assertRaises(ValueError):
            packet.read_va(raw, [dict(good, type=8)], 0x1000, 1)
        with self.assertRaises(ValueError):
            packet.read_va(raw, [good], 0x1003, 2)
        with self.assertRaises(ValueError):
            packet.read_va(raw, [good, dict(good)], 0x1000, 1)
        with self.assertRaises(ValueError):
            packet.read_va(raw, [good], 0x1000, 0)
        with self.assertRaises(ValueError):
            packet.read_va(raw, [good], -1, 1)
        with self.assertRaises(ValueError):
            packet.read_va(raw[:2], [good], 0x1000, 4)

    def test_account_secret_is_runtime_nobits_storage(self):
        record = json.loads(self.files['summary.json'])['account_hash_secret']
        self.assertEqual(record, {'slot_va': '0x64dfa78', 'target_va': '0x64ffe90',
                                  'section': '.bss', 'section_type': 8})
        with self.assertRaisesRegex(ValueError, 'uniquely file-backed'):
            packet.read_va(self.data, self.sec, int(record['target_va'], 16), 1)

    def test_changed_instruction_window_is_rejected(self):
        expected = bytes.fromhex('80bf260100000e')
        sec = [{'name': '.text', 'type': 1, 'size': len(expected), 'address': 0x100, 'offset': 0}]
        self.assertEqual(packet.match_window(expected, sec, 0x100, expected)[0], expected)
        bad = expected[:-1] + bytes([expected[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'changed selected'):
            packet.match_window(bad, sec, 0x100, expected)

    def test_relative_branch_shapes_and_target_tampering(self):
        self.assertEqual(packet.branch_destination(0x100, bytes.fromhex('e803000000'), 'call'), 0x108)
        self.assertEqual(packet.branch_destination(0x100, bytes.fromhex('75fc'), 'jcc'), 0xfe)
        self.assertEqual(packet.branch_destination(0x100, bytes.fromhex('0f8402000000'), 'jcc'), 0x108)
        with self.assertRaises(ValueError):
            packet.branch_destination(0x100, bytes.fromhex('e803000000'), 'jmp')
        with self.assertRaises(ValueError):
            packet.branch_destination(0x100, bytes.fromhex('ff15'), 'call')
        sec = [{'name': '.text', 'type': 1, 'size': 5, 'address': 0x100, 'offset': 0}]
        with self.assertRaisesRegex(ValueError, 'destination'):
            packet.inspect_edge(bytes.fromhex('e804000000'), sec, 0x100, 'call', 0x108)

    def test_rip_reference_shape(self):
        self.assertEqual(packet.rip_destination(0x100, bytes.fromhex('488d0501000000'), bytes.fromhex('488d05')), 0x108)
        with self.assertRaises(ValueError):
            packet.rip_destination(0x100, bytes.fromhex('488d0d01000000'), bytes.fromhex('488d05'))
        with self.assertRaises(ValueError):
            packet.rip_destination(0x100, bytes.fromhex('488d05'), bytes.fromhex('488d05'))

    def test_relative_relocation_corruption_controls(self):
        row = struct.pack('<QQq', 0x1234, 8, 0x5678)
        sec = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24}]
        got = packet.collect_relocations(row, sec, {0x1234: 0x5678})
        self.assertEqual(got[0x1234]['addend_va'], '0x5678')
        for invalid in (struct.pack('<QQq', 0x1234, 7, 0x5678),
                        struct.pack('<QQq', 0x1234, 8, 0x5679)):
            with self.assertRaises(ValueError):
                packet.collect_relocations(invalid, sec, {0x1234: 0x5678})
        with self.assertRaisesRegex(ValueError, 'missing'):
            packet.collect_relocations(row, sec, {0x1235: 0x5678})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            packet.collect_relocations(row + row, [dict(sec[0], size=48)], {0x1234: 0x5678})
        with self.assertRaisesRegex(ValueError, 'truncated'):
            packet.collect_relocations(row, [dict(sec[0], size=25)], {0x1234: 0x5678})

    def test_actual_dynamic_symbol_and_corrupt_name(self):
        found = packet.symbol_relocation(self.data, self.sec, 0x64dfb50, 'memcmp')
        self.assertEqual(found['type'], 6)
        self.assertEqual(found['symbol'], 'memcmp')
        with self.assertRaisesRegex(ValueError, 'symbol'):
            packet.symbol_relocation(self.data, self.sec, 0x64dfb50, 'different')
        with self.assertRaisesRegex(ValueError, 'missing'):
            packet.symbol_relocation(self.data, self.sec, 0x64dfb51, 'memcmp')

    def test_literals_are_target_bytes(self):
        self.assertEqual(self.constants['two_key_topic'].hex(),
                         'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef')
        self.assertEqual(self.constants['one_key_topic'].hex(),
                         'cc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5')
        self.assertEqual(self.constants['emitter'], bytes.fromhex('ff' * 19 + 'fe'))

    def test_status_switch_for_address_09_outcomes(self):
        statuses = json.loads(self.files['status-table.json'])['status_table']
        self.assertEqual(len(statuses), 55)
        rows = {int(x['status'], 16): x for x in statuses}
        self.assertEqual((rows[2]['result_word'], rows[2]['extra_byte']),
                         ('0x8000000000000014', 1))
        self.assertEqual((rows[0x23]['result_word'], rows[0x23]['extra_byte']),
                         ('0x8000000000000000', 3))
        self.assertEqual((rows[0x31]['result_word'], rows[0x31]['extra_byte']),
                         ('0x8000000000000009', None))
        self.assertEqual(rows[5]['kind'], 'ud2')

    def test_status_arm_mutations_and_truncation(self):
        raw = bytes.fromhex('c647080148b800000000000000804883c814488907c3')
        self.assertEqual(packet.decode_status_arm(raw)['result_word'], '0x8000000000000014')
        self.assertEqual(packet.decode_status_arm(bytes.fromhex('0f0b'))['kind'], 'ud2')
        for bad in (b'', raw[:-1], raw[:6] + bytes([1]) + raw[7:], b'\x90' + raw):
            with self.assertRaises(ValueError):
                packet.decode_status_arm(bad)

    def test_status_table_corruption(self):
        fake = [{'name': '.rodata', 'type': 1, 'address': 0x6006ac, 'offset': 0, 'size': 220}]
        with self.assertRaisesRegex(ValueError, 'outside'):
            packet.status_table(bytes(220), fake)

    def test_inspected_status_targets_are_in_selected_fde(self):
        rows = json.loads(self.files['status-table.json'])['status_table']
        self.assertEqual(sum(row['kind'] == 'return' for row in rows), 34)
        self.assertEqual(sum(row['kind'] == 'ud2' for row in rows), 21)
        for row in rows:
            self.assertTrue(0x299c6d0 <= int(row['target_va'], 16) < 0x299c929)

    def test_exception_table_basic_and_landing_bounds(self):
        header, rows = packet.parse_lsda(bytes.fromhex('ffff0104000a0200'), 0x1000, 0x1010)
        self.assertEqual(header['callsite_byte_count'], 4)
        self.assertEqual((rows[0]['start_va'], rows[0]['end_va'], rows[0]['landing_pad_va']),
                         ('0x1000', '0x100a', '0x1002'))
        with self.assertRaisesRegex(ValueError, 'outside FDE'):
            packet.parse_lsda(bytes.fromhex('ffff010400110200'), 0x1000, 0x1010)
        with self.assertRaisesRegex(ValueError, 'landing pad'):
            packet.parse_lsda(bytes.fromhex('ffff0104000a1100'), 0x1000, 0x1010)

    def test_exception_table_bad_encoding_and_truncation(self):
        for raw in (b'', bytes.fromhex('fffe0100'), bytes.fromhex('ffff0280'),
                    bytes.fromhex('ffff0180'), bytes.fromhex('ffff0104000a02'),
                    bytes.fromhex('ff9b7f0100')):
            with self.assertRaises(ValueError):
                packet.parse_lsda(raw, 0x1000, 0x1010)

    def test_real_callsite_landings(self):
        rows = json.loads(self.files['exceptions.json'])['call_sites']
        def landing(pc):
            values = [r for r in rows if int(r['start_va'], 16) <= pc < int(r['end_va'], 16)]
            self.assertEqual(len(values), 1)
            return values[0]['landing_pad_va']
        self.assertEqual(landing(0x29716ac), '0x2971729')
        self.assertEqual(landing(0x29722ed), '0x297236d')

    def test_two_key_event_payload(self):
        a = bytes.fromhex('01' * 20)
        b = bytes.fromhex('00' * 19 + '09')
        amount = (1 << 192) + (1 << 64) + 3
        event = packet.event_payload('two_key', 14, 0, a, b, amount, self.constants)
        self.assertEqual(event['emitter'], 'ff' * 19 + 'fe')
        self.assertEqual(event['topics'][0], self.constants['two_key_topic'].hex())
        self.assertEqual(event['topics'][1], '00' * 12 + '01' * 20)
        self.assertEqual(event['topics'][2], '00' * 31 + '09')
        self.assertEqual(event['data'], '0000000000000001000000000000000000000000000000010000000000000003')

    def test_one_key_event_payload(self):
        key = bytes.fromhex('ab' * 20)
        event = packet.event_payload('one_key', 255, 0, key, None, 1, self.constants)
        self.assertEqual(len(event['topics']), 2)
        self.assertEqual(event['topics'][0], self.constants['one_key_topic'].hex())
        self.assertEqual(event['topics'][1], '00' * 12 + 'ab' * 20)
        self.assertEqual(event['data'], '00' * 31 + '01')

    def test_event_guard_boundaries(self):
        key = bytes(20)
        self.assertIsNone(packet.event_payload('two_key', 13, 0, key, key, 1, self.constants))
        self.assertIsNotNone(packet.event_payload('two_key', 14, 0, key, key, 1, self.constants))
        self.assertIsNone(packet.event_payload('two_key', 14, 1, key, key, 1, self.constants))
        self.assertIsNone(packet.event_payload('two_key', 14, 0, key, key, 0, self.constants))
        maximum = packet.event_payload('one_key', 14, 0, key, None, (1 << 256) - 1, self.constants)
        self.assertEqual(maximum['data'], 'ff' * 32)

    def test_event_rejects_malformed_inputs(self):
        key = bytes(20)
        for args in [('bad', 14, 0, key, key, 1), ('two_key', 14, 0, key[:-1], key, 1),
                     ('two_key', 14, 0, key, key[:-1], 1), ('one_key', 14, 0, key, None, -1),
                     ('one_key', 14, 0, key, None, 1 << 256), ('one_key', 256, 0, key, None, 1),
                     ('one_key', 14, -1, key, None, 1)]:
            with self.assertRaises(ValueError):
                packet.event_payload(*args, self.constants)
        with self.assertRaises(ValueError):
            packet.event_payload('one_key', 14, 0, key, None, 1, {'one_key_topic': b'x', 'emitter': b'y'})

    def test_row_selection_and_small_sort(self):
        a = (1).to_bytes(20, 'big')
        b = (2).to_bytes(20, 'big')
        c = (3).to_bytes(20, 'big')
        d = (4).to_bytes(20, 'big')
        self.assertEqual(packet.select_small_rows([d, c, b, a], {a: 7, b: 0, c: 2}), [(a, 7), (c, 2)])
        self.assertEqual(packet.select_small_rows([c, c], {c: 2}), [(c, 2), (c, 2)])
        self.assertEqual(packet.select_small_rows([b], {b: 0}), [])

    def test_row_count_boundary_is_after_filter(self):
        keys = [n.to_bytes(20, 'big') for n in range(21)]
        accounts = {k: 1 for k in keys}
        self.assertEqual(len(packet.select_small_rows(keys[:20], accounts)), 20)
        with self.assertRaisesRegex(ValueError, 'large sort'):
            packet.select_small_rows(keys, accounts)
        accounts[keys[-1]] = 0
        self.assertEqual(len(packet.select_small_rows(keys, accounts)), 20)

    def test_large_sort_scratch_boundaries(self):
        self.assertEqual(packet.row_sort_scratch(21), {'requested_rows': 21, 'heap_branch': False,
                                                       'short_sort_flag': True})
        self.assertTrue(packet.row_sort_scratch(64)['short_sort_flag'])
        self.assertFalse(packet.row_sort_scratch(65)['short_sort_flag'])
        self.assertFalse(packet.row_sort_scratch(73)['heap_branch'])
        self.assertTrue(packet.row_sort_scratch(74)['heap_branch'])
        self.assertEqual(packet.row_sort_scratch(0x22e0a)['requested_rows'], 0x22e09)
        for bad in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                packet.row_sort_scratch(bad)

    def test_row_inputs_are_checked(self):
        key = bytes(20)
        for keys, accounts in [([b'bad'], {}), ([key], {key: -1}), ([key], {key: 1 << 256}),
                               ((key,), {}), ([key], [])]:
            with self.assertRaises(ValueError):
                packet.select_small_rows(keys, accounts)

    def test_hash_fold_against_independent_limb_product(self):
        left, right = 0xfedcba9876543210, 0x1020304050607080
        limbs_a = [left & 0xffffffff, left >> 32]
        limbs_b = [right & 0xffffffff, right >> 32]
        cross = sum(limbs_a[i] * limbs_b[j] << (32 * (i + j)) for i in range(2) for j in range(2))
        self.assertEqual(packet.fold64(left, right), (cross & ((1 << 64) - 1)) ^ (cross >> 64))
        self.assertEqual(packet.fold64(0, right), 0)
        with self.assertRaises(ValueError):
            packet.fold64(-1, 1)

    def test_account_hash_is_seed_sensitive_and_validates_key(self):
        key = bytes.fromhex('00' * 19 + '09')
        self.assertNotEqual(packet.account_hash(key, 7, 11), packet.account_hash(key, 8, 11))
        for args in [(b'', 7, 11), (key, -1, 11), (key, 7, 1 << 64)]:
            with self.assertRaises(ValueError):
                packet.account_hash(*args)

    def test_batch_gate_and_reset_boundary(self):
        self.assertFalse(packet.batch_gate(13, 0, 0))
        self.assertTrue(packet.batch_gate(14, 0, 0))
        self.assertFalse(packet.batch_gate(14, 1, 0))
        self.assertFalse(packet.batch_gate(14, 0, 1))
        self.assertEqual(packet.reset_guard(1), ('failure', None))
        self.assertEqual(packet.reset_guard(0), ('store', 0xffffffff))
        self.assertEqual(packet.reset_guard(2), ('store', 1))
        self.assertEqual(packet.reset_guard(0xffffffff), ('store', 0xfffffffe))
        for args in [(-1, 0, 0), (14, 256, 0), (14, 0, True)]:
            with self.assertRaises(ValueError):
                packet.batch_gate(*args)
        for invalid in [-1, 1 << 32, True]:
            with self.assertRaises(ValueError):
                packet.reset_guard(invalid)

    def test_every_key_bit_changes_membership(self):
        key = bytes.fromhex('00' * 19 + '09')
        for bit in range(160):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertEqual(packet.select_small_rows([bytes(changed)], {key: 7}), [])
        self.assertEqual(packet.select_small_rows([key], {key: 7}), [(key, 7)])

    def test_corrupt_real_status_table_cell(self):
        original = packet.read_va
        def corrupted(data, sec, va, size):
            raw, off, name = original(data, sec, va, size)
            if va == 0x6006b0 and size == 4:
                return bytes(4), off, name
            return raw, off, name
        with mock.patch.object(packet, 'read_va', side_effect=corrupted):
            with self.assertRaisesRegex(ValueError, 'status table target'):
                packet.status_table(self.data, self.sec)

    def test_bad_lsda_interval(self):
        with self.assertRaisesRegex(ValueError, 'invalid FDE'):
            packet.parse_lsda(bytes.fromhex('ffff0104000a0200'), 5, 5)
        with self.assertRaisesRegex(ValueError, 'invalid FDE'):
            packet.parse_lsda(bytes.fromhex('ffff0104000a0200'), -1, 10)

    def test_source_descriptors_and_corruption(self):
        locations = json.loads(self.files['source-locations.json'])
        self.assertEqual(len(locations), 1)
        selected = {r['label']: r for r in locations}
        self.assertEqual((selected['reset_guard']['source_suffix'], selected['reset_guard']['line'],
                          selected['reset_guard']['column']), ('z_vendor/revm-state/src/lib.rs', 60, 21))
        suffix = 'z_vendor/revm-state/src/lib.rs'
        source = b'prefix/' + suffix.encode('ascii')
        desc = bytes(8) + struct.pack('<QII', len(source), 60, 21)
        self.assertEqual(packet.decode_source_location(desc, source, suffix)['line'], 60)
        for bad_desc, bad_source in [(desc[:-1], source), (desc, source[:-1]),
                                     (desc, b'prefix!' + suffix.encode('ascii'))]:
            with self.assertRaises(ValueError):
                packet.decode_source_location(bad_desc, bad_source, suffix)

    def test_all_generated_files_match_saved_packet(self):
        evidence = ROOT / 'research' / 'work-items' / 'RE-021-blake-poststate-115'
        self.assertEqual(len(self.files), 11)
        for name, content in self.files.items():
            self.assertEqual((evidence / name).read_bytes(), content, name)


if __name__ == '__main__':
    unittest.main()
