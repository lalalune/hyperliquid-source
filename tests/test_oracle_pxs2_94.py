import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import oracle_pxs2_94 as scan


class OraclePxs2StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = scan.TARGET.read_bytes()
        cls.secs, cls.funcs, cls.calls, cls.branches, cls.windows, cls.snapshot, cls.entry, cls.rules, cls.tables, cls.constants, cls.indirect, cls.descriptor, cls.temporal = scan.gather(cls.data)

    def test_input_digest_and_missing_or_corrupted_bytes(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), scan.SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            scan.verify_digest(self.data[:-1])
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            scan.verify_digest(b'not the node')

    def test_bad_input_does_not_create_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                scan.generate(b'not the pinned target', destination)
            self.assertFalse(destination.exists())

    def test_fde_and_file_coordinate(self):
        by_name = {f['role']: f for f in self.funcs}
        self.assertEqual(len(by_name), 20)
        self.assertEqual(by_name['entry_writer']['start_va'], '0x32608a0')
        self.assertEqual(by_name['entry_writer']['end_va_exclusive'], '0x3260b97')
        entry = by_name['entry_writer']
        offset = int(entry['file_offset'], 16)
        n = int(entry['end_va_exclusive'], 16) - int(entry['start_va'], 16)
        self.assertEqual(hashlib.sha256(self.data[offset:offset+n]).hexdigest(), entry['body_sha256'])

    def test_address_rejects_unbacked_and_nobits(self):
        with self.assertRaisesRegex(ValueError, 'uniquely backed'):
            scan.read_va(self.data, self.secs, 0, 1)
        bss = next(s for s in self.secs if s['type'] == 8 and s['name'] == '.bss')
        with self.assertRaisesRegex(ValueError, 'uniquely backed'):
            scan.read_va(self.data, self.secs, bss['address'], 1)
        for size in (0, -1):
            with self.assertRaises(ValueError):
                scan.read_va(self.data, self.secs, 0x32608a0, size)
        with self.assertRaises(ValueError):
            scan.read_va(self.data, self.secs, -1, 1)

    def test_direct_call_path_and_wrong_opcode(self):
        call_map = {name: (int(site, 16), int(target, 16)) for name, site, _, target in self.calls}
        self.assertEqual(call_map['wrapper_to_vector_write'], (0x325f5b8, 0x322fbd0))
        self.assertEqual(call_map['collect_read_triple'], (0x341a2ab, 0x2aa4970))
        self.assertEqual(call_map['snapshot_read_pxs2_map'], (0x2d3a6fc, 0x2d8dc60))
        self.assertEqual(call_map['snapshot_read_pxs2_seq'], (0x2d3a8cb, 0x2d8dc60))
        self.assertEqual(call_map['triple_read_2'], (0x2aa557b, 0x2e33e50))
        self.assertEqual(scan.direct_call(self.data, self.secs, 0x3260a07), 0x359af90)
        with self.assertRaisesRegex(ValueError, 'Expected rel32 call'):
            scan.direct_call(self.data, self.secs, 0x3260a08)

    def test_branch_destinations_and_wrong_opcode(self):
        branch_map = {name: int(target, 16) for name, _, _, target in self.branches}
        self.assertEqual(branch_map['snapshot_duplicate_pxs2'], 0x2d3ad82)
        self.assertEqual(branch_map['snapshot_missing_pxs2'], 0x2d3a711)
        self.assertEqual(branch_map['snapshot_seq_empty'], 0x2d3a9c1)
        self.assertEqual(branch_map['snapshot_seq_exact_one'], 0x2d3a985)
        self.assertEqual(branch_map['group_empty'], 0x2aa5740)
        self.assertEqual(branch_map['group_one'], 0x2aa582c)
        self.assertEqual(branch_map['group_two'], 0x2aa59f8)
        self.assertEqual(branch_map['group_more_than_three'], 0x2aa5758)
        self.assertEqual(branch_map['entry_duplicate_p'], 0x2e3548a)
        self.assertEqual(branch_map['entry_omit_u'], 0x32609c4)
        with self.assertRaisesRegex(ValueError, 'Expected conditional branch'):
            scan.conditional_target(self.data, self.secs, 0x3260a07)

    def test_patched_instruction_fails_closed(self):
        bad = bytearray(self.data)
        off = scan.va_offset(self.secs, 0x2d3a2c6, 1, True)
        bad[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unexpected instruction'):
            scan.field_names(bad, self.secs)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            scan.verify_digest(bad)

    def test_aliases_and_tag_dispatch(self):
        for key in (b'u', b'last_update_time'):
            self.assertEqual(scan.classify(key, self.entry), 0)
        for key in (b'p', b'px'):
            self.assertEqual(scan.classify(key, self.entry), 1)
        for key in (b'd', b'daily_px'):
            self.assertEqual(scan.classify(key, self.entry), 2)
        for key in (b'', b'pxs2', b'P', b'daily_Px', b'last_update_tim', b'last_update_time\x00', b'\xff'):
            self.assertEqual(scan.classify(key, self.entry), 3)
        self.assertEqual(scan.classify(b'pxs2', self.snapshot, 1), 0)
        self.assertEqual(scan.classify(b'pxs3', self.snapshot, 1), 1)
        self.assertEqual(self.tables['entry_field_tags']['target_va'],
                         ['0x2e351ec', '0x2e352af', '0x2e3522d', '0x2e35277'])

    def test_each_alias_byte_is_significant(self):
        for fields, unknown in ((self.snapshot, 1), (self.entry, 3)):
            for key, _ in fields:
                for i in range(len(key)):
                    mutant = key[:i] + bytes([key[i] ^ 1]) + key[i+1:]
                    self.assertEqual(scan.classify(mutant, fields, unknown), unknown, (key, i))

    def test_corrupted_length_dispatch_rejected(self):
        bad = bytearray(self.data)
        off = scan.va_offset(self.secs, 0x581ec4, 1)
        bad[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'length dispatch'):
            scan.field_names(bad, self.secs)

    def test_group_arity_model(self):
        self.assertEqual([scan.group_path(n) for n in range(6)],
                         ['missing_0', 'missing_1', 'missing_2', 'exact_3', 'excess', 'excess'])
        with self.assertRaises(ValueError):
            scan.group_path(16)
        with self.assertRaises(ValueError):
            scan.group_path(-1)

    def test_time_decode_chain_and_branch_gate(self):
        self.assertEqual(scan.direct_call(self.data, self.secs, 0x2a8d66c), 0x2a93110)
        self.assertEqual(scan.direct_call(self.data, self.secs, 0x2a934c6), 0x3a0d6f0)
        self.assertEqual(scan.direct_call(self.data, self.secs, 0x3a0d7cf), 0x1514b50)
        indirect = {row['role']: row for row in self.indirect}
        self.assertEqual(indirect['time_generic_decode']['addend_va'], '0x13c3660')
        self.assertEqual(indirect['time_text_input_check']['addend_va'], '0x157a200')
        self.assertEqual(indirect['time_parsed_value_finalize']['addend_va'], '0x151c2c0')
        self.assertEqual(scan.parsed_time_route(1, 0), 'finalize')
        for a, b in ((0, 0), (0, 1), (1, 1)):
            self.assertEqual(scan.parsed_time_route(a, b), 'error_conversion')
        for a, b in ((-1, 0), (1, 1 << 64), (True, 0)):
            with self.assertRaises(ValueError):
                scan.parsed_time_route(a, b)

    def test_entry_field_route_seen_and_unknown(self):
        for tag in range(3):
            self.assertEqual(scan.field_route(tag, False), 'decode_value')
            self.assertEqual(scan.field_route(tag, True), 'duplicate_diagnostic')
        for seen in (False, True):
            self.assertEqual(scan.field_route(3, seen), 'unknown_helper')
        for tag, seen in ((4, False), (-1, False), (0, 1)):
            with self.assertRaises(ValueError):
                scan.field_route(tag, seen)

    def test_optional_time_uses_two_helper_results(self):
        self.assertEqual(scan.entry_decisions(7, 7, 7, 0, 0), (2, False))
        self.assertEqual(scan.entry_decisions(7, 7, 8, 0, 0), (3, True))
        self.assertEqual(scan.entry_decisions(7, 7, 7, 1, 0), (3, True))
        self.assertEqual(scan.entry_decisions(7, 7, 7, 0, 1), (3, True))
        self.assertEqual(scan.entry_decisions(7, 8, 7, 0, 0), (2, True))
        self.assertEqual(scan.entry_decisions(7, 8, 8, 0, 0), (3, False))
        for args in ((0, 7, 7, 0, 0), (7, 0, 7, 0, 0), (7, 7, 1 << 32, 0, 0)):
            with self.assertRaises(ValueError):
                scan.entry_decisions(*args)

    def test_unsigned_width_boundaries(self):
        expected = {0: '00', 127: '7f', 128: 'cc80', 255: 'ccff', 256: 'cd0100',
                    65535: 'cdffff', 65536: 'ce00010000',
                    (1 << 32) - 1: 'ceffffffff', 1 << 32: 'cf0000000100000000',
                    (1 << 64) - 1: 'cfffffffffffffffff'}
        for value, result in expected.items():
            self.assertEqual(scan.encode_unsigned(value, self.rules).hex(), result)
        for bad in (-1, 1 << 64, 1.0, True):
            with self.assertRaises(ValueError):
                scan.encode_unsigned(bad, self.rules)

    def test_indirect_slots_and_relocation_negative_controls(self):
        selected = {x['role']: x for x in self.indirect}
        self.assertEqual(selected['default_helper_first']['slot_va'], '0x576e890')
        self.assertEqual(selected['default_helper_first']['addend_va'], '0x151f6f0')
        self.assertEqual(selected['time_date_formatter']['addend_va'], '0x151f240')
        self.assertEqual(selected['time_clock_formatter']['addend_va'], '0x15204a0')
        self.assertEqual(selected['missing_time_default']['addend_va'], '0x3c0c870')
        with self.assertRaisesRegex(ValueError, 'Expected RIP-relative'):
            scan.indirect_slot(self.data, self.secs, 0x32608b7)
        with self.assertRaisesRegex(ValueError, 'Missing selected relocation'):
            scan.relocation_addends(self.data, self.secs, {0x12345678})
        bad = bytearray(self.data)
        record = int(selected['time_date_formatter']['record_file_offset'], 16)
        bad[record + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unexpected or duplicate relocation'):
            scan.relocation_addends(bad, self.secs, {0x576f560})

    def test_snapshot_descriptor_is_relocated_and_bound_to_reader(self):
        self.assertEqual(self.descriptor['slot_va'], '0x56d8498')
        self.assertEqual(self.descriptor['addend_va'], '0x578892')
        self.assertEqual(self.descriptor['length'], 36)
        self.assertEqual(self.descriptor['text'], 'struct OracleSnapshot with 1 element')
        scan.expect(self.data, self.secs, 0x2d3a9c6, bytes.fromhex('488d15cbda9902'))
        self.assertEqual(scan.conditional_target(self.data, self.secs, 0x2d3a8bd)[0], 0x2d3a9c1)

    def test_time_format_partial_structure(self):
        self.assertEqual(self.constants['time_type'], 'Time')
        self.assertEqual(self.constants['time_separator'], 'T')
        self.assertEqual(scan.direct_call(self.data, self.secs, 0x31ebcf8), 0x3599f00)
        self.assertEqual(scan.conditional_target(self.data, self.secs, 0x31ebcb1)[0], 0x31ebd48)
        self.assertEqual(scan.conditional_target(self.data, self.secs, 0x31ebccb)[0], 0x31ebd48)
        self.assertEqual(scan.conditional_target(self.data, self.secs, 0x31ebce1)[0], 0x31ebd48)

    def test_time_evidence_rejects_corrupt_code_and_descriptors(self):
        bad = bytearray(self.data)
        code = scan.va_offset(self.secs, 0x151f24e, 1, True)
        bad[code] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unexpected instruction'):
            scan.temporal_rules(bad, self.secs)
        bad[code] ^= 1
        descriptor = scan.va_offset(self.secs, 0x250cb7, 1)
        bad[descriptor] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unexpected fractional format descriptors'):
            scan.temporal_rules(bad, self.secs)

    def test_date_and_time_formatter_ordinary_paths(self):
        rules = self.temporal
        self.assertEqual(rules['date_year_limit'], 10000)
        self.assertEqual(rules['date_index_mask'], 1023)
        self.assertEqual(len(bytes.fromhex(rules['date_table_hex'])), 733)
        self.assertEqual(rules['fraction_widths'], [3, 6, 9])
        jan = (1970 << 13) | (3 << 3)
        leap = (2024 << 13) | (120 << 3)
        dec = (2024 << 13) | (732 << 3)
        examples = [(jan, 0, 0, '1970-01-01T00:00:00'),
                    (leap, 45296, 123000000, '2024-02-29T12:34:56.123'),
                    (leap, 45296, 123456000, '2024-02-29T12:34:56.123456'),
                    (leap, 45296, 123456789, '2024-02-29T12:34:56.123456789'),
                    (dec, 86399, 1000000000, '2024-12-31T23:59:60'),
                    (dec, 86399, 1000000001, '2024-12-31T23:59:60.000000001')]
        for word, sec, nano, expected in examples:
            self.assertEqual(scan.modeled_time(word, sec, nano, rules), expected)

    def test_time_model_rejects_unstudied_and_invalid_ranges(self):
        rules = self.temporal
        valid = (1970 << 13) | (3 << 3)
        for word, sec, nano in (((10000 << 13) | (3 << 3), 0, 0),
                                ((2024 << 13) | (733 << 3), 0, 0),
                                (valid, 86400, 0), (valid, -1, 0),
                                (valid, 0, 2000000000), (valid, 0, -1),
                                (0xffffffff, 0, 0)):
            with self.assertRaises(ValueError):
                scan.modeled_time(word, sec, nano, rules)

    def test_clock_reciprocal_division_for_every_second_of_a_day(self):
        # Compare the machine-code reciprocals with independent integer division.
        for seconds in range(86400):
            minutes = (seconds * 0x88888889) >> 37
            hours = (seconds * 0x91a2b3c5) >> 43
            minute_hours = (minutes * 0x8888889) >> 33
            self.assertEqual(minutes, seconds // 60)
            self.assertEqual(hours, seconds // 3600)
            self.assertEqual(minute_hours, minutes // 60)

    def test_fraction_predicates_match_boundaries(self):
        rules = self.temporal
        values = (1, 999, 1000, 999999, 1000000, 123000000,
                  123456000, 123456789, 999999999)
        for value in (*values, *range(0, 1000000000, 100003)):
            a = scan.ror32(value * rules['fraction_multipliers'][0], rules['fraction_rotations'][0])
            b = scan.ror32(value * rules['fraction_multipliers'][1], rules['fraction_rotations'][1])
            self.assertEqual(a <= rules['fraction_thresholds'][0], value % 1000000 == 0)
            self.assertEqual(b <= rules['fraction_thresholds'][1], value % 1000 == 0)
        with self.assertRaises(ValueError):
            scan.ror32(1, 0)

    def test_compact_map_examples(self):
        expected = {(0, 0): '82a17000a16400', (1, 2): '82a17001a16402',
                    (127, 128): '82a1707fa164cc80', (255, 256): '82a170ccffa164cd0100',
                    (65535, 65536): '82a170cdffffa164ce00010000'}
        for (p, d), encoded in expected.items():
            self.assertEqual(scan.compact_named_entry(p, d, self.rules).hex(), encoded)
        for p, d in ((-1, 0), (0, 1 << 64)):
            with self.assertRaises(ValueError):
                scan.compact_named_entry(p, d, self.rules)

    def test_machine_byte_shape_and_marker_constants(self):
        scan.expect(self.data, self.secs, 0x323c7ed, bytes.fromhex('c6043093'))
        scan.expect(self.data, self.secs, 0x323c816, bytes.fromhex('498d7720'))
        scan.expect(self.data, self.secs, 0x323c82b, bytes.fromhex('4983c740'))
        scan.expect(self.data, self.secs, 0x322fbf4, bytes.fromhex('48c1e005488d1c40'))
        self.assertEqual(self.rules['markers'], [0xcc, 0xcd, 0xce, 0xcf])
        self.assertEqual(self.constants['oracle_kind_map'], 'OracleKindMap')


if __name__ == '__main__':
    unittest.main()
