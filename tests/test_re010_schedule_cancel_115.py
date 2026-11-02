import csv
import datetime
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re010_schedule_cancel_115 as evidence


def records(blob):
    return list(csv.DictReader(io.StringIO(blob.decode('utf-8')), delimiter='\t'))


class ScheduleCancelEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The captured node is read as data. It is never executed.
        cls.data = evidence.BINARY.read_bytes()
        cls.secs = evidence.sections(cls.data)
        cls.files = evidence.generate_evidence(cls.data)
        cls.constants, _ = evidence.extract_constants(cls.data, cls.secs)

    def test_input_digest_and_wrong_digest(self):
        evidence.check_digest(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.check_digest(self.data, '0' * 64)

    def test_corrupted_input_hash_is_rejected(self):
        value = b'authentic sample bytes'
        digest = hashlib.sha256(value).hexdigest()
        evidence.check_digest(value, digest)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.check_digest(value[:-1] + b'!', digest)

    def test_selected_fde_extents_and_noncoverage(self):
        rows = records(self.files['functions.tsv'])
        self.assertEqual(len(rows), 23)
        core = next(r for r in rows if r['role'] == 'core')
        self.assertEqual((core['start_va'], core['end_va_exclusive'], core['body_size']),
                         ('0x2c2cb40', '0x2c2cf4a', '1034'))
        self.assertEqual(core['body_sha256'], evidence.FDE_PINS[0][3])

    def test_single_byte_body_corruption_is_rejected(self):
        changed = bytearray(self.data)
        role, start, end, digest = evidence.FDE_PINS[0]
        self.assertEqual(role, 'core')
        changed[evidence.section_offset(self.secs, start + 2, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            evidence.check_body(changed, self.secs, start, end, digest)

    def test_corrupted_fde_range_is_rejected(self):
        rows = records(self.files['functions.tsv'])
        core = next(r for r in rows if r['role'] == 'core')
        # An FDE has its encoded range after length, CIE pointer and start.
        fde_off = evidence.section_offset(self.secs, int(core['fde_va'], 16), 16)
        changed = bytearray(self.data)
        n = struct.unpack_from('<i', changed, fde_off + 12)[0]
        struct.pack_into('<i', changed, fde_off + 12, n + 1)
        with self.assertRaises(ValueError):
            evidence.indexed_functions(changed, self.secs)

    def test_non_file_backed_section_is_rejected(self):
        # TLS .tbss can share linked VAs with a file-backed non-TLS section;
        # use the ordinary .bss, whose address is not also file-backed.
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            evidence.section_offset(self.secs, bss['address'], 1)

    def test_range_end_and_ambiguity_are_rejected(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        end = text['address'] + text['size']
        with self.assertRaises(ValueError):
            evidence.section_offset([text], end - 1, 2)
        with self.assertRaises(ValueError):
            evidence.section_offset([text, dict(text)], text['address'], 1)
        with self.assertRaises(ValueError):
            evidence.section_offset([text], text['address'], 0)

    def test_direct_call_and_corruption(self):
        site, target = 0x2c2cb79, 0x2a8ae60
        raw = evidence.read_va(self.data, self.secs, site, 5, executable=True)
        self.assertEqual(evidence.check_direct_call(site, raw, target), raw)
        broken = raw[:1] + bytes([raw[1] ^ 1]) + raw[2:]
        with self.assertRaisesRegex(ValueError, 'call changed'):
            evidence.check_direct_call(site, broken, target)

    def test_branch_decode_positive_and_negative_displacements(self):
        self.assertEqual(evidence.decode_control(0x1000, b'\x75\xfe'),
                         ('jne', 0x1000, b'\x75\xfe'))
        self.assertEqual(evidence.decode_control(0x1000, b'\x0f\x84\x04\0\0\0'),
                         ('je', 0x100a, b'\x0f\x84\x04\0\0\0'))

    def test_branch_decode_rejects_truncation_and_nonbranches(self):
        for raw in (b'\xe8\0', b'\x0f\x84\0\0', b'\x90\x90'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.decode_control(0x1000, raw)

    def test_corrupted_cutoff_branch_displacement_is_detected(self):
        site = 0x2c2ce49
        raw = evidence.read_va(self.data, self.secs, site, 2, executable=True)
        self.assertEqual(evidence.decode_control(site, raw)[:2], ('jb', 0x2c2ce59))
        changed = bytearray(self.data)
        changed[evidence.section_offset(self.secs, site + 1, 1)] ^= 1
        changed_raw = evidence.read_va(changed, self.secs, site, 2, executable=True)
        self.assertNotEqual(evidence.decode_control(site, changed_raw)[1], 0x2c2ce59)
        _, start, end, digest = evidence.FDE_PINS[0]
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            evidence.check_body(changed, self.secs, start, end, digest)

    def test_relocations_read_expected_entry(self):
        raw = struct.pack('<QQq', 0x1100, (3 << 32) | 6, -4)
        sec = {'type': 4, 'size': len(raw), 'offset': 0}
        self.assertEqual(evidence.checked_relocations(raw, sec, {0x1100}),
                         {0x1100: (6, 3, -4, 0)})

    def test_relocations_reject_truncation_duplicate_and_missing(self):
        raw = struct.pack('<QQq', 0x1100, 8, 42)
        with self.assertRaises(ValueError):
            evidence.checked_relocations(raw, {'type': 4, 'size': 23, 'offset': 0}, {0x1100})
        with self.assertRaises(ValueError):
            evidence.checked_relocations(raw + raw, {'type': 4, 'size': 48, 'offset': 0}, {0x1100})
        with self.assertRaises(ValueError):
            evidence.checked_relocations(raw, {'type': 4, 'size': 24, 'offset': 0}, {0x1101})
        with self.assertRaises(ValueError):
            evidence.checked_relocations(raw, {'type': 4, 'size': 48, 'offset': 0}, {0x1100})

    def test_duplicate_required_section_is_rejected(self):
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        with self.assertRaises(ValueError):
            evidence.unique_section([sec, dict(sec)], '.rela.dyn')

    def test_lazy_defaults_bind_initializers_and_copy_zero_fields(self):
        descriptors, expected = evidence.lazy_descriptors(self.data, self.secs)
        self.assertEqual(len(descriptors), 2)
        slots = evidence.checked_relocations(self.data, evidence.unique_section(self.secs, '.rela.dyn'), set(expected))
        rows = evidence.check_lazy_relocations(slots, expected)
        self.assertEqual(len(rows), 6)
        self.assertEqual(slots[0x64fda80][:3], (8, 0, 0x44e9f40))
        self.assertEqual(slots[0x64fd958][:3], (8, 0, 0x3d25c00))
        # Both initializers establish zero XMM0 before the selected 16-byte store.
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x44e9f5a, 3, executable=True), b'\x0f\x57\xc0')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x44e9f80, 4, executable=True), b'\x0f\x11\x47\x50')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x3d25c12, 3, executable=True), b'\x0f\x57\xc0')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x3d25c2d, 4, executable=True), b'\x0f\x11\x47\x40')
        # Both callback variants copy these same initialized bytes to the cell.
        for site in (0x44dd1e9, 0x44db3a9):
            self.assertEqual(evidence.read_va(self.data, self.secs, site, 9, executable=True),
                             b'\x0f\x10\x44\x24\x58\x0f\x11\x43\x50')
        for site in (0x3ced322, 0x3c4c5b2):
            self.assertEqual(evidence.read_va(self.data, self.secs, site, 9, executable=True),
                             b'\x0f\x10\x44\x24\x40\x0f\x11\x43\x40')

    def test_lazy_initializer_relocation_corruption_is_rejected(self):
        _, expected = evidence.lazy_descriptors(self.data, self.secs)
        slots = evidence.checked_relocations(self.data, evidence.unique_section(self.secs, '.rela.dyn'), set(expected))
        typ, sym, addend, file_off = slots[0x64fda80]
        slots[0x64fda80] = (typ, sym, addend + 1, file_off)
        with self.assertRaisesRegex(ValueError, 'lazy relocation'):
            evidence.check_lazy_relocations(slots, expected)

    def test_source_location_corruption_is_rejected(self):
        changed = bytearray(self.data)
        changed[evidence.section_offset(self.secs, 0x436bc9, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'source location path'):
            evidence.source_locations(changed, self.secs)

    def test_prior_dispatch_context_binds_index_and_first_calls(self):
        rows = {r['family']: r for r in records(self.files['dispatch-context.tsv'])}
        self.assertEqual(set(rows), {'serializer', 'execute_r12', 'execute_r15'})
        for row in rows.values():
            self.assertEqual((row['selected_index'], row['derived_tag'], row['serializer_name']),
                             ('18', '0x98', 'scheduleCancel'))
        self.assertEqual(rows['execute_r12']['first_call_target_va'], '0x283c900')
        self.assertEqual(rows['execute_r15']['first_call_target_va'], '0x2c06530')

    def test_prior_dispatch_context_rejects_corrupt_table_and_name(self):
        for va, error in ((0x60a3a8, 'table entry'), (0x60c538, 'variant name')):
            changed = bytearray(self.data)
            changed[evidence.section_offset(self.secs, va, 1)] ^= 1
            with self.subTest(va=va), self.assertRaisesRegex(ValueError, error):
                evidence.dispatch_context(changed, self.secs)

    def test_binary_constants_and_volume_location(self):
        c = self.constants
        self.assertEqual(c['volume_minimum'], 100_000_000)
        self.assertEqual(c['volume_divisor'], 100.0)
        paths = {r['path'] for r in records(self.files['source-locations.tsv'])}
        self.assertIn('l1/src/scaled_vlm.rs', paths)
        self.assertIn('l1/src/raw_vlm.rs', paths)
        self.assertEqual((c['delay_seconds'], c['seconds_per_day'], c['nanoseconds_per_second']),
                         (5, 86_400, 1_000_000_000))

    def test_cutoff_fallback_triple_and_comparison(self):
        c = self.constants
        fallback = (c['fallback_date'], c['fallback_seconds'], c['fallback_nanoseconds'])
        self.assertEqual(fallback, (0x7fffd6de, 86_399, 999_999_999))
        self.assertFalse(evidence.packed_later(fallback, fallback))
        self.assertFalse(evidence.packed_later((fallback[0], 86_399, 999_000_000), fallback))
        branch = next(r for r in records(self.files['branches.tsv']) if r['site_va'] == '0x2c2ccf4')
        self.assertEqual((branch['operation'], branch['target_va']), ('je', '0x2c2ce0e'))

    def test_ordinal_helper_year_guard_boundaries(self):
        c = self.constants
        for year, accepted in ((-262144, False), (-262143, True), (-262142, True),
                               (0, True), (262141, True), (262142, True), (262143, False)):
            self.assertEqual(evidence.ordinal_year_gate(c, year), accepted)
        self.assertEqual(c['fallback_date'] >> 13, 262142)
        self.assertEqual((c['fallback_date'] >> 4) & 0x1ff, 365)
        with self.assertRaises(ValueError):
            evidence.ordinal_year_gate(c, 1 << 31)

    def test_tree_comparisons_load_the_memcmp_relocation(self):
        rows = records(self.files['register-calls.tsv'])
        self.assertEqual({r['role'] for r in rows}, {'core_tree_compare', 'map_tree_compare'})
        self.assertTrue(all(r['dynamic_symbol'] == 'memcmp' and r['rela_type'] == '6' for r in rows))

    def test_map_representation_boundaries_and_state_writes(self):
        c = self.constants
        self.assertEqual(c['tree_representation_marker'], 1 << 63)
        self.assertEqual(c['tree_to_compact_below'], 32)
        self.assertEqual(c['compact_threshold_minus_one'] + 1, 64)
        self.assertEqual(c['lookup_key_bytes'], 20)
        self.assertEqual(c['compact_record_stride'], 48)
        self.assertEqual((c['request_state_time_date_offset'], c['request_state_time_nanos_offset']),
                         (c['expiry_state_time_date_offset'], c['expiry_state_time_nanos_offset']))
        self.assertEqual((c['expiry_state_time_date_offset'], c['expiry_state_time_seconds_offset'],
                          c['expiry_state_time_nanos_offset'], c['expiry_state_previous_date_offset']),
                         (0x60, 0x64, 0x68, 0x6c))
        rows = {r['role']: r for r in records(self.files['state-writes.tsv'])}
        self.assertEqual((rows['clear_existing_date']['value_offset'], rows['clear_existing_date']['width_bytes']), ('8', '4'))
        self.assertEqual((rows['store_deadline_date']['value_offset'], rows['store_deadline_date']['width_bytes']), ('8', '4'))
        self.assertEqual((rows['store_deadline_time']['value_offset'], rows['store_deadline_time']['width_bytes']), ('12', '8'))

    def test_volume_gate_precedes_absent_action(self):
        c = self.constants
        below = c['volume_minimum'] - 1
        self.assertEqual(evidence.abstract_case(c, below, 0, 0, -1, 1, 10),
                         (c['status_volume'], 'no_map_operation'))
        self.assertEqual(evidence.abstract_case(c, below + 1, 0, 0, -1, 1, 10),
                         (c['status_success'], 'clear_date'))

    def test_absent_action_does_not_create_and_uses_low_bit(self):
        c = self.constants
        n = c['volume_minimum']
        self.assertEqual(evidence.abstract_case(c, n, 0, 1, 1, 0, 0),
                         (c['status_success'], 'leave_map'))
        self.assertEqual(evidence.abstract_case(c, n, 2, 1, 1, 1, 0),
                         (c['status_success'], 'clear_date'))
        self.assertEqual(evidence.abstract_case(c, n, 3, 1, 1, 1, 0),
                         (c['status_success'], 'store_date_and_time'))

    def test_time_errors_precede_counter(self):
        c = self.constants
        n = c['volume_minimum']
        self.assertEqual(evidence.abstract_case(c, n, 1, 0, 1, 1, 10)[0], c['status_bad_time'])
        self.assertEqual(evidence.abstract_case(c, n, 1, 1, 0, 1, 10)[0], c['status_early'])
        self.assertEqual(evidence.abstract_case(c, n, 1, 1, 1, 1, 10)[0], c['status_counter'])

    def test_counter_nine_is_allowed_ten_is_rejected(self):
        c = self.constants
        args = (c, c['volume_minimum'], 1, 1, 1, 1)
        self.assertEqual(evidence.abstract_case(*args, 9), (c['status_success'], 'store_date_and_time'))
        self.assertEqual(evidence.abstract_case(*args, 10),
                         (c['status_counter'], 'entry_materialized_no_date_store'))

    def test_strict_packed_time_comparison_and_signed_date(self):
        cutoff = (1, 42, 999)
        self.assertFalse(evidence.packed_later(cutoff, cutoff))
        self.assertFalse(evidence.packed_later((1, 42, 998), cutoff))
        self.assertTrue(evidence.packed_later((1, 42, 1000), cutoff))
        self.assertTrue(evidence.packed_later((1, 43, 0), cutoff))
        self.assertFalse(evidence.packed_later((0xffffffff, 0, 0), (0, 0, 0)))

    def test_packed_time_rejects_out_of_range_fields(self):
        with self.assertRaises(ValueError):
            evidence.packed_later((1, 1 << 32, 0), (1, 0, 0))
        with self.assertRaises(ValueError):
            evidence.packed_later((1, 0), (1, 0, 0))

    def test_saturating_addition_boundary(self):
        top = (1 << 64) - 1
        self.assertEqual(evidence.saturating_add_on_return(top - 1, 1), top)
        self.assertEqual(evidence.saturating_add_on_return(top - 1, 2), top)
        self.assertEqual(evidence.saturating_add_on_return(9, 4), 13)
        with self.assertRaises(ValueError):
            evidence.saturating_add_on_return(top + 1, 0)

    def test_time_magic_matches_division_on_recorded_inputs(self):
        c = self.constants
        self.assertEqual(c['epoch_day_bias'], datetime.date(1970, 1, 1).toordinal())
        rows = records(self.files['time-arithmetic-vectors.tsv'])
        self.assertGreaterEqual(len(rows), 260)
        for row in rows:
            value = int(row['input_milliseconds'])
            whole_seconds, millis = divmod(value, 1000)
            days, seconds = divmod(whole_seconds, 86_400)
            self.assertEqual((int(row['direct_days']), int(row['days_from_seconds']),
                              int(row['seconds_of_day']), int(row['nanoseconds'])),
                             (days, days, seconds, millis * 1_000_000))
        with self.assertRaises(ValueError):
            evidence.time_fields_from_magic(c, c['fast_time_limit'] + 1)

    def test_mutated_time_magic_breaks_independent_division(self):
        c = dict(self.constants)
        c['millisecond_division_magic'] //= 2
        raw = c['fast_time_limit']
        _, _, seconds, nanos = evidence.time_fields_from_magic(c, raw)
        whole_seconds, ms = divmod(raw, 1000)
        self.assertNotEqual((seconds, nanos), (whole_seconds % 86_400, ms * 1_000_000))

    def test_due_scan_treats_equal_deadline_as_due(self):
        now = (100, 100, 500_000_000)
        self.assertFalse(evidence.due_at((0, 0, 0), now))
        self.assertTrue(evidence.due_at((99, 86_399, 999_999_999), now))
        self.assertTrue(evidence.due_at(now, now))
        self.assertFalse(evidence.due_at((100, 100, 500_000_001), now))
        self.assertFalse(evidence.due_at((101, 0, 0), now))

    def test_clock_entry_copies_state_and_passes_same_pointer_to_expiry(self):
        advance = evidence.read_va(self.data, self.secs, 0x2bdf2c1, 29, executable=True)
        self.assertEqual(advance.hex(),
                         '488d4b608b7908897b74488b3948897b6c488b3e4889398b7e08897908')
        context = evidence.read_va(self.data, self.secs, 0x2bdf41b, 8, executable=True)
        self.assertEqual(context, b'\x48\x89\x9c\x24\xc8\x00\x00\x00')
        argument = evidence.read_va(self.data, self.secs, 0x2bdf491, 8, executable=True)
        self.assertEqual(argument, b'\x48\x8d\xbc\x24\xc8\x00\x00\x00')
        self.assertEqual(evidence.read_va(self.data, self.secs, 0x2bdf916, 3, executable=True),
                         b'\x4c\x8b\x33')
        calls = {r['role']: r for r in records(self.files['calls.tsv'])}
        self.assertEqual(calls['clock_entry_to_expiry']['target_or_slot_va'], '0x2bdf8f0')

    def test_expiry_increment_precedes_optional_reset(self):
        now = (100, 100, 500_000_000)
        self.assertEqual(evidence.expiry_case(now, now, 9, 100), (True, False, 10, 0, False))
        self.assertEqual(evidence.expiry_case(now, now, 9, 99), (True, True, 0, 0, True))
        self.assertEqual(evidence.expiry_case((101, 0, 0), now, 9, 99), (False, True, 0, 101, False))
        self.assertEqual(evidence.expiry_case((0, 0, 0), now, 9, 99), (False, True, 0, 0, True))

    def test_expiry_counter_saturates(self):
        now = (100, 100, 500_000_000)
        maximum = (1 << 64) - 1
        self.assertEqual(evidence.expiry_case(now, now, maximum, 100)[2], maximum)
        self.assertEqual(evidence.expiry_case(now, now, maximum - 1, 100)[2], maximum)
        with self.assertRaises(ValueError):
            evidence.expiry_case(now, now, maximum + 1, 100)

    def test_expiry_writes_and_synthetic_cases(self):
        writes = {r['role']: r for r in records(self.files['expiry-writes.tsv'])}
        self.assertEqual(writes['clear_due_date']['instruction_hex'], '41c7450800000000')
        self.assertEqual(writes['reset_tree_counter']['instruction_hex'], '49c744c30800000000')
        self.assertEqual(len(records(self.files['expiry-vectors.tsv'])), 96)

    def test_handoff_selector_and_per_dex_calls(self):
        self.assertEqual(self.constants['expiry_handoff_selector'], 2)
        self.assertEqual(self.constants['expiry_handoff_flag'], 15)
        calls = {r['role']: r for r in records(self.files['calls.tsv'])}
        self.assertEqual(calls['handoff_dex_collect']['target_or_slot_va'], '0x22f2000')
        self.assertEqual(calls['handoff_dex_apply']['target_or_slot_va'], '0x2419810')
        self.assertEqual(calls['handoff_base_collect']['target_or_slot_va'], '0x22f2160')
        self.assertEqual(calls['handoff_base_apply']['target_or_slot_va'], '0x241a3c0')

    def test_synthetic_vectors_cover_all_selected_outcomes(self):
        rows = records(self.files['decision-vectors.tsv'])
        self.assertEqual(len(rows), 360)
        self.assertEqual({r['status'] for r in rows}, {'0x89', '0x11b', '0x11c', '0x11d', '0x1a2'})
        self.assertEqual({r['map_action'] for r in rows},
                         {'no_map_operation', 'clear_date', 'leave_map',
                          'entry_materialized_no_date_store', 'store_date_and_time'})
        for r in records(self.files['time-vectors.tsv']):
            self.assertEqual(r['strictly_later'], str(int(r['deadline_delta_ns_from_cutoff']) > 0).lower())

    def test_output_counts_and_input_identity(self):
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['artifact_sha256'], evidence.TARGET_SHA256)
        self.assertEqual(summary['branches_selected'], 144)
        self.assertEqual(summary['direct_calls_selected'], 28)
        self.assertEqual(summary['indirect_calls_selected'], 15)
        self.assertEqual(summary['register_calls_selected'], 2)
        self.assertEqual(summary['state_writes_selected'], 3)
        self.assertEqual(summary['expiry_writes_selected'], 5)
        self.assertEqual(summary['expiry_vectors_synthetic'], 96)
        self.assertEqual(summary['lazy_relocations_selected'], 6)
        self.assertEqual(summary['dispatch_context_rows'], 3)
        self.assertEqual(summary['source_locations_selected'], 3)
        self.assertEqual(summary['addition_vectors_synthetic'], 16)
        self.assertGreaterEqual(summary['time_arithmetic_vectors_synthetic'], 260)


if __name__ == '__main__':
    unittest.main()
