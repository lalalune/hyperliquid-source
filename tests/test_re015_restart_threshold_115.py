# SPDX-License-Identifier: MIT
import contextlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import re015_restart_threshold_115 as collector


class RestartThresholdEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = collector.BINARY.read_bytes()
        collector.require_digest(cls.data)
        cls.secs, index = collector.unwind_index(cls.data)
        cls.index = index
        cls.fdes = collector.find_fdes(cls.data, cls.secs, index)
        cls.mutable = bytearray(cls.data)

    @classmethod
    @contextlib.contextmanager
    def damaged(cls, va, *, byte=1):
        _, offset = collector.locate(cls.secs, va, 1)
        before = cls.mutable[offset]
        cls.mutable[offset] ^= byte
        try:
            yield cls.mutable
        finally:
            cls.mutable[offset] = before

    def test_identity_and_actual_byte_corruption(self):
        collector.require_digest(self.data)
        with self.damaged(0x1562372) as corrupt:
            with self.assertRaises(ValueError):
                collector.require_digest(corrupt)
        with self.assertRaises(ValueError):
            collector.require_digest(self.data[:-1])

    def test_bad_capture_produces_no_evidence_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence'
            with self.assertRaises(ValueError):
                collector.generate(b'not the pinned capture', output)
            self.assertFalse(output.exists())

    def test_historical_input_is_authenticated_before_parsing(self):
        with self.assertRaises(ValueError):
            collector.compare_historical(b'wrong capture', self.data)

    def test_selected_unwind_ranges(self):
        self.assertEqual(len(self.fdes), 9)
        self.assertEqual(sum(f['end'] - f['start'] for f in self.fdes), 26650)
        by_role = {f['role']: f for f in self.fdes}
        self.assertEqual(by_role['resume_poll']['start'], 0x2aeaef0)
        self.assertEqual(by_role['setting_wrapper']['end'], 0x15623d5)
        self.assertIsNotNone(by_role['setting_reader']['lsda'])

    def test_all_selected_windows_bind_to_one_fde(self):
        rows = collector.window_rows(self.data, self.secs, self.fdes)
        self.assertEqual(len(rows), 58)
        self.assertEqual(len({r['role'] for r in rows}), len(rows))

    def test_code_corruption_is_rejected_by_window_contract(self):
        with self.damaged(0x1575e1c) as corrupt:
            with self.assertRaises(ValueError):
                collector.window_rows(corrupt, self.secs, self.fdes)

    def test_actual_fde_range_damage_is_rejected(self):
        fde = next(f for f in self.fdes if f['role'] == 'setting_wrapper')
        with self.damaged(fde['fde'] + 12) as corrupt:
            with self.assertRaises(ValueError):
                collector.find_fdes(corrupt, self.secs, self.index)

    def test_selected_extent_is_not_a_next_index_guess(self):
        shortened = [dict(f) for f in self.fdes]
        owner = next(f for f in shortened if f['role'] == 'setting_wrapper')
        owner['end'] = 0x1562370
        with self.assertRaises(ValueError):
            collector.window_rows(self.data, self.secs, shortened)

    def test_transfer_and_selected_table_targets(self):
        transfers = {r[0]: collector.decode_transfer(self.data, self.secs, r)
                     for r in collector.TRANSFERS}
        self.assertEqual(transfers['setting_call']['target'], 0x1501b80)
        self.assertEqual(transfers['reader_decode']['target'], 0x1574a60)
        self.assertEqual(transfers['threshold_cmp']['target'], 0x2af0157)
        tables = {r['role']: r for r in collector.table_rows(self.data, self.secs)}
        self.assertEqual(tables['outer_resume']['target'], 0x2aeb1cd)
        self.assertEqual(tables['nested_first_poll']['target'], 0x2aefee7)
        self.assertEqual(tables['nested_wait']['target'], 0x2af016e)
        self.assertEqual(tables['first_wait_inner_resume']['target'], 0x2a9147e)

    def test_condition_opcode_damage_is_rejected(self):
        spec = next(r for r in collector.TRANSFERS if r[0] == 'threshold_cmp')
        with self.damaged(0x2af0128) as corrupt:
            with self.assertRaises(ValueError):
                collector.decode_transfer(corrupt, self.secs, spec)

    def test_transfer_displacement_damage_is_rejected(self):
        spec = next(r for r in collector.TRANSFERS if r[0] == 'setting_call')
        with self.damaged(0x1562353) as corrupt:
            with self.assertRaises(ValueError):
                collector.decode_transfer(corrupt, self.secs, spec)

    def test_dispatch_displacement_damage_is_rejected(self):
        with self.damaged(0x6042a4) as corrupt:
            with self.assertRaises(ValueError):
                collector.table_rows(corrupt, self.secs)

    def test_rip_relative_entry_and_corruption(self):
        refs = {r['role']: r for r in collector.rip_rows(self.data, self.secs)}
        self.assertEqual(refs['setting_template']['target'], 0x4315ea)
        with self.damaged(0x156232c) as corrupt:
            with self.assertRaises(ValueError):
                collector.rip_rows(corrupt, self.secs)

    def test_elapsed_boundary_is_rip_bound_and_mutation_rejected(self):
        refs = {r['role']: r for r in collector.rip_rows(self.data, self.secs)}
        data = {r['role']: r for r in collector.data_rows(self.data, self.secs)}
        self.assertEqual(refs['elapsed_boundary']['target'], data['ordered_elapsed_boundary_binary64']['va'])
        self.assertEqual(data['ordered_elapsed_boundary_binary64']['raw'], bytes.fromhex('0000000000c08240'))
        with self.damaged(0x2aeffc6) as corrupt:
            with self.assertRaises(ValueError):
                collector.rip_rows(corrupt, self.secs)

    def test_relative_relocations_and_corruption(self):
        rows = collector.find_relocations(self.data, self.secs)
        slots = {r['role']: r for r in rows}
        self.assertEqual(slots['configuration_cell_slot']['addend'], 0x64f06c0)
        self.assertEqual(slots['path_expander_slot']['addend'], 0x1500c10)
        rec_off = slots['setting_wrapper_slot']['record_offset']
        saved = self.mutable[rec_off + 8]
        self.mutable[rec_off + 8] ^= 1
        try:
            with self.assertRaises(ValueError):
                collector.find_relocations(self.mutable, self.secs)
        finally:
            self.mutable[rec_off + 8] = saved

    def test_full_entry_and_terminator_damage(self):
        rows = {r['role']: r for r in collector.data_rows(self.data, self.secs)}
        setting = rows['setting_full_entry']['raw']
        self.assertTrue(setting.startswith(b'\xc0\x29/'))
        self.assertTrue(setting.endswith(b'.json\0'))
        with self.damaged(0x4315ea + len(setting) - 1) as corrupt:
            with self.assertRaises(ValueError):
                collector.data_rows(corrupt, self.secs)

    def test_tilde_prefix_length_and_all_two_byte_inputs(self):
        gate = collector.va_bytes(self.data, self.secs, 0x1500c24, 6, executable=True)
        compare = collector.va_bytes(self.data, self.secs, 0x1500c37, 6, executable=True)
        self.assertEqual(gate, bytes.fromhex('4883fa02730d'))
        self.assertEqual(compare[:4], bytes.fromhex('6641813f'))
        immediate = int.from_bytes(compare[4:], 'little')
        for number in range(65536):
            candidate = number.to_bytes(2, 'little')
            self.assertEqual(number == immediate, candidate == b'~/')
        for candidate in (b'', b'~', b'/', b'~/child', b'~x'):
            machine_gate = len(candidate) >= 2 and int.from_bytes(candidate[:2], 'little') == immediate
            self.assertEqual(machine_gate, candidate.startswith(b'~/'))

    def test_name_descriptor_length_damage(self):
        with self.damaged(0x63f89a0) as corrupt:
            with self.assertRaises(ValueError):
                collector.data_rows(corrupt, self.secs)

    def test_non_file_backed_and_unmapped_addresses_rejected(self):
        fake = [dict(name='.bss', type=8, flags=3, address=0x100, offset=0, size=8)]
        with self.assertRaises(ValueError):
            collector.locate(fake, 0x100, 1)
        with self.assertRaises(ValueError):
            collector.locate(self.secs, 0xffffffffffffffff, 2)
        with self.assertRaises(ValueError):
            collector.locate(self.secs, 0x4315ea, 0)
        with self.assertRaises(ValueError):
            collector.locate(self.secs, -1, 1)

    def test_cross_section_and_ambiguous_mapping_rejected(self):
        sec = dict(name='a', type=1, flags=2, address=0x100, offset=0, size=8)
        with self.assertRaises(ValueError):
            collector.locate([sec], 0x107, 2)
        with self.assertRaises(ValueError):
            collector.locate([sec, dict(sec, name='b', offset=8)], 0x101, 1)
        with self.assertRaises(ValueError):
            collector.locate([sec], 0x100, 1, executable=True)

    def test_lsda_selected_failure_landings(self):
        f = {x['role']: x for x in self.fdes}
        poll = collector.parse_lsda(self.data, self.secs, f['resume_poll'])
        wrapper = collector.parse_lsda(self.data, self.secs, f['setting_wrapper'])
        def landing(rows, site):
            matches = [r['landing'] for r in rows if r['start'] <= site < r['start'] + r['length']]
            self.assertEqual(len(matches), 1)
            return matches[0]
        self.assertEqual(landing(poll, 0x2af011a), 0x2af047a)
        self.assertEqual(landing(poll, 0x2af017d), 0x2af04dc)
        self.assertEqual(landing(poll, 0x2aefef6), 0x2af056a)
        self.assertEqual(landing(wrapper, 0x1562352), 0x15623b5)

    def test_lsda_header_damage_is_rejected(self):
        fde = next(f for f in self.fdes if f['role'] == 'setting_wrapper')
        with self.damaged(fde['lsda']) as corrupt:
            with self.assertRaises(ValueError):
                collector.parse_lsda(corrupt, self.secs, fde)

    def test_lsda_call_site_encoding_damage_is_rejected(self):
        fde = next(f for f in self.fdes if f['role'] == 'setting_wrapper')
        with self.damaged(fde['lsda'] + 2) as corrupt:
            with self.assertRaises(ValueError):
                collector.parse_lsda(corrupt, self.secs, fde)

    def test_lsda_table_bounds_and_landing_controls(self):
        sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x2000, offset=0, size=4)
        fde = dict(role='test', start=0x1000, end=0x1010, lsda=0x2000)
        with self.assertRaises(ValueError):
            collector.parse_lsda(b'\xff\xff\x01\x05', [sec], fde)
        sec['size'] = 8
        with self.assertRaises(ValueError):
            collector.parse_lsda(b'\xff\xff\x01\x04\x00\x02\x11\x00', [sec], fde)

    def test_signed_minimum_is_the_only_neg_overflow_word(self):
        window = next(w for w in collector.window_rows(self.data, self.secs, self.fdes)
                      if w['role'] == 'reader_text_read')
        self.assertIn(bytes.fromhex('48f7d8713e'), window['raw'])
        words = list(range(65536)) + [1 << 63, (1 << 63) - 1,
                                      (1 << 63) + 1, collector.MAX_U64]
        for word in words:
            signed = word if word < 1 << 63 else word - (1 << 64)
            overflow = not (-(1 << 63) <= -signed < (1 << 63))
            self.assertEqual(overflow, word == 1 << 63)

    def test_integer_boundaries_and_syntax(self):
        cases = {
            b'0': 0, b' 1\n': 1, b'18446744073709551615': collector.MAX_U64,
            b'18446744073709551616': None, b'01': None, b'': None, b'-0': None,
            b'-1': None, b'+1': None, b'1.0': None, b'1e0': None,
            b'1x': None, b'\x0b1': None, b'1\x00': None,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(collector.decimal_integer_model(value), expected)
        with self.assertRaises(TypeError):
            collector.decimal_integer_model('1')

    def test_integer_model_against_independent_json_parser(self):
        def oracle(value):
            try:
                s = value.decode('ascii')
                parsed = json.loads(s)
            except (ValueError, UnicodeDecodeError):
                return None
            if type(parsed) is not int or s.lstrip(' \t\n\r').startswith('-'):
                return None
            return parsed if 0 <= parsed <= collector.MAX_U64 else None
        samples = [str(v).encode() for v in range(1000)]
        samples.extend(str(collector.MAX_U64 + delta).encode() for delta in range(-50, 51))
        samples.extend(bytes([v]) + b'1' for v in range(256))
        samples.extend(b'1' + bytes([v]) for v in range(256))
        for value in samples:
            self.assertEqual(collector.decimal_integer_model(value), oracle(value), repr(value))

    def test_whitespace_mask_all_byte_values(self):
        rows = {r['role']: r for r in collector.data_rows(self.data, self.secs)}
        mask = int.from_bytes(rows['text_whitespace_mask_immediate']['raw'], 'little')
        accepted = {v for v in range(256) if v <= 0x20 and (mask >> v) & 1}
        self.assertEqual(accepted, {9, 10, 13, 32})

    def test_integer_accumulation_cutoff_with_independent_arithmetic(self):
        rows = {r['role']: r for r in collector.data_rows(self.data, self.secs)}
        cutoff_minus_one = int.from_bytes(rows['decimal_cutoff_immediate']['raw'], 'little')
        quotient = cutoff_minus_one + 1
        for acc in range(quotient - 2, quotient + 3):
            for digit in range(10):
                branch_accepts = acc <= cutoff_minus_one or (acc == quotient and digit <= 5)
                self.assertEqual(branch_accepts, acc * 10 + digit <= collector.MAX_U64)

    def test_counter_model_independent_product(self):
        for previous in range(256):
            for setting in range(256):
                threshold = max(setting, 1)
                incremented = previous + 1
                reached = incremented >= threshold
                expected = (threshold, 0 if reached else incremented, int(not reached))
                self.assertEqual(collector.threshold_step(previous, setting), expected)

    def test_threshold_floor_reset_and_saturation(self):
        m = collector.MAX_U64
        cases = [(0, 0, (1, 0, 0)), (0, 1, (1, 0, 0)),
                 (0, 2, (2, 1, 1)), (1, 2, (2, 0, 0)),
                 (m - 2, m, (m, m - 1, 1)), (m - 1, m, (m, 0, 0)),
                 (m, m, (m, 0, 0))]
        for previous, setting, expected in cases:
            self.assertEqual(collector.threshold_step(previous, setting), expected)
        for invalid in (-1, m + 1, True, 1.0):
            with self.assertRaises(ValueError):
                collector.threshold_step(invalid, 1)
            with self.assertRaises(ValueError):
                collector.threshold_step(1, invalid)

    def test_retained_evidence_regenerates(self):
        expected = collector.ROOT / 'research/work-items/RE-015-restart-threshold-115'
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            summary = collector.generate(self.data, target)
            self.assertEqual(summary['selected_dispatch_entries'], 5)
            self.assertEqual(summary['decoded_lsda_call_sites'], 247)
            names = sorted(p.name for p in target.iterdir())
            self.assertEqual(len(names), 10)
            for name in names:
                self.assertEqual((target / name).read_bytes(), (expected / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
