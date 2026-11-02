"""Static extraction controls and independent arithmetic checks for node 94."""
import copy
import csv
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import evm_fee_bump94 as subject


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = subject.Image(subject.ARTIFACT.read_bytes())

    def test_artifact_digest_and_wrong_digest(self):
        self.assertEqual(subject.check_digest(self.img.data), subject.DIGEST)
        corrupt = bytearray(self.img.data)
        corrupt[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.check_digest(corrupt)

    def test_file_mapping_rejects_nobits_ambiguous_and_out_of_bounds(self):
        sections = [dict(type=1, size=8, address=0x100, offset=0x20, flags=4),
                    dict(type=8, size=8, address=0x200, offset=0x28, flags=3)]
        self.assertEqual(subject.file_offset(sections, 0x102, 2, True), 0x22)
        for va, size in [(0xff, 1), (0x107, 2), (0x200, 1), (0x100, 0), (-1, 1)]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                subject.file_offset(sections, va, size)
        with self.assertRaises(ValueError):
            subject.file_offset(sections + [dict(sections[0])], 0x100, 1)

    def test_selected_fdes_and_code_hashes(self):
        functions = self.img.validate_functions()
        self.assertEqual(len(functions), 10)
        self.assertEqual(functions[0]['start_va'], '0x3428000')
        self.assertEqual(functions[0]['end_va_exclusive'], '0x3428462')
        self.assertEqual(functions[0]['file_offset'], '0x3427000')
        self.assertEqual(hashlib.sha256(bytes.fromhex(functions[0]['bytes_hex'])).hexdigest(),
                         functions[0]['sha256'])
        damaged = copy.copy(self.img)
        damaged.fdes = dict(self.img.fdes)
        damaged.fdes.pop(0x3428000)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            damaged.validate_functions()
        damaged.fdes[0x3428000] = dict(self.img.fdes[0x3428000], end=0x3428461)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            damaged.validate_functions()

    def test_fde_overlap_and_extent_controls(self):
        one = {'start': 100, 'end': 120}
        selected, _ = subject.select_nonoverlapping_fdes([one], [(100, 120)])
        self.assertEqual(selected[100], one)
        for rows in ([], [one, dict(one)], [one, {'start': 110, 'end': 130}],
                     [{'start': 100, 'end': 119}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                subject.select_nonoverlapping_fdes(rows, [(100, 120)])

    def test_mutated_function_byte_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x3428000 and size == 0x462:
                value = bytearray(raw)
                value[0x2f0] ^= 1
                return bytes(value)
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'function bytes differ'):
                self.img.validate_functions()

    def test_mutated_arithmetic_immediate_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x34282e3:
                return raw[:-1] + bytes([raw[-1] ^ 1])
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'instruction pattern differs'):
                subject.assert_arithmetic_patterns(self.img)

    def test_branch_decoding_and_mutants(self):
        rows = subject.extracted_branches(self.img)
        self.assertEqual(len(rows), 20)
        self.assertEqual(rows[-1][4], '')
        self.assertEqual(subject.decode_branch(bytes.fromhex('760e'), 0x3428361),
                         ('jbe', 0x3428371, 2))
        with self.assertRaises(ValueError):
            subject.decode_branch(b'\x90\x90', 0x1000)
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x342831c:
                value = bytearray(raw)
                value[2] ^= 1
                return bytes(value)
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'branch differs'):
                subject.extracted_branches(self.img)

    def test_all_variant_labels_and_offsets(self):
        variants = subject.get_variants(self.img)
        self.assertEqual([v['name'] for v in variants],
                         ['Legacy', 'Eip2930', 'Eip1559', 'Eip4844', 'Eip7702'])
        self.assertEqual([v['new_nonce_offset'] for v in variants],
                         ['0x70', '0x68', '0x78', '0x88', '0x78'])
        self.assertEqual([v['fields'][1]['tagged_offset'] for v in variants],
                         ['0x40', '0x50', '0x50', '0x50', '0x50'])
        for v in variants[2:]:
            self.assertEqual(v['fields'][2]['field'], 'maxPriorityFeePerGas')
            self.assertEqual(v['fields'][2]['tagged_offset'], '0x60')

    def test_vector_serializer_row_stride_bridge(self):
        bridge = subject.get_layout_bridge(self.img)
        self.assertEqual((bridge['vector_stride'], bridge['scanner_row_stride'],
                          bridge['old_row_tagged_offset']), (0x150, 0x160, 0x10))
        self.assertEqual((bridge['old_first_offset'], bridge['new_first_offset'],
                          bridge['first_step_nonzero_tag'], bridge['old_second_offset'],
                          bridge['new_second_offset']), (0x40, 0x40, 0x10, 0x60, 0x60))
        with mock.patch.object(self.img, 'call_target', return_value=0):
            with self.assertRaisesRegex(ValueError, 'serializer call differs'):
                subject.get_layout_bridge(self.img)

    def test_mutated_serializer_field_offset_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x1e651d4:
                return raw[:-1] + b'\x40'
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'first fee offset'):
                subject.get_variants(self.img)

    def test_mutated_old_fee_load_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x3428363:
                value = bytearray(raw)
                value[3] ^= 8
                return bytes(value)
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'old and new fee field layouts differ'):
                subject.get_layout_bridge(self.img)

    def test_mutated_nonce_jump_table_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x58c5b8 + 2 * 4:
                value = bytearray(raw)
                value[0] ^= 1
                return bytes(value)
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaises(ValueError):
                subject.get_variants(self.img)

    def test_mutated_error_message_is_rejected(self):
        original_read = self.img.read
        def damaged_read(va, size, executable=False):
            raw = original_read(va, size, executable)
            if va == 0x7c20e9:
                return b'X' + raw[1:]
            return raw
        with mock.patch.object(self.img, 'read', side_effect=damaged_read):
            with self.assertRaisesRegex(ValueError, 'error message differs'):
                subject.get_errors(self.img)

    def test_error_formatters_and_relocation_control(self):
        errors = subject.get_errors(self.img)
        self.assertEqual([(v['payload'], v['message']) for v in errors],
                         [(0, 'already known'), (4, 'replacement transaction underpriced')])
        with mock.patch.object(self.img, 'relocation_target', return_value=0):
            with self.assertRaisesRegex(ValueError, 'outer error'):
                subject.get_errors(self.img)

    def test_division_relocation_control(self):
        self.assertEqual(subject.assert_arithmetic_patterns(self.img), (110, 100))
        with mock.patch.object(self.img, 'relocation_target', return_value=0):
            with self.assertRaisesRegex(ValueError, 'division relocation'):
                subject.assert_arithmetic_patterns(self.img)

    def test_generation_is_complete_and_repeatable(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a, b = Path(first), Path(second)
            counts_a = subject.generate(a, self.img)
            counts_b = subject.generate(b, self.img)
            self.assertEqual(counts_a, counts_b)
            self.assertEqual(counts_a['row_model_cases'], 250)
            expected = {'evidence.json', 'arithmetic-proof.json', 'branches.tsv', 'windows.tsv',
                        'scalar-model.tsv', 'row-model.tsv', 'residues.tsv'}
            self.assertEqual({p.name for p in a.iterdir()}, expected)
            self.assertEqual({p.name for p in b.iterdir()}, expected)
            for name in sorted(expected):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)
            # Independent expected-path table. Group order is old<2/new<2,
            # old<2/new>=2, old>=2/new<2, old>=2/new>=2.
            absent, zero, passed = 'second_absent_new', 'second_zero', 'second_pass'
            standard = (absent, zero, absent, passed)
            expected_paths = {
                'first_equal_tiny': standard,
                'first_one_below': ('first_below',) * 4,
                'first_exact': standard,
                'second_one_below': (absent, zero, absent, 'second_below'),
                'second_zero_new': (absent, zero, absent, zero),
                'second_zero_old': (absent, zero, absent, zero),
                'second_exact': standard,
                'both_zero': (absent, zero, absent, zero),
                'first_overflow': ('first_overflow',) * 4,
                'second_overflow': (absent, zero, absent, 'second_overflow'),
            }
            with (a / 'row-model.tsv').open(encoding='utf-8', newline='') as handle:
                rows = list(csv.DictReader(handle, delimiter='\t'))
            self.assertEqual(len(rows), 250)
            self.assertEqual({row['case'] for row in rows}, set(expected_paths))
            self.assertEqual(len({(row['case'], row['old_tag'], row['new_tag']) for row in rows}), 250)
            for row in rows:
                group = 2 * (int(row['old_tag']) >= 2) + (int(row['new_tag']) >= 2)
                path = expected_paths[row['case']][group]
                self.assertEqual(row['modeled_path'], path, row)
                returned = path in ('first_below', 'first_overflow', 'second_below', 'second_overflow')
                self.assertEqual((row['output_tag_if_return'], row['output_payload_if_return']),
                                 ('3', '4') if returned else ('', ''), row)


class ArithmeticTests(unittest.TestCase):
    def test_small_rounding_and_ties(self):
        for old in range(10):
            self.assertEqual(subject.limbs_product(old), (False, old))
        for old, want in [(10, 11), (11, 12), (19, 20), (20, 22), (100, 110)]:
            self.assertEqual(subject.limbs_product(old), (False, want))
        self.assertEqual(subject.evaluate(2, 2, 9, 9, 1, 1), ('second_pass', None, None))
        self.assertEqual(subject.evaluate(2, 2, 10, 10, 10, 11), ('first_below', 3, 4))
        self.assertEqual(subject.evaluate(2, 2, 10, 11, 10, 10), ('second_below', 3, 4))

    def test_overflow_boundary_and_both_limb_overflow_mechanisms(self):
        bound = subject.MAX128 // 110
        self.assertEqual(subject.limbs_product(bound), (False, bound + bound // 10))
        self.assertTrue(subject.limbs_product(bound + 1)[0])
        self.assertLessEqual(bound * 110, subject.MAX128)
        self.assertGreater((bound + 1) * 110, subject.MAX128)
        self.assertLessEqual(((bound + 1) * 110) // 100, subject.MAX128)
        base = 1 << 64
        high = (base - 1) // 110
        carry_case = (high << 64) | (base - 1)
        self.assertLess(high * 110, base)
        self.assertGreaterEqual(high * 110 + ((base - 1) * 110 // base), base)
        self.assertTrue(subject.limbs_product(carry_case)[0])
        high_overflow = ((base + 109) // 110) << 64
        self.assertGreaterEqual((high_overflow >> 64) * 110, base)
        self.assertTrue(subject.limbs_product(high_overflow)[0])

    def test_all_domain_scale_obligations_and_bad_constants(self):
        proof, residues = subject.scale_proof(110, 100)
        self.assertEqual((proof['period'], proof['advance']), (10, 11))
        self.assertEqual(proof['coefficient_left'], proof['coefficient_right'])
        self.assertEqual(len(residues), 10)
        self.assertEqual([row[2] for row in residues], list(range(10)))
        self.assertTrue(all(0 <= row[3] < 100 for row in residues))
        for multiplier, divisor in [(111, 100), (110, 101), (0, 100), (110, 0)]:
            with self.subTest(multiplier=multiplier, divisor=divisor), self.assertRaises(ValueError):
                subject.scale_proof(multiplier, divisor)

    def test_residue_identity_and_boundary_samples(self):
        bound = subject.MAX128 // 110
        # q is representative; the README supplies the algebraic all-q argument.
        for q in (0, 1, 9, (1 << 64), bound // 10 - 1, bound // 10):
            for r in range(10):
                value = 10 * q + r
                if value <= bound:
                    overflow, quotient = subject.limbs_product(value)
                    self.assertFalse(overflow)
                    self.assertEqual(quotient, (110 * value) // 100)
                    self.assertEqual(quotient, value + value // 10)
        for value in [0, 1, (1 << 64) - 1, 1 << 64, bound - 1, bound, bound + 1, subject.MAX128]:
            overflow, quotient = subject.limbs_product(value)
            self.assertEqual(overflow, value * 110 > subject.MAX128)
            if not overflow:
                self.assertEqual(quotient, (value * 110) // 100)

    def test_all_tag_pairs_second_value_rules(self):
        for old_tag in range(5):
            for new_tag in range(5):
                actual = subject.evaluate(old_tag, new_tag, 10, 11, 10, 10)
                if new_tag < 2:
                    expected = ('second_absent_new', None, None)
                elif old_tag < 2:
                    expected = ('second_zero', None, None)
                else:
                    expected = ('second_below', 3, 4)
                self.assertEqual(actual, expected, (old_tag, new_tag))

    def test_zero_bypass_overflow_priority_and_pass(self):
        bound = subject.MAX128 // 110
        self.assertEqual(subject.evaluate(2, 2, 10, 11, 10, 0), ('second_zero', None, None))
        self.assertEqual(subject.evaluate(2, 2, 10, 11, 0, 10), ('second_zero', None, None))
        self.assertEqual(subject.evaluate(2, 2, bound + 1, subject.MAX128, 10, 0),
                         ('first_overflow', 3, 4))
        self.assertEqual(subject.evaluate(2, 2, 10, 11, bound + 1, subject.MAX128),
                         ('second_overflow', 3, 4))
        self.assertEqual(subject.evaluate(2, 2, 10, 11, 10, 11), ('second_pass', None, None))
        self.assertEqual(subject.evaluate(2, 0, 10, 11, bound + 1, subject.MAX128),
                         ('second_absent_new', None, None))

    def test_invalid_tags_and_u128_values_are_rejected(self):
        for old, new in [(-1, 0), (0, 5), (9, 1)]:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                subject.evaluate(old, new, 1, 1, 1, 1)
        for value in [-1, subject.MAX128 + 1]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.limbs_product(value)
            with self.assertRaises(ValueError):
                subject.evaluate(0, 0, value, 1, 1, 1)


if __name__ == '__main__':
    unittest.main()
