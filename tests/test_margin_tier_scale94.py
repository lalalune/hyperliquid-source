"""Target-bound and adversarial controls for the margin tier view packet."""

from fractions import Fraction
import hashlib
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from tools import margin_tier_scale94 as m


class MarginTierScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = m.BINARY.read_bytes()
        cls.image = m.Image(cls.raw)
        cls.record = m.collect(cls.image)
        cls.constants = cls.record['constants']

    def test_authenticates_full_input_and_qualifies_extents(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), m.TARGET)
        self.assertEqual(len(self.record['functions']), 18)
        self.assertEqual(self.record['functions'][5]['start_va'], '0x2a25ed0')
        self.assertEqual(self.record['functions'][5]['end_va'], '0x2a260d6')
        self.assertEqual(self.record['functions'][5]['fde_va'], '0x112184c')

    def test_corrupt_digest_is_rejected_before_elf_parsing(self):
        altered = bytearray(self.raw)
        altered[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.Image(altered)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.verify_digest(b'not an ELF')

    def test_nobits_and_out_of_range_are_not_file_bytes(self):
        bss = next(s for s in self.image.secs if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file backed'):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read((1 << 64) - 1, 2)
        text = self.image.named_section('.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2, executable=True)
        for va, size in ((-1, 1), (0, 0), (0, -1)):
            with self.assertRaises(ValueError):
                self.image.mapping(va, size)

    def test_wrong_unwind_end_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'FDE'):
            self.image.one_fde(0x2a25ed0, 0x2a260d5)
        with self.assertRaisesRegex(ValueError, 'FDE'):
            self.image.one_fde(1, 2)

    def test_corrupted_body_is_rejected_even_with_valid_outer_digest(self):
        original_read = self.image.read
        start = 0x2a25ed0
        def damaged(va, size, executable=False):
            value = original_read(va, size, executable)
            if va == start:
                value = bytes([value[0] ^ 1]) + value[1:]
            return value
        with patch.object(self.image, 'read', side_effect=damaged):
            with self.assertRaisesRegex(ValueError, 'function byte hash'):
                m.collect(self.image)

    def test_success_response_copy_window_corruption_is_rejected(self):
        stages = {x['role']: x for x in self.record['anchors']}
        self.assertEqual(len(m.FLOW), 6)
        self.assertEqual(stages['converter result staging']['va'], '0x27db9e0')
        self.assertEqual(stages['wrapper return copy']['va'], '0x2587220')
        original_read = self.image.read
        def damaged(va, size, executable=False):
            value = original_read(va, size, executable)
            if va == 0x27dbb60:
                value = bytes([value[0] ^ 1]) + value[1:]
            return value
        with patch.object(self.image, 'read', side_effect=damaged):
            with self.assertRaisesRegex(ValueError, 'instruction anchor'):
                m.collect(self.image)

    def test_branch_decoder_rejects_opcode_and_displacement_mutations(self):
        self.assertEqual(m.decode_branch(b'\x74\x7c', 0x27dbc73, '74'), (2, 0x27dbcf1))
        with self.assertRaisesRegex(ValueError, 'opcode'):
            m.decode_branch(b'\x75\x7c', 0x27dbc73, '74')
        with self.assertRaisesRegex(ValueError, 'truncated'):
            m.decode_branch(b'\x0f\x84\x00', 0, '0f84')
        with patch.object(self.image, 'read', return_value=b'\x74\x7b'):
            with self.assertRaisesRegex(ValueError, 'branch target'):
                m.extract_branch(self.image, 0x27dbc73, '74', 0x27dbcf1, 'test')

    def test_call_and_relocation_corruption_are_rejected(self):
        with patch.object(self.image, 'read', return_value=b'\xe9\xf3\x46\x25\x00'):
            with self.assertRaisesRegex(ValueError, 'direct call'):
                m.extract_call(self.image, 'test', 0x2587158, 'direct', 0x27db850)
        with patch.object(self.image, 'relocations', {0x5774f20: [(8, 0x1234)]}):
            with self.assertRaisesRegex(ValueError, 'call target'):
                m.extract_call(self.image, 'test', 0x27db9da, 'indirect', 0x2a25ed0)
        with patch.object(self.image, 'relocations', {0x5774f20: [(8, 0x2a25ed0), (8, 0x2a25ed0)]}):
            with self.assertRaisesRegex(ValueError, 'relocation'):
                self.image.relocation(0x5774f20)

    def test_named_fields_are_extracted_and_reject_wrong_key(self):
        self.assertEqual([x['name'] for x in self.record['fields']],
                         ['description', 'marginTiers', 'lowerBound', 'maxLeverage'])
        self.assertEqual([x['length'] for x in self.record['fields']], [11, 11, 10, 11])
        with self.assertRaisesRegex(ValueError, 'field name'):
            m.extract_field(self.image, 'tier', 0x2a2629e, b'lowerbound')
        with patch.object(self.image, 'read', return_value=b'\x90' * 15):
            with self.assertRaisesRegex(ValueError, 'field setup'):
                m.extract_field(self.image, 'tier', 0x2a2629e, b'lowerBound')

    def test_selector_boundary_and_failure_precedence(self):
        self.assertEqual(m.selector_route(False, 50, True), ('lookup-error', False))
        self.assertEqual(m.selector_route(True, 49, False), ('call-getter-and-converter', True))
        self.assertEqual(m.selector_route(True, 50, False), ('missing-selector-0x154', False))
        self.assertEqual(m.selector_route(True, 50, True), ('call-getter-and-converter', True))
        self.assertEqual(m.selector_route(True, (1 << 32) - 1, False), ('missing-selector-0x154', False))
        for value in (-1, 1 << 32, True):
            with self.assertRaises(ValueError):
                m.selector_route(True, value, False)
        with self.assertRaises(ValueError):
            m.selector_route(1, 49, False)

    def test_allocation_boundaries_and_row_stride(self):
        c = self.record
        self.assertEqual(c['row_stride'], 16)
        self.assertEqual(c['vector_limit'] // c['row_stride'], (1 << 59) - 1)
        self.assertLessEqual(((1 << 59) - 1) * 16, c['vector_limit'])
        self.assertGreater((1 << 59) * 16, c['vector_limit'])
        q = c['serial_limit']
        self.assertLessEqual(q * 72, (1 << 63) - 1)
        self.assertGreater((q + 1) * 72, (1 << 63) - 1)

    def test_collection_count_and_helper_boundaries(self):
        limit = self.record['collection_limit']
        cutoff = self.record['collection_cutoff']
        self.assertEqual(self.record['collection_stride'], 56)
        self.assertEqual(limit, ((1 << 63) - 1) // 56)
        for declared, emitted, route in ((0, 0, 'empty'), (1, 1, 'single-no-preparation-helper'),
                                        (20, 20, 'direct-preparation-helper'),
                                        (21, 21, 'indirect-preparation-helper'),
                                        (limit + 1, None, 'size-overflow')):
            self.assertEqual(m.collection_route(declared, emitted, limit, cutoff), route)
        for declared, emitted in ((-1, 0), (3, 4), (3, 0), (3, 1), (1, -1)):
            with self.assertRaises(ValueError):
                m.collection_route(declared, emitted, limit, cutoff)


    def test_tree_layout_bridge_and_boundary_controls(self):
        layout = self.record['bridge']
        self.assertEqual(layout['key_offset'], 0x218)
        self.assertEqual(layout['payload_stride'], 48)
        self.assertEqual(layout['node_count_offset'], 0x246)
        self.assertEqual(layout['initial_node_allocation_bytes'], 0x248)
        self.assertEqual(layout['node_slots_on_simple_insert'], 11)
        self.assertEqual(layout['special_field_key'], '$serde_json::private::RawValue')
        for index in range(layout['node_slots_on_simple_insert']):
            for key in (0, 49, 50, (1 << 32) - 1):
                payload = bytes((index + n) & 255 for n in range(48))
                actual = m.simulate_bridge(layout, index, key, payload)
                self.assertEqual(actual['key_offset'], 0x218 + index * 4)
                self.assertEqual(actual['payload_offset'], index * 48)
                self.assertEqual(actual['observed_key'], key)
                self.assertTrue(actual['payload_equal'])
        for index, key, payload in ((-1, 0, bytes(48)), (11, 0, bytes(48)),
                                    (0, -1, bytes(48)), (0, 1 << 32, bytes(48)),
                                    (0, 0, bytes(47))):
            with self.assertRaises(ValueError):
                m.simulate_bridge(layout, index, key, payload)

    def test_bridge_rejects_mismatched_tree_offsets_and_stride(self):
        original_read = self.image.read
        def alter_offset(va, size, executable=False):
            value = original_read(va, size, executable)
            if va == 0x2a1441a:
                return value[:-4] + (0x21c).to_bytes(4, 'little')
            return value
        with patch.object(self.image, 'read', side_effect=alter_offset):
            with self.assertRaisesRegex(ValueError, 'key offsets differ'):
                m.bridge_layout(self.image)
        def alter_stride(va, size, executable=False):
            value = original_read(va, size, executable)
            if va == 0x2a14425:
                value = value[:7] + bytes([value[7] ^ 1]) + value[8:]
            return value
        with patch.object(self.image, 'read', side_effect=alter_stride):
            with self.assertRaisesRegex(ValueError, 'payload-address stride'):
                m.bridge_layout(self.image)

    def test_special_writer_field_bytes_are_not_generic_names(self):
        self.assertEqual(self.record['bridge']['special_field_key'], '$serde_json::private::RawValue')
        original_read = self.image.read
        def alter_constant(va, size, executable=False):
            value = original_read(va, size, executable)
            if va == 0x206110:
                return bytes([value[0] ^ 1]) + value[1:]
            return value
        with patch.object(self.image, 'read', side_effect=alter_constant):
            with self.assertRaisesRegex(ValueError, 'special field key'):
                m.bridge_layout(self.image)


    def test_keyed_writer_state_and_length_failures(self):
        special = self.record['bridge']['special_field_key'].encode('ascii')
        margin = self.record['bridge']['margin_field_key'].encode('ascii')
        self.assertEqual(m.keyed_route(True, len(margin), margin, special), 'special-wrong-length-error')
        self.assertEqual(m.keyed_route(True, len(special), special, special), 'special-value-call')
        altered = special[:-1] + b'X'
        self.assertEqual(m.keyed_route(True, len(altered), altered, special), 'special-wrong-key-error')
        self.assertEqual(m.keyed_route(False, 0, b'', special), 'ordinary-empty-name-then-tree')
        self.assertEqual(m.keyed_route(False, len(margin), margin, special), 'ordinary-allocate-then-tree-on-success')
        self.assertEqual(m.keyed_route(False, (1 << 63) - 1, b'', special), 'ordinary-allocate-then-tree-on-success')
        self.assertEqual(m.keyed_route(False, 1 << 63, b'', special), 'field-allocation-size-error')
        with self.assertRaisesRegex(ValueError, 'truncated'):
            m.keyed_route(True, len(special), b'', special)
        with self.assertRaises(ValueError):
            m.keyed_route(False, 1 << 64, b'', special)

    def test_ties_to_even_are_independently_checked(self):
        one = 0x3ff0000000000000
        self.assertEqual(m.round_binary64(Fraction(1, 1) + Fraction(1, 1 << 53)), one)
        self.assertEqual(m.round_binary64(Fraction(1, 1) + Fraction(3, 1 << 53)), one + 2)
        self.assertEqual(m.round_binary64(Fraction(1, 1) + Fraction(5, 1 << 53)), one + 2)
        self.assertEqual(m.round_binary64(Fraction(1, 1 << 1075)), 0)
        self.assertEqual(m.round_binary64(Fraction(3, 1 << 1075)), 2)

    def test_full_width_lane_premises_and_corruption(self):
        facts = m.prove_lane_lift(self.constants)
        self.assertEqual([(x['binary_exponent'], x['payload_bits'], x['payload_unit']) for x in facts],
                         [(52, 32, 1), (84, 32, 1 << 32)])
        corrupt = dict(self.constants)
        corrupt['bias_low'] ^= 1
        with self.assertRaisesRegex(ValueError, 'prefix and bias'):
            m.prove_lane_lift(corrupt)
        corrupt = dict(self.constants)
        corrupt['unpack_high'] ^= 1 << 20
        corrupt['bias_high'] = corrupt['unpack_high'] << 32
        with self.assertRaisesRegex(ValueError, 'lane bias'):
            m.prove_lane_lift(corrupt)

    def test_integer_conversion_and_division_match_independent_host(self):
        # struct/float is an independent implementation of IEEE binary64 on this
        # platform, not a node execution or proof of the node's runtime mode.
        values = m.host_control_inputs()
        self.assertEqual(len(values), 2243)
        self.assertEqual((values[0], values[-1]), (0, (1 << 64) - 1))
        for value in values:
            with self.subTest(value=value):
                converted, result = m.simd_conversion(value, self.constants)
                expected_first = struct.unpack('<Q', struct.pack('<d', float(value)))[0]
                expected_second = struct.unpack('<Q', struct.pack('<d', float(value) / 1000000.0))[0]
                self.assertEqual(converted, expected_first)
                self.assertEqual(result, expected_second)
                self.assertEqual(m.integer_round_u64(value)[0], int(float(value)))

    def test_exact_decimal_ratio_and_double_rounding_witness(self):
        divisor = m.float_fraction(self.constants['divisor_bits'])
        self.assertEqual(divisor, 1000000)
        for x in (0, 1, 1000, 15624, 15625, 15626, 10**15):
            _, got = m.simd_conversion(x, self.constants)
            self.assertEqual(m.float_fraction(got) == Fraction(x, 1000000), x % 15625 == 0)
        x = 9007199254740993
        _, actual = m.simd_conversion(x, self.constants)
        direct = m.round_binary64(Fraction(x, 1000000))
        self.assertEqual(actual, 0x4200c6f7a0b5ed8d)
        self.assertEqual(direct, 0x4200c6f7a0b5ed8e)
        self.assertNotEqual(actual, direct)

    def test_two_roundings_can_lose_an_exact_integer_ratio(self):
        witness = m.exact_ratio_witness(self.constants)
        raw = witness['raw_u64']
        self.assertEqual(raw, 9223372036880000000)
        self.assertEqual(raw % 15625, 0)
        self.assertEqual(Fraction(raw, 1000000), 9223372036880)
        first, result = m.simd_conversion(raw, self.constants)
        self.assertEqual(m.float_fraction(first), raw - 1024)
        self.assertEqual(result, 0x42a0c6f7a0b61fff)
        self.assertEqual(m.round_binary64(Fraction(raw, 1000000)), 0x42a0c6f7a0b62000)
        self.assertNotEqual(m.float_fraction(result), Fraction(raw, 1000000))
        self.assertNotEqual(m.float_fraction(m.round_binary64(Fraction(raw - 1, 1000000))),
                            Fraction(raw - 1, 1000000))

    def test_prior_admission_cap_would_make_integer_stage_exact(self):
        # RE-007's separate tier-admission evidence reports this cap. The
        # ownership link to this converter is not established by this test.
        cap = 10**15
        self.assertLess(cap, 1 << 53)
        for raw in (0, 1, 15624, 15625, cap - 1, cap):
            integer_bits, result_bits = m.simd_conversion(raw, self.constants)
            self.assertEqual(m.float_fraction(integer_bits), raw)
            exact_ratio = Fraction(raw, 1000000)
            self.assertEqual(result_bits, m.round_binary64(exact_ratio))
            self.assertLessEqual(abs(m.float_fraction(result_bits) - exact_ratio),
                                 Fraction(1, 1 << 24))
        self.assertGreater(Fraction(1, 1000000), Fraction(1, 1 << 23))
        for raw in (0, 1, 15624, cap - 2, cap - 1):
            _, left = m.simd_conversion(raw, self.constants)
            _, right = m.simd_conversion(raw + 1, self.constants)
            self.assertLess(left, right)
        integer_bits, _ = m.simd_conversion((1 << 53) + 1, self.constants)
        self.assertNotEqual(m.float_fraction(integer_bits), (1 << 53) + 1)

    def test_integer_conversion_partition_and_ties(self):
        bins = m.integer_conversion_bins(self.constants)
        self.assertEqual(len(bins), 12)
        self.assertEqual(bins[0]['upper_exclusive'], 1 << 53)
        self.assertEqual(bins[-1]['upper_exclusive'], 1 << 64)
        self.assertEqual(sum(row['input_count'] for row in bins), 1 << 64)
        self.assertEqual(Fraction(sum(row['exact_count'] for row in bins), 1 << 64),
                         Fraction(13, 4096))
        self.assertEqual(sum(row['midpoint_tie_count'] for row in bins), 11 * (1 << 52))
        for previous, current in zip(bins, bins[1:]):
            self.assertEqual(previous['upper_exclusive'], current['lower_u64'])
            lower, spacing = current['lower_u64'], current['integer_spacing']
            first_tie, _ = m.simd_conversion(lower + spacing // 2, self.constants)
            next_tie, _ = m.simd_conversion(lower + spacing + spacing // 2, self.constants)
            self.assertEqual(m.float_fraction(first_tie), lower)
            self.assertEqual(m.float_fraction(next_tie), lower + 2 * spacing)
            self.assertEqual(current['max_integer_error'], spacing // 2)
        damaged = dict(self.constants)
        damaged['bias_low'] ^= 1
        with self.assertRaisesRegex(ValueError, 'prefix and bias'):
            m.integer_conversion_bins(damaged)

    def test_integer_lift_rounding_routes_and_upper_carry(self):
        boundary = 1 << 53
        cases = ((boundary, boundary, 'exact'),
                 (boundary + 1, boundary, 'tie-even-down'),
                 (boundary + 3, boundary + 4, 'tie-even-up'),
                 ((1 << 54) + 1, 1 << 54, 'round-down'),
                 ((1 << 54) + 3, (1 << 54) + 4, 'round-up'),
                 ((1 << 64) - 1, 1 << 64, 'round-up'))
        for raw, expected_integer, expected_route in cases:
            self.assertEqual(m.integer_round_u64(raw), (expected_integer, expected_route))
            bits, _ = m.simd_conversion(raw, self.constants)
            self.assertEqual(m.float_fraction(bits), expected_integer)
        for raw in (-1, 1 << 64, True, 1.5):
            with self.assertRaises(ValueError):
                m.integer_round_u64(raw)

    def test_earliest_adjacent_collision_boundary(self):
        proof = m.earliest_output_collision(self.constants)
        threshold = proof['threshold_raw_u64']
        self.assertEqual(proof['threshold_quotient_power_of_two'], 33)
        self.assertEqual(threshold, (1 << 33) * 1000000)
        self.assertEqual((proof['first_raw_u64'], proof['second_raw_u64']),
                         (8589934592000001, 8589934592000002))
        self.assertEqual(proof['shared_result_f64_bits'], '4200000000000001')
        outputs = [m.simd_conversion(x, self.constants)[1] for x in range(threshold - 1, threshold + 4)]
        self.assertNotEqual(outputs[0], outputs[1])
        self.assertNotEqual(outputs[1], outputs[2])
        self.assertEqual(outputs[2], outputs[3])
        self.assertNotEqual(outputs[3], outputs[4])
        for raw, result in zip(range(threshold - 1, threshold + 4), outputs):
            host_bits = struct.unpack('<Q', struct.pack('<d', float(raw) / 1000000.0))[0]
            self.assertEqual(result, host_bits)
        damaged = dict(self.constants)
        damaged['divisor_bits'] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected divisor'):
            m.earliest_output_collision(damaged)


    def test_full_u64_absolute_error_bound_and_attaining_integer_tie(self):
        bounds = m.u64_rounding_error_bound(self.constants)
        self.assertEqual(bounds['integer_conversion_error_max'], 1024)
        self.assertEqual(bounds['integer_error_attaining_u64'], (1 << 63) + 1024)
        self.assertEqual(bounds['quotient_upper_bound_binade'], 44)
        bound = Fraction(bounds['total_error_bound_numerator'], bounds['total_error_bound_denominator'])
        self.assertEqual(bound, Fraction(16, 15625) + Fraction(1, 512))
        for row in m.cases(self.constants):
            u = row['raw_u64']
            result = m.float_fraction(int(row['view_f64_bits'], 16))
            self.assertLessEqual(abs(result - Fraction(u, 1000000)), bound)
        damaged = dict(self.constants)
        damaged['divisor_bits'] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected divisor'):
            m.u64_rounding_error_bound(damaged)

    def test_nonrepresentable_inputs_are_rejected(self):
        for value in (-1, 1 << 64, True, 0.0):
            with self.assertRaises(ValueError):
                m.simd_conversion(value, self.constants)
        for bits in (-1, 1 << 63, 0x7ff0000000000000):
            with self.assertRaises(ValueError):
                m.float_fraction(bits)
        with self.assertRaises(ValueError):
            m.round_binary64(Fraction(-1, 2))

    def test_case_generator_is_stable_and_boundary_complete(self):
        a = m.cases(self.constants)
        b = m.cases(self.constants)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 255)
        self.assertEqual(a[0]['raw_u64'], 0)
        self.assertEqual(a[-1]['raw_u64'], (1 << 64) - 1)
        self.assertEqual(sum(x['two_step_differs'] for x in a), 4)
        self.assertEqual(len(self.record['branches']), 67)
        self.assertEqual(len(self.record['calls']), 24)
        self.assertEqual(len(self.record['anchors']), 34)


if __name__ == '__main__':
    unittest.main()
