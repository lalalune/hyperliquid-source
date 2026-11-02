import copy
import hashlib
import math
import struct
import unittest

from tools import aws_scalar_input94 as m


class Overlay:
    """Change a virtual byte range without copying or modifying the capture."""
    def __init__(self, image, va, replacement):
        self.image = image
        self.va = va
        self.replacement = replacement
        self.sections = image.sections
        self.fdes = image.fdes
        self.context_fdes = image.context_fdes
        self.relocations = image.relocations

    def offset(self, va, size=1):
        return self.image.offset(va, size)

    def read(self, va, size):
        raw = bytearray(self.image.read(va, size))
        lo = max(va, self.va)
        hi = min(va + size, self.va + len(self.replacement))
        if lo < hi:
            raw[lo - va:hi - va] = self.replacement[lo - self.va:hi - self.va]
        return bytes(raw)

    def pin(self, va, expected):
        expected = bytes.fromhex(expected)
        m.require(self.read(va, len(expected)) == expected, 'overlaid contract mismatch')

    def relative(self, slot):
        m.require(slot in self.relocations, 'unresolved relative slot')
        return self.relocations[slot][0]


class ScalarInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.ARTIFACT.read_bytes()
        cls.image = m.Image(cls.data)
        cls.record = m.analyze(cls.image)

    def test_target_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.DIGEST)
        bad = bytearray(self.data)
        bad[0x200] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            m.Image(bad)

    def test_unmapped_and_non_file_backed_ranges_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(0, 1 << 63)
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_reject_ambiguous_file_backing(self):
        alias = copy.copy(self.image)
        section = next(s for s in self.image.sections if s['name'] == '.text')
        alias.sections = self.image.sections + [dict(section)]
        with self.assertRaises(ValueError):
            alias.read(0x13c1720, 1)

    def test_full_fde_partition_and_body_hashes(self):
        for function in self.record['functions']:
            selected = [r for r in self.record['instructions'] if r['owner'] == function['start']]
            self.assertEqual(selected[0]['va'], function['start'])
            self.assertEqual(selected[-1]['va'] + selected[-1]['size'], function['end'])
            self.assertEqual(sum(r['size'] for r in selected), function['byte_count'])
            self.assertEqual(hashlib.sha256(self.image.read(function['start'],
                                function['byte_count'])).hexdigest(), function['body_sha256'])

    def test_direct_branch_destinations_against_raw_displacements(self):
        owners = {r['va']: r['owner'] for r in self.record['instructions']}
        branches = [r for r in self.record['instructions'] if r['kind'] in ('branch', 'jump')]
        for row in branches:
            raw = self.image.read(row['va'], row['size'])
            if 0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb:
                disp = struct.unpack('<b', raw[-1:])[0]
            elif raw[0] == 0xe9 or raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
                disp = struct.unpack('<i', raw[-4:])[0]
            else:
                self.fail(f'unexpected direct branch encoding {raw.hex()}')
            target = row['va'] + len(raw) + disp
            self.assertEqual(target, row['target'])
            self.assertEqual(owners[target], row['owner'])

    def test_rip_relative_targets_against_encoded_displacements(self):
        rows = [r for r in self.record['instructions']
                if r.get('memory', {}).get('base') == 'rip']
        self.assertEqual(len(rows), 72)
        for row in rows:
            # These selected RIP-relative encodings have no trailing immediate;
            # their signed displacement therefore occupies the final four bytes.
            self.assertNotIn('immediate', row)
            raw = self.image.read(row['va'], row['size'])
            displacement = struct.unpack('<i', raw[-4:])[0]
            self.assertEqual(row['memory']['disp'], displacement)
            self.assertEqual(row['rip_target'], row['va'] + len(raw) + displacement)

    def test_selector_offsets_use_table_base_not_slot_address(self):
        for row in self.record['slots']:
            raw = self.image.read(row['slot'], 4)
            displacement = struct.unpack('<i', raw)[0]
            self.assertEqual(m.SELECTOR + displacement, row['target'])
        for row in self.record['format_slots']:
            raw = self.image.read(row['slot'], 4)
            displacement = struct.unpack('<i', raw)[0]
            self.assertEqual(0x7c93b4 + displacement, row['target'])

    def test_fde_extent_change_is_refused(self):
        altered = copy.copy(self.image)
        altered.fdes = {k: dict(v) for k, v in self.image.fdes.items()}
        altered.fdes[0x13c1720]['end'] -= 1
        with self.assertRaisesRegex(ValueError, 'FDE end'):
            m.analyze(altered)

    def test_arbitrary_body_change_is_refused(self):
        original = self.image.read(0x1407ff1, 1)
        altered = Overlay(self.image, 0x1407ff1, bytes([original[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            m.analyze(altered)

    def test_table_has_exact_reviewed_targets(self):
        self.assertEqual(len(self.record['slots']), 33)
        for row in self.record['slots']:
            expected = m.ARMS.get(row['code'], (m.DEFER, 'deferred'))
            self.assertEqual((row['target'], row['role']), expected)

    def test_table_redirect_to_valid_wrong_arm_is_refused(self):
        slot = m.SELECTOR + 4 * (0xc2 - 0xc0)
        wrong = struct.pack('<i', 0x13c1958 - m.SELECTOR)
        with self.assertRaisesRegex(ValueError, 'redirected'):
            m.analyze(Overlay(self.image, slot, wrong), body_gates=False)

    def test_table_redirect_into_instruction_is_refused(self):
        slot = m.SELECTOR + 4 * (0xc2 - 0xc0)
        wrong = struct.pack('<i', 0x13c1955 - m.SELECTOR)
        with self.assertRaisesRegex(ValueError, 'instruction start'):
            m.analyze(Overlay(self.image, slot, wrong), body_gates=False)

    def test_wrong_width_guard_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'width guard'):
            m.analyze(Overlay(self.image, 0x13c174c, b'\x08'), body_gates=False)

    def test_inverted_length_branch_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'length-guard branch'):
            m.analyze(Overlay(self.image, 0x13c1855, b'\x82'), body_gates=False)

    def test_bad_byte_order_sequence_is_refused(self):
        with self.assertRaises(ValueError):
            m.analyze(Overlay(self.image, 0x13c175e, b'\xcb'), body_gates=False)

    def test_incorrect_sign_extension_is_refused(self):
        with self.assertRaises(ValueError):
            m.analyze(Overlay(self.image, 0x140846a, b'\xb6'), body_gates=False)

    def test_wrong_visitor_target_is_refused(self):
        va = 0x13c196d
        replacement = b'\xe8' + struct.pack('<i', 0x1407ff0 - (va + 5))
        with self.assertRaisesRegex(ValueError, 'scalar call changed'):
            m.analyze(Overlay(self.image, va, replacement), body_gates=False)

    def test_wrong_visitor_tag_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'descriptor tag'):
            m.analyze(Overlay(self.image, 0x14081bc, b'\x06'), body_gates=False)

    def test_bad_expected_type_relocation_is_refused(self):
        altered = copy.copy(self.image)
        altered.relocations = dict(self.image.relocations)
        _, pos = altered.relocations[0x5668e90]
        altered.relocations[0x5668e90] = (0x14010e0, pos)
        with self.assertRaisesRegex(ValueError, 'RELATIVE addend'):
            m.analyze(altered, body_gates=False)

    def test_relative_relocation_with_symbol_is_refused(self):
        bad = bytearray(self.data)
        pos = self.image.relocations[0x576e7a0][1]
        struct.pack_into('<I', bad, pos + 12, 1)
        with self.assertRaisesRegex(ValueError, 'relocation has a symbol'):
            m.Image(bad, authenticate=False)

    def test_duplicate_relative_slot_is_refused(self):
        bad = bytearray(self.data)
        pos = self.image.relocations[0x576e7a0][1]
        struct.pack_into('<Q', bad, pos, 0x576e758)
        with self.assertRaisesRegex(ValueError, 'duplicate relative relocation'):
            m.Image(bad, authenticate=False)

    def test_short_input_message_corruption_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'short-input error slice'):
            m.analyze(Overlay(self.image, 0x216949, b'F'), body_gates=False)

    def test_template_corruption_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'invalid-type template'):
            m.analyze(Overlay(self.image, 0x20193e, b'\x0d'), body_gates=False)

    def test_context_call_retarget_is_refused(self):
        va = 0x13b664f
        replacement = b'\xe8' + struct.pack('<i', 0x13f6410 - (va + 5))
        with self.assertRaisesRegex(ValueError, 'context handoff'):
            m.analyze(Overlay(self.image, va, replacement), body_gates=False)

    def test_context_fde_must_still_contain_the_handoff(self):
        altered = copy.copy(self.image)
        altered.context_fdes = [dict(self.image.context_fdes[0], end=0x13b689f)]
        with self.assertRaisesRegex(ValueError, 'context caller FDE'):
            m.analyze(altered, body_gates=False)

    def test_unrecognized_encoding_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsupported opcode'):
            m.analyze(Overlay(self.image, 0x13c1720, b'\x0b'), body_gates=False)

    def test_branch_into_operand_is_refused(self):
        # Change the first conditional branch displacement to land inside LEA.
        with self.assertRaisesRegex(ValueError, 'instruction start'):
            m.analyze(Overlay(self.image, 0x13c1730, b'\x01'), body_gates=False)

    def test_selector_full_domain(self):
        routes = [m.selector_route(self.record, i)[1] for i in range(256)]
        self.assertEqual(routes.count('deferred'), 241)
        self.assertEqual(routes[0], 'unsigned_payload')
        self.assertEqual(routes[0xc1], 'deferred')
        self.assertEqual(routes[0xe0], 'signed_payload')
        self.assertEqual(routes[0xe1], 'deferred')

    def test_unsigned_32_and_signed_32_have_different_boundaries(self):
        unsigned = m.model(self.record, 0xcc, 0, b'\x20')
        signed = m.model(self.record, 0xd0, 0, b'\x20')
        self.assertEqual(unsigned['value'], '32')
        self.assertEqual(unsigned['boundary'], 'unsigned_visitor')
        self.assertIsNone(unsigned['result_tag'])
        self.assertEqual(signed['value'], '32')
        self.assertEqual(signed['boundary'], 'error_constructor')
        self.assertIsNone(signed['result_tag'])

    def test_unsigned_75_and_76_are_forwarded_without_local_result_claim(self):
        for value in (75, 76):
            for code, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
                case = m.model(self.record, code, 0, value.to_bytes(width, 'big'))
                self.assertEqual((case['value'], case['boundary'], case['result_tag']),
                                 (str(value), 'unsigned_visitor', None))

    def test_unsigned_full_width_values_are_forwarded(self):
        for code, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
            maximum = (1 << (width * 8)) - 1
            for value in (maximum - 1, maximum):
                case = m.model(self.record, code, 0, value.to_bytes(width, 'big'))
                self.assertEqual(case['value'], str(value))
                self.assertEqual(case['boundary'], 'unsigned_visitor')

    def test_all_fixed_width_short_reads_drain_only_available_bytes(self):
        for code, data in self.record['widths'].items():
            width = data['width']
            for n in range(width):
                case = m.model(self.record, code, 0, b'\xff' * n)
                self.assertEqual((case['consumed'], case['remaining'], case['result_tag']),
                                 (n, 0, 1))
                self.assertEqual(case['boundary'], 'short_input')

    def test_complete_reads_leave_following_bytes_untouched(self):
        for code, data in self.record['widths'].items():
            width = data['width']
            case = m.model(self.record, code, 0, b'\x01' * width + b'\xaa\xbb')
            self.assertEqual((case['consumed'], case['remaining']), (width, 2))

    def test_signed_values_are_sign_extended_after_big_endian_read(self):
        for code, width in ((0xd0, 1), (0xd1, 2), (0xd2, 4), (0xd3, 8)):
            for value in (-1, -(1 << (width * 8 - 1)), 0, 32, (1 << (width * 8 - 1)) - 1):
                case = m.model(self.record, code, 0, value.to_bytes(width, 'big', signed=True))
                self.assertEqual(case['value'], str(value))
                self.assertEqual(case['boundary'], 'error_constructor')

    def test_deferred_result_preserves_selector_payload_and_cursor(self):
        for code in (1, 0xbf, 0xc1, 0xc4, 0xdf, 0xe1, 0xff):
            row = m.model(self.record, code, 0x81, b'abc')
            self.assertEqual((row['result_tag'], row['value'], row['consumed'], row['remaining']),
                             (2, f'{code:02x}81', 0, 3))

    def test_float_inputs_keep_raw_bits_without_nan_prediction(self):
        for code, data in ((0xca, bytes.fromhex('7fc01234')),
                           (0xcb, bytes.fromhex('7ff8000000001234'))):
            row = m.model(self.record, code, 0, data)
            self.assertEqual(row['value'], data.hex())
            self.assertEqual(row['boundary'], 'error_constructor')

    def test_four_error_kind_slots_and_templates(self):
        self.assertEqual({r['tag']: r['target'] for r in self.record['format_slots']},
                         {0: 0x4eb8e47, 2: 0x4eb8f4f, 3: 0x4eb8f8b, 7: 0x4eb8fca})
        entries = {r['role']: r['bytes'] for r in self.record['format_templates']}
        self.assertEqual(bytes.fromhex(entries['unit']), b'unit value')
        self.assertEqual(bytes.fromhex(entries['float_suffix']), b'.0')
        self.assertIn(b'integer `', bytes.fromhex(entries['integer']))

    def test_error_kind_slot_retarget_to_valid_arm_is_refused(self):
        slot = 0x7c93b4 + 2 * 4
        wrong = struct.pack('<i', 0x4eb8f8b - 0x7c93b4)
        with self.assertRaisesRegex(ValueError, 'unexpected-kind arm changed'):
            m.analyze(Overlay(self.image, slot, wrong), body_gates=False)

    def test_error_value_template_corruption_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'integer template'):
            m.analyze(Overlay(self.image, 0x1fd934, b'I'), body_gates=False)

    def test_float_suffix_corruption_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'float_suffix'):
            m.analyze(Overlay(self.image, 0x7c94c8, b','), body_gates=False)

    def test_dot_writer_relocation_retarget_is_refused(self):
        altered = copy.copy(self.image)
        altered.relocations = dict(self.image.relocations)
        _, pos = altered.relocations[0x5750f90]
        altered.relocations[0x5750f90] = (0x4eb8950, pos)
        with self.assertRaisesRegex(ValueError, 'RELATIVE addend'):
            m.analyze(altered, body_gates=False)

    def test_string_and_character_forward_to_distinct_writer_slots(self):
        for site, replacement in ((0x4eb8966, b'\x18'), (0x4eb8a64, b'\x20')):
            with self.subTest(site=site):
                with self.assertRaisesRegex(ValueError, 'contract'):
                    m.analyze(Overlay(self.image, site, replacement), body_gates=False)

    def test_dot_scan_matches_independent_byte_oracle_at_all_positions(self):
        for size in range(81):
            for align in range(8):
                baseline = b'7' * size
                self.assertFalse(m.dot_scan(self.record, baseline, align)['found'])
                for pos in range(size):
                    data = baseline[:pos] + b'.' + baseline[pos + 1:]
                    self.assertEqual(m.dot_scan(self.record, data, align)['found'], b'.' in data,
                                     (size, align, pos))

    def test_dot_scan_word_filter_matches_oracle_for_all_two_byte_prefixes(self):
        # Exercise both halves of the 16-byte fast block, including high bits.
        for value in range(65536):
            pair = value.to_bytes(2, 'little')
            for filler in (0, 0x2d, 0x2f, 0x7f, 0x80, 0xff):
                pad = bytes([filler])
                for data in (pair + pad * 14, pad * 8 + pair + pad * 6):
                    self.assertEqual(m.dot_scan(self.record, data, 0)['found'], b'.' in data)

    def test_word_filter_matching_byte_forces_a_fallback_for_any_lower_borrow(self):
        # At a matching byte, x XOR period is zero. The constant's low byte
        # is zero and its other bytes are one, so the subtraction high bit is
        # clear for either possible incoming borrow. Both OR operands are also
        # below 0x80 at the matching byte, for either half of the block.
        constant = self.record['word_constants']['subtract']
        period = self.record['period']
        for position in range(8):
            minuend = (constant >> (position * 8)) & 0xff
            borrows = (0,) if position == 0 else (0, 1)
            for borrow in borrows:
                difference = (minuend - borrow) & 0xff
                for or_operand in (period, period ^ period):
                    self.assertEqual((difference | or_operand) & 0x80, 0)

    def test_dot_word_filter_constant_corruption_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'dot scan constants'):
            m.analyze(Overlay(self.image, 0x4eb89c6, b'\x2f'), body_gates=False)

    def test_dot_word_filter_branch_corruption_is_refused(self):
        with self.assertRaises(ValueError):
            m.analyze(Overlay(self.image, 0x4eb8a0d, b'\x74'), body_gates=False)

    def test_boolean_formatter_payload_offset_corruption_is_refused(self):
        with self.assertRaises(ValueError):
            m.analyze(Overlay(self.image, 0x4eb8e4a, b'\x02'), body_gates=False)

    def test_float_finite_branch_corruption_is_refused(self):
        with self.assertRaises(ValueError):
            m.analyze(Overlay(self.image, 0x4eb911f, b'\x7d'), body_gates=False)

    def test_dot_scan_rejects_bad_alignment_and_type(self):
        for align in (-1, 8, True):
            with self.assertRaises(ValueError):
                m.dot_scan(self.record, b'1.0', align)
        with self.assertRaises(ValueError):
            m.dot_scan(self.record, '1.0', 0)

    def test_dot_flag_is_sticky_and_character_match_uses_full_register(self):
        self.assertEqual(m.character_flag(self.record, 0, 0x2e), 1)
        self.assertEqual(m.character_flag(self.record, 0, 0x12e), 0)
        self.assertEqual(m.character_flag(self.record, 0x80, 0x2e), 0x81)
        self.assertEqual(m.dot_flag(0x81, False), 0x81)
        self.assertEqual(m.dot_flag(0x80, True), 0x81)
        with self.assertRaises(ValueError):
            m.character_flag(self.record, 0, 1 << 32)
        with self.assertRaises(ValueError):
            m.dot_flag(-1, True)

    def test_float_finish_distinguishes_finite_and_nonfinite(self):
        for bits in (0, 0x8000000000000000, 1, 0x7fefffffffffffff, 0xffefffffffffffff):
            self.assertEqual(m.float_finish(self.record, bits, 0, 0, 0),
                             {'class': 'finite', 'suffix_call': True, 'return_byte': 0})
        for bits in (0x7ff0000000000000, 0xfff0000000000000,
                     0x7ff0000000000001, 0x7ff8000000001234):
            self.assertEqual(m.float_finish(self.record, bits, 7, 0, 0),
                             {'class': 'nonfinite', 'suffix_call': False, 'return_byte': 7})

    def test_float_finish_propagates_writer_failures_and_dot_flag(self):
        self.assertEqual(m.float_finish(self.record, 0, 8, 0, 0)['return_byte'], 1)
        self.assertFalse(m.float_finish(self.record, 0, 8, 0, 0)['suffix_call'])
        self.assertFalse(m.float_finish(self.record, 0, 0, 1, 1)['suffix_call'])
        self.assertEqual(m.float_finish(self.record, 0, 0, 0, 7)['return_byte'], 1)
        self.assertEqual(m.float_finish(self.record, 0, 0, 0, 0)['return_byte'], 0)

    def test_float_finish_rejects_bad_bits_and_status(self):
        for args in ((-1, 0, 0, 0), (1 << 64, 0, 0, 0), (0, 256, 0, 0), (0, 0, -1, 0)):
            with self.assertRaises(ValueError):
                m.float_finish(self.record, *args)

    def test_float_model_class_against_python_binary64(self):
        for case in m.float_cases(self.record):
            value = struct.unpack('<d', struct.pack('<Q', int(case['bits'], 16)))[0]
            self.assertEqual(case['class'] == 'finite', math.isfinite(value))

    def test_invalid_model_inputs_rejected(self):
        for selector, payload in ((-1, 0), (256, 0), (0, -1), (0, 256), (True, 0)):
            with self.assertRaises(ValueError):
                m.model(self.record, selector, payload, b'')
        with self.assertRaises(ValueError):
            m.model(self.record, 0, 0, 'text')

    def test_generated_evidence_is_deterministic_in_process(self):
        one = m.output_files(self.image)
        two = m.output_files(self.image)
        self.assertEqual(one, two)
        self.assertEqual(len(one), 18)
        for data in one.values():
            self.assertNotIn(b'/' + b'tmp' + b'/', data)
            self.assertNotIn(b'/' + b'home' + b'/', data)


if __name__ == '__main__':
    unittest.main()
