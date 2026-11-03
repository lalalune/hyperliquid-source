"""Target-grounded controls for the selected static TWAP-cancel evidence."""
from contextlib import contextmanager
import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools import re010_twap_cancel_115 as subject


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(subject.BINARY.read_bytes())
        cls.image = subject.Image(cls.data)

    @contextmanager
    def changed(self, va, replacement):
        offset = self.image.offset(va, len(replacement))
        previous = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = previous

    def test_artifact_digest(self):
        self.assertEqual(subject.verify_digest(self.data), subject.TARGET)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.verify_digest(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.verify_digest(self.data, '0' * 64)

    def test_selected_fde_bounds_and_bodies(self):
        records = subject.validate_fdes(self.image)
        self.assertEqual(len(records), 14)
        self.assertEqual(records[0][1:3], (0x39d0f20, 0x39d1b0a))
        self.assertEqual(records[1][1:3], (0x2c2f020, 0x2c2f7c2))

    def test_corrupted_fde_body_is_rejected(self):
        original = self.image.read(0x2c2f100, 1)
        with self.changed(0x2c2f100, bytes([original[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'body bytes mismatch'):
                subject.validate_fdes(self.image)

    def test_fde_end_is_not_the_next_start(self):
        first = self.image.fdes[0x2d2c6e0]
        self.assertEqual(first['end'], 0x2d2d019)
        self.assertEqual(self.image.fdes[0x2d2d020]['start'] - first['end'], 7)

    def test_fde_index_disagreement_is_rejected(self):
        va = 0x2c2f020
        previous = self.image.index[va]
        self.image.index[va] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'FDE index mismatch'):
                subject.validate_fdes(self.image)
        finally:
            self.image.index[va] = previous

    def test_fde_requires_executable_file_bytes(self):
        va = 0x2c2f020
        section = next(s for s in self.image.sections
                       if s['address'] <= va < s['address'] + s['size'] and s['flags'] & 4)
        saved = section['flags']
        try:
            section['flags'] &= ~4
            with self.assertRaisesRegex(ValueError, 'file-backed executable section'):
                subject.validate_fdes(self.image)
        finally:
            section['flags'] = saved

    def test_negative_and_unmapped_intervals(self):
        for va, length in ((-1, 1), (0, 1), (0x2c2f020, 0), (0x2c2f020, -1), (1 << 63, 8)):
            with self.subTest(va=va, length=length):
                with self.assertRaises(ValueError):
                    self.image.read(va, length)

    def test_nobits_is_never_a_file_mapping(self):
        fake = [{'type': 8, 'address': 0x1000, 'size': 64, 'offset': 0}]
        with self.assertRaisesRegex(ValueError, 'NOBITS'):
            subject.file_offset(fake, 0x1000, 1, 64)

    def test_ambiguous_and_truncated_mapping_are_rejected(self):
        row = {'type': 1, 'address': 0x1000, 'size': 16, 'offset': 4}
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            subject.file_offset([row, dict(row)], 0x1000, 1, 32)
        with self.assertRaisesRegex(ValueError, 'outside file'):
            subject.file_offset([row], 0x100c, 4, 19)
        self.assertEqual(subject.file_offset([row], 0x100c, 4, 20), 16)

    def test_full_instruction_windows_match(self):
        self.assertEqual(len(subject.validate_windows(self.image)), len(subject.WINDOWS))
        raw = self.image.read(0x39d1232, 1)
        with self.changed(0x39d1232, bytes([raw[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                subject.validate_windows(self.image)

    def test_branch_decoding_and_corruption(self):
        rows = subject.checked_branches(self.image)
        self.assertGreater(len(rows), len(subject.BRANCHES))
        self.assertTrue(any(row[0] == 'remove_paired_remove_row_not_two' for row in rows))
        raw, cc, dest = subject.decode_branch(self.image, 0x2c2f087)
        self.assertEqual((raw.hex(), cc, dest), ('0f8302060000', 3, 0x2c2f68f))
        with self.changed(0x2c2f087, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'conditional branch'):
                subject.decode_branch(self.image, 0x2c2f087)
        raw_disp = self.image.read(0x2c2f089, 1)
        with self.changed(0x2c2f089, bytes([raw_disp[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'branch target mismatch'):
                subject.checked_branches(self.image)

    def test_paired_branch_target_corruption_is_rejected(self):
        va = 0x2d2d393
        self.assertEqual(subject.decode_branch(self.image, va)[2], 0x2d2d39c)
        with self.changed(va + 1, b'\x06'):
            with self.assertRaisesRegex(ValueError, 'paired branch target mismatch'):
                subject.checked_branches(self.image)

    def test_shift_condition_corruption_is_rejected(self):
        with self.changed(0x24da64f + 1, b'\x87'):
            with self.assertRaisesRegex(ValueError, 'branch condition mismatch'):
                subject.checked_branches(self.image)

    def test_call_target_and_opcode_corruption(self):
        raw, target = subject.decode_call(self.image, 0x2a2fbe2)
        self.assertEqual((raw.hex(), target), ('e839f41f00', 0x2c2f020))
        with self.changed(0x2a2fbe2, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'not a rel32 call'):
                subject.decode_call(self.image, 0x2a2fbe2)
        raw_disp = self.image.read(0x2a2fbe3, 1)
        with self.changed(0x2a2fbe3, bytes([raw_disp[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'call target mismatch'):
                subject.checked_calls(self.image)

    def test_rip_lea_target_and_bad_opcode(self):
        raw, target = subject.decode_rip_lea(self.image, 0x39d108d)
        self.assertEqual((len(raw), target), (7, subject.INPUT_TABLE))
        self.assertEqual(subject.decode_rip_lea(self.image, 0x36b9339)[1], subject.FIELD_TABLE)
        with self.changed(0x39d108d, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'RIP-relative lea'):
                subject.decode_rip_lea(self.image, 0x39d108d)

    def test_direct_jump_decoding_and_corruption(self):
        self.assertEqual(subject.decode_jump(self.image, 0x36b9374)[1], 0x36bae27)
        self.assertEqual(subject.decode_jump(self.image, 0x2d2ca5a)[1], 0x2d2cacc)
        self.assertEqual(len(subject.checked_jumps(self.image)), len(subject.JUMPS))
        with self.changed(0x2d2ca5a, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'not a supported direct jump'):
                subject.decode_jump(self.image, 0x2d2ca5a)
        old = self.image.read(0x36b9375, 1)
        with self.changed(0x36b9375, bytes([old[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'jump target mismatch'):
                subject.checked_jumps(self.image)

    def test_name_index_directly_from_instructions(self):
        first = self.image.read(0x3661e58, 8)
        last = self.image.read(0x3661e6b, 2)
        self.assertEqual(first + last, b'twapCancel')
        ordinal = self.image.read(0x3662628, 1)[0]
        self.assertEqual(ordinal, 35)
        fde = self.image.containing_fde(0x3661e2d)
        _, _, target = self.image.table_target(subject.NAME_TABLE, len(first + last) - 4,
                                                fde['start'], fde['end'])
        self.assertEqual(target, 0x3661e2d)
        self.assertEqual(subject.decode_branch(self.image, 0x3661e72)[2], 0x3662625)
        for i in range(10):
            bad = bytearray(first + last)
            bad[i] ^= 1
            with self.subTest(position=i):
                self.assertFalse(bad[:8] == first and bad[8:] == last)

    def test_prior_equal_length_name_cannot_steal_selected_case(self):
        base = struct.unpack('<Q', self.image.read(0x3661e2f, 8))[0]
        add = struct.unpack('<i', self.image.read(0x3661e3a, 4))[0]
        earlier = struct.pack('<Q', (base + add) & ((1 << 64) - 1)) + self.image.read(0x3661e49, 2)
        selected = self.image.read(0x3661e58, 8) + self.image.read(0x3661e6b, 2)
        self.assertEqual((earlier, selected), (b'spotDeploy', b'twapCancel'))
        self.assertNotEqual(earlier, selected)
        self.assertEqual(self.image.read(0x3662586, 1)[0], 27)
        self.assertEqual(self.image.read(0x3662628, 1)[0], 35)

    def test_context_calls_connect_to_the_same_core(self):
        _, inner_wrapper = subject.decode_call(self.image, 0x2bdbe01)
        _, direct_wrapper = subject.decode_call(self.image, 0x2bdaa2a)
        self.assertEqual(self.image.containing_fde(0x2a2fbe2)['start'], inner_wrapper)
        self.assertEqual(self.image.containing_fde(0x2c0a868)['start'], direct_wrapper)
        self.assertEqual(subject.decode_call(self.image, 0x2a2fbe2)[1], 0x2c2f020)
        self.assertEqual(subject.decode_call(self.image, 0x2c0a868)[1], 0x2c2f020)

    def test_variant_and_field_relocations(self):
        expected = ['a', 'asset', 't', 'twapId']
        for i, name in enumerate(expected):
            ptr, length, observed = self.image.relative_string(subject.FIELD_TABLE + 16 * i)
            self.assertEqual((length, observed), (len(name), name))
            self.assertEqual(self.image.read(ptr, length), name.encode('ascii'))
        for table in subject.VARIANT_TABLES:
            self.assertEqual(self.image.relative_string(table + 16 * subject.INDEX)[2], 'twapCancel')

    def test_missing_string_relocation_rejected(self):
        slot = subject.FIELD_TABLE
        saved = self.image.relocations.pop(slot)
        try:
            with self.assertRaisesRegex(ValueError, 'missing RELATIVE'):
                self.image.relative_string(slot)
        finally:
            self.image.relocations[slot] = saved

    def test_wrong_or_oversized_string_length_rejected(self):
        slot = subject.FIELD_TABLE
        with self.changed(slot + 8, struct.pack('<Q', 129)):
            with self.assertRaisesRegex(ValueError, 'descriptor string length'):
                self.image.relative_string(slot)
        with self.changed(slot + 8, struct.pack('<Q', 0)):
            with self.assertRaisesRegex(ValueError, 'descriptor string length'):
                self.image.relative_string(slot)

    def test_rela_parser_rejects_corruption_and_duplicates(self):
        row = struct.pack('<QQq', 0x1000, 8, 0x2000)
        sec = {'type': 4, 'offset': 0, 'size': len(row)}
        self.assertEqual(subject.relative_relocations(row, sec)[0x1000][0], 0x2000)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            subject.relative_relocations(row[:-1], sec)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            subject.relative_relocations(row, {'type': 8, 'offset': 0, 'size': 24})
        duplicate = row + struct.pack('<QQq', 0x1000, 6, 0)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            subject.relative_relocations(duplicate, {'type': 4, 'offset': 0, 'size': 48})
        symbol_relative = struct.pack('<QQq', 0x1000, (1 << 32) | 8, 0x2000)
        with self.assertRaisesRegex(ValueError, 'has a symbol'):
            subject.relative_relocations(symbol_relative, sec)

    def test_selected_table_indices_and_range_checks(self):
        fde = self.image.fdes[0x39d0f20]
        for kind in range(1, 16):
            _, _, target = self.image.table_target(subject.INPUT_TABLE, kind - 1,
                                                    fde['start'], fde['end'])
            self.assertTrue(fde['start'] <= target < fde['end'])
        with self.assertRaisesRegex(ValueError, 'invalid table index'):
            self.image.table_target(subject.INPUT_TABLE, -1, fde['start'], fde['end'])
        slot = subject.INPUT_TABLE + 4
        with self.changed(slot, struct.pack('<i', 0x7fffffff)):
            with self.assertRaisesRegex(ValueError, 'outside selected range'):
                self.image.table_target(subject.INPUT_TABLE, 1, fde['start'], fde['end'])

    def test_field_spellings_and_negative_controls(self):
        expected = ((b'a', 0), (b'asset', 0), (b't', 1), (b'twapId', 1))
        for value, index in expected:
            self.assertEqual(subject.field_key_model(value), index)
            for position in range(len(value)):
                bad = bytearray(value)
                bad[position] ^= 0x80
                with self.subTest(value=value, position=position):
                    self.assertIsNone(subject.field_key_model(bytes(bad)))
        for bad in (b'', b'A', b'twapid', b'asset\0', b'twapId ', b'twapI'):
            self.assertIsNone(subject.field_key_model(bad))

    def test_three_pair_comparisons(self):
        expected = [('remove', 2361, 39, 18), ('first_remove', 1387, 36, 16),
                    ('tree_remove', 654, 16, 7)]
        for pair, expected_row in zip(subject.PAIRS, expected):
            role, a, b, sites = pair
            size, diffs, operands, covered, _ = subject.pair_records(self.image, a, b, sites)
            self.assertEqual((role, size, len(diffs), len(operands)), expected_row)
            self.assertEqual(len(covered), 4 * len(operands))

    def test_unmasked_pair_corruption_is_not_normalized(self):
        _, first, second, sites = subject.PAIRS[0]
        old = self.image.read(first + 0x100, 1)
        with self.changed(first + 0x100, bytes([old[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'unmasked body difference'):
                subject.pair_records(self.image, first, second, sites)

    def test_masked_operand_does_not_prove_equal_call_targets(self):
        _, first, second, sites = subject.PAIRS[0]
        original = subject.pair_records(self.image, first, second, sites)
        old = self.image.read(0x2d2c70a, 1)
        with self.changed(0x2d2c70a, bytes([old[0] ^ 1])):
            changed = subject.pair_records(self.image, first, second, sites)
        self.assertEqual(original[-1], changed[-1])
        self.assertNotEqual(original[2][0][4], changed[2][0][4])
        self.assertNotEqual(original[1], changed[1])

    def test_pair_instruction_opcode_corruption_rejected(self):
        _, first, second, sites = subject.PAIRS[0]
        with self.changed(0x2d2c709, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'opcode mismatch'):
                subject.pair_records(self.image, first, second, sites)

    def test_pair_extent_disagreement_rejected(self):
        _, first, second, sites = subject.PAIRS[0]
        saved = self.image.fdes[second]['end']
        self.image.fdes[second]['end'] -= 1
        try:
            with self.assertRaisesRegex(ValueError, 'lengths differ'):
                subject.pair_records(self.image, first, second, sites)
        finally:
            self.image.fdes[second]['end'] = saved

    def test_compact_row_mutation_precedes_row_kind_check(self):
        self.assertEqual(self.image.read(0x2d2c9c8, 7).hex(), '49ffcc4d896518')
        self.assertEqual(self.image.read(0x2d2ca4f, 4).hex(), '4080fd02')
        self.assertLess(0x2d2c9c8, 0x2d2ca4f)
        self.assertEqual(self.image.read(0x2d2d308, 7).hex(), '49ffcc4d896518')
        self.assertEqual(self.image.read(0x2d2d38f, 4).hex(), '4080fd02')

    def test_first_row_mutation_precedes_row_kind_check(self):
        self.assertEqual(self.image.read(0x2d2f1a6, 7).hex(), '49ffcf4d897e18')
        self.assertEqual(self.image.read(0x2d2f1ad, 4).hex(), '4180fc02')

    def test_error_results_still_reach_selected_handoffs(self):
        self.assertEqual(subject.decode_jump(self.image, 0x2c2f1ad)[1], 0x2c2f4c7)
        self.assertEqual(subject.decode_jump(self.image, 0x2c2f284)[1], 0x2c2f607)
        self.assertEqual(subject.decode_call(self.image, 0x2c2f4e5)[1], 0x2419810)
        self.assertEqual(subject.decode_call(self.image, 0x2c2f622)[1], 0x241a3c0)

    def test_magic_division_proof_and_boundary_vectors(self):
        multiplier = struct.unpack('<Q', self.image.read(0x2c2f06b, 8))[0]
        shift = self.image.read(0x2c2f07f, 1)[0]
        divisor = 10000
        scale = 1 << (64 + shift)
        error = multiplier * divisor - scale
        self.assertEqual(multiplier, (scale + divisor - 1) // divisor)
        self.assertEqual(error, 432)
        self.assertLess(((1 << 64) - 1) * error, scale)
        samples = {0, 1, divisor - 1, divisor, divisor + 1, (1 << 64) - 1}
        for q in (0, 1, 2, 101, (1 << 32), ((1 << 64) - 1) // divisor):
            for r in (0, 1, divisor - 1):
                x = q * divisor + r
                if x < 1 << 64:
                    samples.add(x)
        for x in sorted(samples):
            with self.subTest(x=x):
                self.assertEqual(subject.fixed_division_model(x, multiplier, shift), x // divisor)
        self.assertNotEqual(subject.fixed_division_model(divisor, multiplier - 1, shift), 1)
        for invalid in (-1, 1 << 64):
            with self.assertRaisesRegex(ValueError, 'outside u64'):
                subject.fixed_division_model(invalid, multiplier, shift)

    def test_record_group_remainder_and_stride(self):
        multiplier = struct.unpack('<Q', self.image.read(0x2c2f06b, 8))[0]
        for mul_va, shift_va, divisor_va, stride_va in (
            (0x2a8119f, 0x2a811b3, 0x2a811d8, 0x2a811f3),
            (0x2a81ac9, 0x2a81add, 0x2a81b02, 0x2a81b1d),
        ):
            self.assertEqual(struct.unpack('<Q', self.image.read(mul_va, 8))[0], multiplier)
            self.assertEqual(self.image.read(shift_va, 1)[0], 11)
            divisor = struct.unpack('<I', self.image.read(divisor_va, 4))[0]
            self.assertEqual(divisor, 10000)
            self.assertEqual(1 << self.image.read(stride_va, 1)[0], 32)
            for value in (0, 9999, 10000, 10001, (1 << 64) - 1):
                quotient = subject.fixed_division_model(value, multiplier, 11)
                self.assertEqual((quotient, value - quotient * divisor), divmod(value, divisor))
        with self.changed(0x2a811d8, b'\x11'):
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                subject.validate_windows(self.image)

    def test_record_bounds_targets_and_failure_bytes(self):
        for site, target in ((0x2a811e6, 0x2a812b9), (0x2a81b10, 0x2a81c13),
                             (0x2a80ccf, 0x2a810f0), (0x2a8156e, 0x2a81a19)):
            raw, code, actual = subject.decode_branch(self.image, site)
            self.assertEqual((code, actual), (3, target))
        for target in (0x2a810f0, 0x2a81a19):
            self.assertEqual(self.image.read(target + 29, 2), b'\x0f\x0b')
        with self.changed(0x2a81570, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'branch target mismatch'):
                subject.checked_branches(self.image)

    def test_record_small_selector_arithmetic_boundaries(self):
        maximum = (1 << 64) - 1
        offset = 100000000
        factor = 10
        threshold = (maximum - offset) // factor
        multiply_threshold = maximum // factor
        for selector in (0, 1):
            for value in (0, 1, threshold - 1, threshold, threshold + 1,
                          multiply_threshold - 1, multiply_threshold,
                          multiply_threshold + 1, maximum):
                with self.subTest(value=value, selector=selector):
                    observed = subject.record_arithmetic_model(value, selector, factor, offset)
                    self.assertEqual(observed, min(value * factor + selector, maximum - offset))
        for value, selector in ((-1, 0), (1 << 64, 0), (1, 2), (1, -1)):
            with self.assertRaisesRegex(ValueError, 'invalid record arithmetic'):
                subject.record_arithmetic_model(value, selector, factor, offset)
        with self.changed(0x2a80d59, b'\x0b'):
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                subject.validate_windows(self.image)

    def test_record_multiply_overflow_condition_and_targets(self):
        for site, target in ((0x2a80d62, 0x2a810e4), (0x2a81605, 0x2a81a0d)):
            _, code, actual = subject.decode_branch(self.image, site)
            self.assertEqual((code, actual), (0, target))
        self.assertEqual(subject.decode_jump(self.image, 0x2a810eb)[1], 0x2a80d68)
        self.assertEqual(subject.decode_jump(self.image, 0x2a81a14)[1], 0x2a8160b)
        with self.changed(0x2a81606, b'\x81'):
            with self.assertRaisesRegex(ValueError, 'branch condition mismatch'):
                subject.checked_branches(self.image)

    def test_shift_import_and_slot_corruption(self):
        raw, slot = subject.decode_rip_slot(self.image, 0x24da71c)
        self.assertEqual((raw.hex(), slot), ('ff25464e0004', 0x64df568))
        imported = subject.dynamic_import(self.image, slot)
        self.assertEqual((imported[2], imported[-1]), (6, 'memmove'))
        with self.changed(0x24da71c, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'slot reference'):
                subject.decode_rip_slot(self.image, 0x24da71c)
        with self.assertRaisesRegex(ValueError, 'import relocation'):
            subject.dynamic_import(self.image, slot + 1)
        name_offset = imported[-2]
        old = self.data[name_offset]
        try:
            self.data[name_offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'unexpected imported symbol'):
                subject.dynamic_import(self.image, slot)
        finally:
            self.data[name_offset] = old

    def test_shift_caller_plan_all_small_valid_rings(self):
        cases = 0
        copy_counts = set()
        for capacity in range(1, 15):
            for head in range(capacity):
                for length in range(1, capacity + 1):
                    for index in range(length):
                        rows = list(range(capacity))
                        old = [rows[(head + i) % capacity] for i in range(length)]
                        new_head, copies = subject.compact_remove_plan(capacity, head, length, index)
                        copy_counts.add(len(copies))
                        for destination, source, count in copies:
                            self.assertGreaterEqual(count, 0)
                            self.assertGreaterEqual(source, 0)
                            self.assertGreaterEqual(destination, 0)
                            self.assertLessEqual(source + count, capacity)
                            self.assertLessEqual(destination + count, capacity)
                            rows[destination:destination + count] = rows[source:source + count]
                        actual = [rows[(new_head + i) % capacity] for i in range(length - 1)]
                        self.assertEqual(actual, old[:index] + old[index + 1:])
                        cases += 1
        self.assertEqual(cases, 6020)
        self.assertEqual(copy_counts, {0, 1, 2, 3})

    def test_shift_caller_plan_invalid_bounds(self):
        for inputs in ((0, 0, 1, 0), (1 << 64, 0, 1, 0), (2, 2, 1, 0), (2, -1, 1, 0),
                       (2, 0, 0, 0), (2, 0, 3, 0), (2, 0, 2, 2),
                       (2, 0, 2, -1)):
            with self.subTest(inputs=inputs):
                with self.assertRaisesRegex(ValueError, 'invalid compact-ring input'):
                    subject.compact_remove_plan(*inputs)

    def test_wrapper_threshold_boundary_and_internal_words(self):
        limit = struct.unpack('<Q', self.image.read(0x2a2fbb9, 8))[0]
        self.assertEqual(limit, 0x0ccccccccccccccc)
        self.assertTrue(limit - 1 < limit)
        self.assertFalse(limit < limit)
        self.assertFalse(limit + 1 < limit)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2a2fba9, 2))[0], 0x1a2)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2a2fce7, 2))[0], 0x154)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2c2f051, 2))[0], 0x108)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2d2ccdb, 2))[0], 0xd4)

    def test_wrapper_result_tags_and_record_lengths(self):
        self.assertEqual(self.image.read(0x2a2fc42, 3).hex(), 'c60305')
        self.assertEqual(self.image.read(0x2a2fced, 3).hex(), 'c6030f')
        self.assertEqual(struct.unpack('<I', self.image.read(0x2c2f4aa, 4))[0], 0x2b8)
        self.assertEqual(struct.unpack('<I', self.image.read(0x2c2f5ea, 4))[0], 0x2c8)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2c2f4c5, 2))[0], 0x1a2)
        self.assertEqual(struct.unpack('<H', self.image.read(0x2c2f605, 2))[0], 0x1a2)

    def test_generation_is_byte_stable_in_process(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            first, second = root / 'first', root / 'second'
            result1 = subject.generate(self.image, first)
            result2 = subject.generate(self.image, second)
            self.assertEqual(result1, result2)
            self.assertEqual(result1['selected_fdes'], 14)
            self.assertEqual(result1['record_indexing_paths'], 4)
            self.assertEqual(result1['record_arithmetic_paths'], 2)
            self.assertEqual(result1['shift_slot_references'], 18)
            paths = sorted(p.name for p in first.iterdir())
            self.assertEqual(paths, sorted(p.name for p in second.iterdir()))
            for name in paths:
                with self.subTest(name=name):
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            constants = json.loads((first / 'constants.json').read_text())
            self.assertEqual((constants['name'], constants['index'], constants['tag']),
                             ('twapCancel', 35, 0xa9))
            with (first / 'shift-dynamic-import.tsv').open(newline='') as handle:
                imported = next(csv.DictReader(handle, delimiter='\t'))
            self.assertEqual(int(imported['slot_va'], 16),
                             struct.unpack('<Q', bytes.fromhex(imported['rela_bytes'])[:8])[0])
            self.assertEqual(imported['name'], 'memmove')


if __name__ == '__main__':
    unittest.main()
