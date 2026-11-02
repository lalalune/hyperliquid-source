import struct
import unittest

from tools import question_settlement94 as q


class ChangedImage:
    def __init__(self, image, va, xor=1):
        self.image, self.va, self.xor = image, va, xor

    def read(self, va, size):
        data = bytearray(self.image.read(va, size))
        if va <= self.va < va + size:
            data[self.va - va] ^= self.xor
        return bytes(data)


class StaticSettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.TARGET.read_bytes()
        cls.image = q.Image(cls.data)
        q.validate_windows(cls.image)
        cls.code = cls.image.read(q.WINDOWS['classify_a'][0], 32)
        cls.base = q.WINDOWS['classify_a'][0]
        cls.one = 0x3ff0000000000000

    def test_digest_binding(self):
        self.assertEqual(q.check_hash(self.data), q.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            q.check_hash(b'corrupt target')

    def test_mutated_instruction_is_refused(self):
        modified = ChangedImage(self.image, 0x4d6aec4)
        with self.assertRaisesRegex(ValueError, 'instruction bytes'):
            q.validate_windows(modified)

    def test_out_of_range_address_is_refused(self):
        with self.assertRaises(ValueError):
            self.image.read(1 << 64, 8)
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(0x20a730, -1)

    def test_nobits_is_not_file_backed(self):
        # .tbss may share its VA with a file-backed TLS neighbor, so use .bss.
        section = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(section['address'], 1)

    def test_ambiguous_mapping_is_refused(self):
        fake = object.__new__(q.Image)
        fake.data = b'1234'
        s = dict(type=1, size=4, address=0x1000, offset=0)
        fake.sections = [s, dict(s)]
        with self.assertRaises(ValueError):
            fake.read(0x1000, 1)

    def test_forged_direct_call_rejected(self):
        with self.assertRaisesRegex(ValueError, 'direct relative call'):
            q.relative_call(ChangedImage(self.image, 0x448460f, 0xe8 ^ 0x90), 0x448460f)
        self.assertNotEqual(q.relative_call(ChangedImage(self.image, 0x4484610), 0x448460f), 0x489edd0)

    def test_branch_targets_and_corruption(self):
        cond, target, raw = q.conditional_branch(self.image, 0x47bbcb5)
        self.assertEqual((cond, target), ('below_or_equal', 0x47bbd5b))
        self.assertEqual(raw, bytes.fromhex('0f86a0000000'))
        with self.assertRaisesRegex(ValueError, 'conditional branch'):
            q.conditional_branch(ChangedImage(self.image, 0x47bbcb5), 0x47bbcb5)
        self.assertNotEqual(q.conditional_branch(ChangedImage(self.image, 0x47bbcb7), 0x47bbcb5)[1], target)

    def test_corrupted_indirect_opcode_rejected(self):
        with self.assertRaisesRegex(ValueError, 'RIP-relative call'):
            q.indirect_slot(ChangedImage(self.image, 0x47bbd64), 0x47bbd64)

    def test_slot_relocations(self):
        self.assertEqual(q.indirect_slot(self.image, 0x47bbd64), 0x57731d8)
        self.assertEqual(q.indirect_slot(self.image, 0x47bbda7), 0x5773968)
        self.assertEqual(self.image.relocations({0x57731d8, 0x5773968}),
                         {0x57731d8: 0x3799510, 0x5773968: 0x4ead680})
        with self.assertRaisesRegex(ValueError, 'missing slot'):
            self.image.relocations({1})

    def test_text_reference_and_constant(self):
        self.assertEqual(q.rip_lea_target(self.image, 0x4d6af1a), 0x715457)
        self.assertEqual(self.image.read(0x20a730, 8), struct.pack('<Q', self.one))
        with self.assertRaises(ValueError):
            q.rip_lea_target(self.image, 0x4d6aeb0)

    def test_all_payload_equivalence_classes(self):
        observed = q.partition(self.code, self.base)
        self.assertEqual(observed['partition_count'], 8192)
        self.assertEqual(observed['payload_count'], 2**64)
        self.assertEqual(observed['counts'], {'zero': 2, 'winner': 1, 'reject': 2**64 - 3})
        # The proof's representatives use fraction 1. Check additional points
        # from each nonzero-fraction class with independent bit predicates.
        for sign in range(2):
            for exp in range(2048):
                for frac in (0, 1, 1 << 51, (1 << 52) - 1):
                    bits = (sign << 63) | (exp << 52) | frac
                    want = ('zero' if exp == 0 and frac == 0 else
                            'winner' if sign == 0 and exp == 1023 and frac == 0 else 'reject')
                    self.assertEqual(q.classify(bits, self.code, self.base)[0], want)

    def test_two_body_copies_agree_on_boundaries(self):
        code_b = self.image.read(q.WINDOWS['classify_b'][0], 32)
        for bits in (0, 1, 1 << 63, (1 << 63) | 1, self.one - 1, self.one,
                     self.one + 1, 0xbff0000000000000, 0x7ff0000000000000,
                     0x7ff8000000000001, 0x7ff0000000000001):
            self.assertEqual(q.classify(bits, self.code, self.base)[0],
                             q.classify(bits, code_b, q.WINDOWS['classify_b'][0])[0])

    def test_full_body_comparison_and_corruption(self):
        rows, result = q.compare_body_copies(self.image, 0x4d6b597, 0x4d6bf77)
        self.assertEqual(len(rows), 39)
        self.assertEqual(result, {'fde_bytes_each': 2519, 'masked_operand_bytes': 156,
                                  'unmasked_equal_bytes': 2363, 'raw_differing_bytes': 78,
                                  'rel32_operands': 39, 'different_resolved_targets': 1})
        with self.assertRaisesRegex(ValueError, 'unexpected locations of body differences'):
            q.compare_body_copies(ChangedImage(self.image, 0x4d6abc0), 0x4d6b597, 0x4d6bf77)
        with self.assertRaisesRegex(ValueError, 'unexpected differing rel32 target'):
            q.compare_body_copies(ChangedImage(self.image, 0x4d6abc0 + 0x45), 0x4d6b597, 0x4d6bf77)
        with self.assertRaisesRegex(ValueError, 'FDE sizes differ'):
            q.compare_body_copies(self.image, 0x4d6b597, 0x4d6bf76)

    def test_changed_conditional_branch_is_refused(self):
        code = bytearray(self.code)
        code[11] ^= 1
        with self.assertRaisesRegex(ValueError, 'control flow'):
            q.classify(self.one, code, self.base)
        code = bytearray(self.code)
        code[22] ^= 1
        with self.assertRaisesRegex(ValueError, 'control flow'):
            q.classify(0, code, self.base)

    def test_changed_comparison_constant_address_is_refused(self):
        code = bytearray(self.code)
        code[4] ^= 1
        with self.assertRaisesRegex(ValueError, 'constant address'):
            q.classify(0, code, self.base)

    def test_classifier_range_validation(self):
        for bits in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                q.classify(bits, self.code, self.base)
        with self.assertRaises(ValueError):
            q.classify(0, self.code[:-1], self.base)

    def test_input_gates_and_failure_precedence(self):
        f = q.abstract_input
        self.assertEqual(f(True, 100, True, True, 2000), 'accepted')
        self.assertEqual(f(False, 101, False, False, 2001), 'unknown_outcome_0xec')
        self.assertEqual(f(True, 101, False, False, 2001), 'fraction_length_0x143')
        self.assertEqual(f(True, 100, False, False, 2001), 'parser_error')
        self.assertEqual(f(True, 100, True, False, 2001), 'conversion_error_0xab')
        self.assertEqual(f(True, 100, True, True, 2001), 'detail_length_0x143')

    def test_losers_then_winner_and_zero_normalization(self):
        result, calls = q.abstract_question([(1, 0), (2, self.one), (3, 1 << 63)],
                                            {1, 2, 3}, 3)
        self.assertEqual((result, calls), ('success', [(1, 0), (3, 0), (2, self.one)]))

    def test_question_failures_and_order(self):
        f = q.abstract_question
        self.assertEqual(f([], set(), 0), ('no_winner', []))
        self.assertEqual(f([(1, 0)], {1}, 2), ('no_winner', []))
        self.assertEqual(f([(1, self.one), (2, self.one)], {1, 2}, 2), ('second_winner', []))
        self.assertEqual(f([(1, 0x3fe0000000000000)], set(), 1), ('invalid_outcome', []))
        self.assertEqual(f([(1, 0x3fe0000000000000)], {1}, 1), ('non_binary_fraction', []))
        self.assertEqual(f([(1, self.one)], {1, 2}, 2), ('all_remaining', []))

    def test_callee_error_stops_later_calls(self):
        result, calls = q.abstract_question([(1, 0), (2, 0), (3, self.one)],
                                            {1, 2, 3}, 3, (0x186, 0x140))
        self.assertEqual(result, 'callee_error')
        self.assertEqual(calls, [(1, 0), (2, 0)])

    def test_duplicate_model_ids_rejected(self):
        with self.assertRaises(ValueError):
            q.abstract_question([(1, 0), (1, self.one)], {1}, 2)

    def test_adjacent_key_coalescing_model(self):
        self.assertEqual(q.coalesce_sorted([]), [])
        self.assertEqual(q.coalesce_sorted([(1, 0), (1, self.one), (2, 0)]),
                         [(1, self.one), (2, 0)])
        self.assertEqual(q.coalesce_sorted([(1, self.one), (1, 0)]), [(1, 0)])
        with self.assertRaisesRegex(ValueError, 'nondecreasing'):
            q.coalesce_sorted([(2, 0), (1, 0)])

    def test_coalescing_window_branch_controls(self):
        code = bytearray.fromhex(q.WINDOWS['tree_equal_run'][1])
        self.assertEqual(q.coalesce_step(code, False, True, True), 'keep_current')
        self.assertEqual(q.coalesce_step(code, True, False, True), 'keep_current')
        self.assertEqual(q.coalesce_step(code, True, True, False), 'drop_current_without_cleanup')
        self.assertEqual(q.coalesce_step(code, True, True, True), 'drop_current_with_cleanup')
        code[11] ^= 1
        with self.assertRaisesRegex(ValueError, 'control flow'):
            q.coalesce_step(code, True, True, False)

    def test_large_sort_slot(self):
        self.assertEqual(q.indirect_slot(self.image, 0x489efee), 0x5775038)
        self.assertEqual(self.image.relocations({0x5775038}), {0x5775038: 0x44861f0})

    def test_row_length_branch_boundaries(self):
        self.assertEqual(q.abstract_input(True, 99, True, True, 1999), 'accepted')
        self.assertEqual(q.abstract_input(True, 100, True, True, 2000), 'accepted')
        self.assertEqual(q.abstract_input(True, 101, True, True, 2000), 'fraction_length_0x143')
        self.assertEqual(q.abstract_input(True, 100, True, True, 2001), 'detail_length_0x143')

    def test_length_gate_reads_immediate_and_rejects_bad_opcodes(self):
        raw = bytearray(bytes.fromhex(q.WINDOWS['row_length'][1]))
        self.assertTrue(q.length_gate(100, 'fraction', raw))
        self.assertFalse(q.length_gate(101, 'fraction', raw))
        raw[12] = 99
        self.assertFalse(q.length_gate(100, 'fraction', raw))
        raw[13] = 0x90
        with self.assertRaisesRegex(ValueError, 'comparison'):
            q.length_gate(100, 'fraction', raw)
        detail = bytearray(bytes.fromhex(q.WINDOWS['detail_length'][1]))
        self.assertTrue(q.length_gate(2000, 'detail', detail))
        self.assertFalse(q.length_gate(2001, 'detail', detail))
        detail[25] ^= 1
        with self.assertRaisesRegex(ValueError, 'comparison'):
            q.length_gate(0, 'detail', detail)
        with self.assertRaises(ValueError):
            q.length_gate(-1, 'fraction', raw)


if __name__ == '__main__':
    unittest.main()
