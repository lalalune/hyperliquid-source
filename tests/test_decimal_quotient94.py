import unittest
from fractions import Fraction

from tools import decimal_quotient94 as q


class DecimalQuotientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.verified_data(q.TARGET.read_bytes())
        cls.image = q.Image(cls.data)

    def divide(self, left, right, image=None):
        status, result, machine = q.evaluate(image or self.image, q.pack(*left), q.pack(*right))
        return status, result, machine

    def test_zero_divisor_precedes_zero_numerator_and_payload_is_untouched(self):
        for a in (0, 1, q.MAX96):
            status, result, _ = self.divide((a, 28, 1), (0, 0, 0))
            self.assertEqual((status, result), (2, None))

    def test_zero_numerator_normalizes_flags_and_mantissa(self):
        for sign in (0, 1):
            status, result, _ = self.divide((0, 28, sign), (1, 0, 1))
            self.assertEqual((status, result), (0, (0, 0)))

    def test_exact_value_and_noncanonical_result_scale(self):
        status, result, _ = self.divide((1, 0, 0), (2, 0, 0))
        self.assertEqual(status, 0)
        self.assertEqual(result, (2 << 16, 50))
        self.assertEqual(q.numeric(result), Fraction(1, 2))

    def test_ties_to_even_at_scale_limit(self):
        for b, parity_site in ((2, 0x4eb0476), (1 << 32, 0x4eb02c1),
                               (1 << 64, 0x4eb04a1)):
            for a, expected in ((1, 0), (3, 2), (5, 2), (7, 4)):
                status, result, machine = self.divide((b//2*a, 28, 0), (b, 0, 0))
                self.assertEqual(status, 0)
                self.assertEqual(q.numeric(result), Fraction(expected, 10**28))
                self.assertIn(parity_site, machine.seen)

    def test_rounding_lemma_and_invalid_inputs(self):
        self.assertEqual(q.rounding_lemma(self.image)['exhaustive_8bit_remainder_divisor_parity_cases'], 65280)
        self.assertTrue(q.small_round_decision(1 << 31, (1 << 32)-1, 0))
        self.assertFalse(q.small_round_decision(1, 2, 0))
        self.assertTrue(q.small_round_decision(1, 2, 1))
        with self.assertRaises(ValueError):
            q.small_round_decision(2, 2, 0)
        with self.assertRaises(ValueError):
            q.small_round_decision(0, 0, 0)

    def test_corrupt_rounding_fragment_is_rejected(self):
        data = bytearray(self.data)
        at = self.image.text_off + 0x4eb046f - self.image.text_va
        data[at] ^= 1
        with self.assertRaises(q.ToolError):
            q.rounding_lemma(q.Image(data))

    def test_overflow_and_underflow(self):
        status, result, _ = self.divide((q.MAX96, 0, 0), (1, 1, 0))
        self.assertEqual((status, result), (1, None))
        status, result, _ = self.divide((1, 0, 0), (q.MAX96, 0, 0))
        self.assertEqual((status, q.numeric(result)), (0, Fraction(0)))

    def test_input_and_address_rejection(self):
        with self.assertRaises(ValueError):
            q.verified_data(self.data[:-1] + bytes([self.data[-1] ^ 1]))
        with self.assertRaises(ValueError):
            q.pack(1, 29, 0)
        with self.assertRaises(q.ToolError):
            self.image.fetch(0)

    def test_corrupt_zero_guard_is_rejected(self):
        data = bytearray(self.data)
        at = self.image.text_off + 0x4eafb82 - self.image.text_va
        data[at] ^= 1
        with self.assertRaises(q.ToolError):
            q.entry_guard(q.Image(data))

    def test_wrong_call_target_is_rejected(self):
        image = q.Image(self.data)
        image.slots[0x57762d0] += 1
        with self.assertRaises(q.ToolError):
            q.caller_anchor(image)

    def test_corrupt_tie_bit_changes_observed_result(self):
        for b, immediate in ((2, 0x4eb0479), (1 << 32, 0x4eb02c3),
                             (1 << 64, 0x4eb04a3)):
            data = bytearray(self.data)
            at = self.image.text_off + immediate - self.image.text_va
            self.assertEqual(data[at], 1)
            data[at] = 0
            mutant = q.Image(data)
            status, result, _ = self.divide((b//2*3, 28, 0), (b, 0, 0), mutant)
            self.assertEqual(status, 0)
            self.assertNotEqual(q.numeric(result), Fraction(2, 10**28))

    def test_fde_boundaries_are_real(self):
        for start in q.STARTS:
            first, end = self.image.fde_of(start)
            self.assertEqual(first, start)
            self.assertGreater(end, first)
            self.assertEqual(q.sweep(self.image, first, end)[-1].va +
                             q.sweep(self.image, first, end)[-1].size, end)


if __name__ == '__main__':
    unittest.main()
