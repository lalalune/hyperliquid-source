"""Controls for the byte-bound fixed-eight floating formatting research."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fixed8_float_rounding94 as m


class FixedEightResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        m.check_target(cls.data)
        cls.image = m.Image(cls.data, authenticate=False)
        cls.plan = m.guard_program(cls.image.bytes(m.GUARD_START, m.GUARD_END - m.GUARD_START, True))
        cls.trim_plan = m.trim_program(cls.image)
        cls.piece_plan = m.piece_program(cls.image)
        cls.carry_plan = m.carry_program(cls.image)

    def test_all_selected_fdes_and_target_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.TARGET_HASH)
        self.assertEqual(len(self.image.fdes), 7)
        for start in m.FUNCTIONS:
            off, body = self.image.body(start)
            self.assertGreater(off, 0)
            self.assertEqual(len(body), self.image.fdes[start]['end'] - start)

    def test_damaged_target_hash(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            m.check_target(changed)

    def test_damaged_selected_instruction(self):
        offset, _ = self.image.region(m.GUARD_START + 13, 1, True)
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'body mismatch'):
                self.image.body(0x1575f90)
            with self.assertRaisesRegex(ValueError, 'guard bytes changed'):
                m.guard_program(self.image.bytes(m.GUARD_START, m.GUARD_END - m.GUARD_START, True))
        finally:
            self.data[offset] = old

    def test_corrupted_branch_displacement(self):
        raw = bytearray(m.GUARD_BYTES)
        raw[15] ^= 1
        with self.assertRaisesRegex(ValueError, 'guard bytes changed'):
            m.guard_program(bytes(raw))
        with self.assertRaisesRegex(ValueError, 'guard bytes changed'):
            m.guard_program(m.GUARD_BYTES[:-1])

    def test_target_relocation_is_required(self):
        slot = 0x5770600
        original = self.image.relocations[slot]
        try:
            self.image.relocations[slot] = original + 16
            with self.assertRaisesRegex(ValueError, 'relocation target'):
                m.read_edge(self.image, next(e for e in m.EDGES if e[0] == 'fast_generator'))
            del self.image.relocations[slot]
            with self.assertRaisesRegex(ValueError, 'relocation target'):
                self.image.relative(slot, original)
        finally:
            self.image.relocations[slot] = original

    def test_carry_symbol_relocation_control(self):
        slot = 0x576e1f8
        original = self.image.symbol_relocations[slot]
        self.assertEqual(self.image.symbolic(slot, 'memset')['symbol_index'], 10)
        try:
            self.image.symbol_relocations[slot] = (original[0] + 1, 0)
            with self.assertRaisesRegex(ValueError, 'symbol name mismatch'):
                self.image.symbolic(slot, 'memset')
            self.image.symbol_relocations[slot] = (original[0], 1)
            with self.assertRaisesRegex(ValueError, 'symbol relocation mismatch'):
                self.image.symbolic(slot, 'memset')
        finally:
            self.image.symbol_relocations[slot] = original

    def test_call_edges_and_selected_branch_targets(self):
        edges = {row[0]: m.read_edge(self.image, row) for row in m.EDGES}
        self.assertEqual(edges['fast_guard_a']['target'], '0x1575f90')
        self.assertEqual(edges['fast_guard_b']['target'], '0x1575f90')
        self.assertEqual(m.branch(self.image, 0x15713c9)['target'], '0x15714a2')
        self.assertEqual(m.branch(self.image, 0x1577a39)['target'], '0x157799a')
        with self.assertRaisesRegex(ValueError, 'conditional branch'):
            m.branch(self.image, m.GUARD_START)

    def test_request_and_shared_precision_edge_corruption(self):
        self.assertEqual(m.read_request(self.image), bytes.fromhex('e520000070010000'))
        for va, message in ((0x20a150, 'template changed'),
                            (0x13cd28f, 'descriptor bytes changed'),
                            (0x1571d5a, 'precision edge changed')):
            off, _ = self.image.region(va, 1)
            old = self.data[off]
            try:
                self.data[off] ^= 1
                with self.assertRaisesRegex(ValueError, message):
                    m.read_request(self.image)
            finally:
                self.data[off] = old

    def test_file_backed_and_range_controls(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.bytes(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.bytes(0xfffffffffffffff0, 32)
        with self.assertRaises(ValueError):
            self.image.bytes(-1, 1)
        with self.assertRaises(ValueError):
            self.image.bytes(0x13cd260, 0)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.bytes(text['address'] + text['size'] - 1, 2, True)

    def test_full_power_table_and_corruption(self):
        constants = m.decoded_constants(self.image)
        rows = m.read_table(self.image, constants['limit'])
        self.assertEqual(len(rows), 81)
        self.assertEqual((rows[0]['decimal_exp'], rows[-1]['decimal_exp']), (-308, 332))
        self.assertEqual([r['decimal_exp'] for r in rows if r['rounding'] == 'exact'], [4, 12, 20])
        off, _ = self.image.region(0x255db8, 1)
        old = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'rounded power'):
                m.read_table(self.image, constants['limit'])
        finally:
            self.data[off] = old

    def test_float_class_and_factor_boundaries(self):
        cases = [(0, 'zero'), (1, 'subnormal'), ((1 << 52)-1, 'subnormal'),
                 (1 << 52, 'normal'), (0x7fefffffffffffff, 'normal'),
                 (0x7ff0000000000000, 'infinity'), (0x7ff0000000000001, 'nan')]
        for raw, expected in cases:
            self.assertEqual(m.float_parts(raw)[3], expected)
            self.assertEqual(m.float_parts(raw | (1 << 63))[3], expected)
        for e in (1, 2, 999, 1023, 2046):
            for frac in (0, 1, (1 << 52)-1):
                bits = (e << 52) | frac
                mantissa, exponent = m.factor_for_bits(bits)
                observed = m.Fraction(mantissa) * m.power_two(exponent)
                expected = m.Fraction((1 << 52) + frac) * m.power_two(e - 1075)
                self.assertEqual(observed, expected)
        with self.assertRaises(ValueError):
            m.float_parts(1 << 64)
        with self.assertRaises(ValueError):
            m.factor_for_bits(0)

    def test_full_domain_index_partition_edges(self):
        constants = m.decoded_constants(self.image)
        index = lambda x: m.index_for_factor(*m.factor_for_bits(x), constants)
        self.assertEqual(index(1), 80)
        self.assertEqual(index((1 << 52) - 1), 78)
        self.assertEqual(index(1 << 52), 78)
        self.assertEqual(index(0x7fefffffffffffff), 1)
        for e in range(1, 2047):
            self.assertEqual(index(e << 52), index((e << 52) | ((1 << 52)-1)))
            self.assertEqual(m.index_operand(*m.factor_for_bits(e << 52), constants),
                             m.index_operand(*m.factor_for_bits((e << 52) | ((1 << 52)-1)), constants))
        for bit in range(52):
            self.assertEqual(index(1 << bit), index((1 << (bit + 1))-1))
        with self.assertRaises(ValueError):
            m.index_for_factor(0, 0, constants)

    def test_formatter_capacity_and_precondition_boundaries(self):
        constants = m.decoded_constants(self.image)
        self.assertEqual(m.formatter_capacity(-1076, constants), (12912, 828))
        self.assertEqual(m.formatter_capacity(0, constants), (0, 21))
        self.assertEqual(m.formatter_capacity(970, constants), (4850, 324))
        self.assertEqual(m.formatter_capacity(-1338, constants)[0], 16056)
        self.assertEqual(m.formatter_capacity(3212, constants)[0], 16060)
        for exponent in (-1339, 3213, -32769, 32768):
            with self.assertRaises(ValueError):
                m.formatter_capacity(exponent, constants)
        for va, expected in m.ASSERTIONS.values():
            self.assertEqual(self.image.bytes(va, len(expected)), expected)

    def test_fast_guard_boundaries(self):
        cases = [(4, 10, 1, 'keep'), (5, 10, 1, 'fallback'),
                 (6, 10, 1, 'increment'), (0, 10, 5, 'fallback'),
                 ((1 << 64)-1, (1 << 64)-1, 1, 'increment')]
        for a, b, c, expected in cases:
            self.assertEqual(m.guard_lift(self.plan, a, b, c), expected)
            self.assertEqual(m.guard_spec(a, b, c), expected)
        for a, b, c in ((10, 9, 1), (1, 10, 0)):
            with self.assertRaises(ValueError):
                m.guard_spec(a, b, c)
        with self.assertRaises(ValueError):
            m.guard_lift(self.plan, 1 << 64, 0, 0)

    def test_slow_comparator_and_ties(self):
        for digit in range(10):
            self.assertFalse(m.slow_compare([7, 0], [8, 0], digit))
            self.assertTrue(m.slow_compare([0, 1], [0xffffffff, 0], digit))
            self.assertEqual(m.slow_compare([7, 2], [7, 2], digit), bool(digit & 1))
        self.assertFalse(m.slow_compare([7], [7], None))
        self.assertTrue(m.slow_compare([0] * 39 + [1], [0xffffffff] * 39 + [0], 0))
        with self.assertRaises(ValueError):
            m.slow_compare([1], [], 0)
        with self.assertRaises(ValueError):
            m.slow_compare([1 << 32], [0], 0)
        with self.assertRaises(ValueError):
            m.slow_compare([1], [1], 10)

    def test_slow_comparator_single_limb_exhaustive(self):
        for left in range(256):
            for right in range(256):
                for digit in (0, 1):
                    expected = left > right or (left == right and digit == 1)
                    self.assertEqual(m.slow_compare([left], [right], digit), expected)

    def test_intermediate_high_product_half_up(self):
        for a in range(256):
            for b in range(256):
                self.assertEqual(m.rounded_product_high(a, b, 8), (a * b + 128) // 256)
        constants = m.decoded_constants(self.image)
        table = m.read_table(self.image, constants['limit'])
        mantissa, exponent = m.factor_for_bits(1 << 52)
        index = m.index_for_factor(mantissa, exponent, constants)
        normalized = mantissa << (64 - mantissa.bit_length())
        factor = int(table[index]['mantissa_hex'], 16)
        high, low = divmod(normalized * factor, 1 << 64)
        self.assertEqual((index, low, high & 1), (78, 1 << 63, 0))
        self.assertEqual(m.rounded_product_high(normalized, factor), high + 1)
        self.assertEqual(m.rounded_product_high((1 << 64)-1, (1 << 64)-1), (1 << 64)-2)
        with self.assertRaises(ValueError):
            m.rounded_product_high(1 << 64, 1)

    def test_rounded_product_opcode_corruption(self):
        offset, _ = self.image.region(0x15761dc, 1, True)
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'rounded high product instructions changed'):
                m.decoded_constants(self.image)
        finally:
            self.data[offset] = old

    def test_trim_loop_and_conditional_tie_examples(self):
        vectors = [(b'0.00000000', b'0'), (b'-0.00000000', b'0'),
                   (b'1.23000000', b'1.23'), (b'100.00000000', b'100'),
                   (b'inf', b'inf'), (b'NaN', b'NaN'), (b'1000', b'1'), (b'', b'')]
        for source, expected in vectors:
            self.assertEqual(m.trim_ascii(source), expected)
            self.assertEqual(m.walk_trim(self.trim_plan, source), expected)
        self.assertEqual(m.walk_trim(self.trim_plan, b'\xff0'), b'\xff')
        with self.assertRaises(ValueError):
            m.walk_trim({}, b'0')
        self.assertEqual(m.fixed8_model(1014 << 52), '0.00195312')
        self.assertEqual(m.fixed8_model((1015 << 52) | (1 << 51)), '0.00585938')
        self.assertEqual(m.fixed8_model(1 << 63), '0')
        self.assertEqual(m.fixed8_model((1 << 63) | 1), '0')
        self.assertEqual(m.fixed8_model(0x7ff0000000000000), 'inf')

    def test_trim_instruction_corruption(self):
        offset, _ = self.image.region(0x13cd2d5, 1, True)
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'trim instruction changed'):
                m.trim_program(self.image)
        finally:
            self.data[offset] = old

    def test_piece_layout_and_failure_guards(self):
        cases = [(-2, 8, b'0.00123000'), (0, 8, b'0.12300000'),
                 (1, 8, b'1.23000000'), (2, 8, b'12.30000000'),
                 (3, 8, b'123.00000000'), (5, 8, b'12300.00000000'),
                 (5, 0, b'12300')]
        for exponent, precision, expected in cases:
            pieces = m.build_pieces(self.piece_plan, b'123', exponent, precision)
            self.assertEqual(m.render_pieces(pieces), expected)
            self.assertLessEqual(len(pieces), 4)
        with self.assertRaisesRegex(ValueError, 'empty'):
            m.build_pieces(self.piece_plan, b'', 1, 8)
        with self.assertRaisesRegex(ValueError, 'first byte'):
            m.build_pieces(self.piece_plan, b'0123', 1, 8)
        with self.assertRaisesRegex(ValueError, 'capacity'):
            m.build_pieces(self.piece_plan, b'123', 1, 8, 3)
        with self.assertRaisesRegex(ValueError, 'width'):
            m.build_pieces(self.piece_plan, b'123', 32768, 8)
        self.assertEqual(m.build_pieces(self.piece_plan, b'1', -32768, 0)[1], ('zeros', 32768))
        self.assertEqual(m.build_pieces(self.piece_plan, b'1', 32767, 0)[1], ('zeros', 32766))

    def test_piece_instruction_corruption(self):
        offset, _ = self.image.region(0x1575e2d, 1, True)
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'piece instruction changed'):
                m.piece_program(self.image)
        finally:
            self.data[offset] = old

    def test_carry_paths_and_signed_overflow(self):
        for mode in ('fast', 'slow'):
            self.assertEqual(m.carry_lift(self.carry_plan, b'129', 1, 0, 4, mode), (b'130', 1, False))
            self.assertEqual(m.carry_lift(self.carry_plan, b'999', 1, 0, 4, mode), (b'1000', 2, True))
            self.assertEqual(m.carry_lift(self.carry_plan, b'999', 1, 0, 3, mode), (b'100', 2, False))
            self.assertEqual(m.carry_lift(self.carry_plan, b'999', -1, 0, 4, mode), (b'100', 0, False))
        self.assertEqual(m.carry_lift(self.carry_plan, b'9', 32767, 0, 2, 'fast'), (b'1', -32768, False))
        self.assertEqual(m.carry_lift(self.carry_plan, b'9', 32767, 0, 2, 'slow'), (b'10', -32768, True))
        for digits, exponent, cutoff, capacity, mode in ((b'', 0, 0, 1, 'fast'),
                (b'2x', 0, 0, 2, 'fast'), (b'99', 0, 0, 1, 'fast'),
                (b'9', 32768, 0, 1, 'fast'), (b'9', 0, 0, 1, 'unknown')):
            with self.assertRaises(ValueError):
                m.carry_lift(self.carry_plan, digits, exponent, cutoff, capacity, mode)

    def test_carry_instruction_corruption(self):
        offset, _ = self.image.region(0x15760bb, 1, True)
        old = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'carry instruction changed'):
                m.carry_program(self.image)
        finally:
            self.data[offset] = old


if __name__ == '__main__':
    unittest.main()
