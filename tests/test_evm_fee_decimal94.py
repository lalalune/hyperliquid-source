import hashlib
import struct
import unittest

from tools import evm_fee_decimal94 as m


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.image = m.Image(cls.data)

    def changed(self, va, replacement, action):
        off = self.image.offset(va, len(replacement))
        old = self.image.data[off:off + len(replacement)]
        try:
            self.image.data[off:off + len(replacement)] = replacement
            with self.assertRaises(m.EvidenceError):
                action()
        finally:
            self.image.data[off:off + len(replacement)] = old

    def test_input_hash(self):
        self.assertEqual(m.authenticate(self.data), m.SHA256)
        with self.assertRaises(m.EvidenceError):
            m.authenticate(b'damaged input')
        with self.assertRaises(m.EvidenceError):
            m.authenticate(self.data, '0' * 64)

    def test_fde_bodies_and_edges(self):
        functions = self.image.validate()
        self.assertEqual(len(functions), 6)
        self.assertEqual(self.image.table_target(0x7c111c, 36), 0x4e46ede)
        self.assertEqual(self.image.table_target(0x7c17b0, 0), 0x4e58627)
        self.assertEqual(self.image.rel32(0x4e58a44, b'\xe8'), 0x4e581c0)
        self.assertEqual(hashlib.sha256(self.image.read(0x4e581c0, 688)).hexdigest(), m.FUNCTIONS[0x4e581c0][2])

    def test_code_and_branch_corruption(self):
        self.changed(0x4e58a1c, b'\x01', self.image.validate)
        self.changed(0x4e583a9, b'\x75', self.image.validate)
        self.changed(0x4e581d5, b'\x90', lambda: self.image.branch(0x4e581d5))

    def test_dispatch_and_format_corruption(self):
        self.changed(0x7c111c + 36 * 4, b'\x00\x00\x00\x00', self.image.validate)
        self.changed(0x7c17b0, b'\x00\x00\x00\x00', self.image.validate)
        self.changed(0x20ab40, b'\xc0', self.image.validate)
        self.changed(0x1fa6e0, b'X', self.image.validate)
        self.changed(0x7c19ec, b'1', self.image.validate)

    def test_slot_and_extent_corruption(self):
        old = self.image.reloc[0x576e1a8]
        try:
            self.image.reloc[0x576e1a8] = old + 1
            with self.assertRaises(m.EvidenceError):
                self.image.validate()
        finally:
            self.image.reloc[0x576e1a8] = old
        old_end = self.image.fdes[0x4e581c0]['end']
        try:
            self.image.fdes[0x4e581c0]['end'] = old_end - 1
            with self.assertRaises(m.EvidenceError):
                self.image.validate()
        finally:
            self.image.fdes[0x4e581c0]['end'] = old_end

    def test_duplicate_and_wrong_relocation_controls(self):
        one = struct.pack('<QQq', 0x1234, 8, 0x8888)
        section = {'offset': 0, 'size': len(one)}
        self.assertEqual(m.read_selected_relocations(one, section, {0x1234}), {0x1234: 0x8888})
        with self.assertRaises(m.EvidenceError):
            m.read_selected_relocations(one + one, {'offset': 0, 'size': 48}, {0x1234})
        other = struct.pack('<QQq', 0x1234, 7, 0x8888)
        with self.assertRaises(m.EvidenceError):
            m.read_selected_relocations(other, section, {0x1234})
        with self.assertRaises(m.EvidenceError):
            m.read_selected_relocations(one + other, {'offset': 0, 'size': 48}, {0x1234})

    def test_unbacked_and_cross_section_ranges(self):
        with self.assertRaises(m.EvidenceError):
            self.image.read(1 << 63, 1)
        with self.assertRaises(m.EvidenceError):
            self.image.read(-1, 1)
        with self.assertRaises(m.EvidenceError):
            self.image.read(0x4e581c0, -1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(m.EvidenceError):
            self.image.read(text['address'] + text['size'] - 1, 2)

    def test_selected_error_template_and_arm_count(self):
        p = m.compact_template(self.image, 0x1fa6df)
        self.assertEqual(p, [{'literal': 'sender does not have enough funds ('}, {'argument': 0},
                             {'literal': ') to cover transaction fees: '}, {'argument': 1}])
        for i in range(15):
            target = self.image.table_target(0x7c17b0, i)
            self.assertTrue(0x4e58610 <= target < 0x4e58836)
        with self.assertRaises(m.EvidenceError):
            self.image.table_target(0x7c17b0, 256)


class ArithmeticTests(unittest.TestCase):
    def test_limb_division_against_integer_divmod(self):
        seed = 0x142857
        for divisor in (1, 2, 10, (1 << 32) - 1, 1 << 32, 10 ** 19, m.U64):
            for _ in range(73):
                limbs = []
                for _ in range(4):
                    seed = (seed * 6364136223846793005 + 1442695040888963407) & m.U64
                    limbs.append(seed)
                quotient, remainder, steps = m.quotient_limbs(limbs, divisor)
                value = sum(n << (64 * i) for i, n in enumerate(limbs))
                q = sum(n << (64 * i) for i, n in enumerate(quotient))
                self.assertEqual((q, remainder), divmod(value, divisor))
                self.assertTrue(all(0 <= step[-1] < divisor for step in steps))

    def test_decimal_boundaries(self):
        radix = 10 ** 19
        values = {0, 1, m.U256}
        for shift in range(256):
            for delta in (-1, 0, 1):
                x = (1 << shift) + delta
                if 0 <= x <= m.U256:
                    values.add(x)
        for power in range(1, 5):
            for delta in (-1, 0, 1):
                x = radix ** power + delta
                if x <= m.U256:
                    values.add(x)
        for value in values:
            text, chunks, _ = m.format_lift(value, radix, 19)
            self.assertEqual(text, str(value))
            self.assertLessEqual(len(chunks), 5)
        self.assertEqual(len(m.split_chunks(m.U256, radix)[0]), 5)
        self.assertEqual(len(str(m.U256)), 78)

    def test_invalid_and_corrupt_arithmetic(self):
        for limbs, divisor in [([0, 0, 0, 0], 0), ([0, 0, 0], 10),
                               ([0, 0, 0, 1 << 64], 10), ([0, 0, 0, -1], 10),
                               ([0, 0, 0, 0], 1 << 64)]:
            with self.assertRaises(m.EvidenceError):
                m.quotient_limbs(limbs, divisor)
        for value, divisor, width in [(0, 0, 19), (-1, 10, 1), (1 << 256, 10, 1), (1, 10, 2), (1, 10, -1)]:
            with self.assertRaises(m.EvidenceError):
                m.format_lift(value, divisor, width)
        for value, radix in [(0, 0), (10, 1)]:
            with self.assertRaises(m.EvidenceError):
                m.split_chunks(value, radix)

    def test_wrapper_low_word_semantics(self):
        self.assertEqual(m.wrapper_route(0), 'zero')
        self.assertEqual(m.wrapper_route(1), 'transaction')
        self.assertEqual(m.wrapper_route((1 << 32) + 1), 'transaction')
        self.assertEqual(m.wrapper_route(1 << 32), 'other')
        self.assertEqual(m.wrapper_route(m.U64), 'other')
        with self.assertRaises(m.EvidenceError):
            m.wrapper_route(1 << 64)

    def test_buffer_boundary_and_overflow(self):
        for old, incoming, result in [(0, 0, ('write', 0)), (0, 256, ('write', 256)),
                                       (255, 1, ('write', 256)), (256, 1, ('error', 256)),
                                       (0, 257, ('error', 0)), (m.U64, 1, ('overflow', m.U64))]:
            self.assertEqual(m.bounded_write(old, incoming), result)
        with self.assertRaises(m.EvidenceError):
            m.bounded_write(-1, 1)


if __name__ == '__main__':
    unittest.main()
