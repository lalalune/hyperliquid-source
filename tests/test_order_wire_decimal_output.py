"""Static controls for the #94 order-wire decimal output packet."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import order_wire_decimal_output as wire


class OrderWireDecimalOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = wire.BINARY.read_bytes()
        cls.qualified = wire.qualify(cls.data)
        cls.rows = wire.sections(cls.data)

    def test_fde_and_call_path(self):
        self.assertEqual(len(self.qualified['functions']), 5)
        self.assertEqual(len(self.qualified['calls']), 4)
        self.assertEqual([k['ascii'] for k in self.qualified['keys']], ['p', 's'])
        self.assertEqual(self.qualified['formatter']['digit_builder_target_va'], '0x4eabb90')
        self.assertEqual(self.qualified['negative_input_location']['line'], 326)

    def test_each_trailing_zero_branch_and_boundaries(self):
        for zeros in range(9):
            for multiplier in (1, 37, 4294967):
                x = multiplier * 10**zeros
                if x >= 1 << 63 or multiplier % 10 == 0:
                    continue
                carrier = wire.prepare(x, self.qualified)
                self.assertEqual(carrier[0] >> 16, 8 - zeros)
                self.assertEqual(carrier, wire.expected(x))
        for x in ((1 << 32)-1, 1 << 32, (1 << 63)-1, 1 << 63, (1 << 64)-1):
            self.assertEqual(wire.prepare(x, self.qualified), wire.expected(x))
        self.assertEqual(wire.prepare(0, self.qualified), (0, 0, 0))
        self.assertIsNone(wire.prepare(1 << 63, self.qualified))

    def test_decimal_text_examples(self):
        for raw, text in ((0, '0'), (1, '0.00000001'), (10, '0.0000001'),
                          (100000000, '1'), (123400000, '1.234'),
                          (100000001, '1.00000001'),
                          ((1 << 63)-1, '92233720368.54775807')):
            self.assertEqual(wire.render_carrier(wire.prepare(raw, self.qualified)), text)

    def test_all_deterministic_model_vectors(self):
        vectors = wire.samples()
        self.assertGreater(len(vectors), 16000)
        for x in vectors:
            self.assertEqual(wire.interpret(self.data, self.rows, x), wire.expected(x), x)
            self.assertEqual(wire.prepare(x, self.qualified), wire.expected(x), x)

    def test_bad_digest_and_bad_body(self):
        changed = bytearray(self.data)
        rows = wire.sections(changed)
        section = next(s for s in rows if s['name'] == '.text')
        changed[section['offset'] + 0x33305ae - section['address']] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            wire.require_target(changed)
        # Bypass the input identity gate to test the independent body check.
        with patch.object(wire, 'TARGET', wire.digest(changed)):
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                wire.qualify(changed)

    def test_interpreter_rejects_unknown_instruction(self):
        changed = bytearray(self.data)
        section = next(s for s in self.rows if s['name'] == '.text')
        changed[section['offset'] + 0x333057b - section['address']] = 0x90
        with self.assertRaisesRegex(ValueError, 'unsupported arithmetic opcode'):
            wire.interpret(changed, self.rows, 1)

    def test_interpreter_detects_mutated_divisibility_constant(self):
        changed = bytearray(self.data)
        section = next(s for s in self.rows if s['name'] == '.text')
        changed[section['offset'] + 0x33305e1 - section['address']] ^= 1
        self.assertNotEqual(wire.interpret(changed, self.rows, 10), wire.expected(10))

    def test_wrong_opcode_and_invalid_addresses(self):
        rows = wire.sections(self.data)
        with self.assertRaises(ValueError):
            wire.decoded_call(self.data, rows, 0x3330570)
        with self.assertRaises(ValueError):
            wire.read_va(self.data, rows, 0, 8, True)
        with self.assertRaises(ValueError):
            wire.read_va(self.data, rows, 0x3330570, -1)
        for x in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                wire.prepare(x, self.qualified)

    def test_corrupt_model_constant_is_detected_by_reference(self):
        altered = copy.deepcopy(self.qualified)
        altered['divisibility_inverse'] = 0
        x = 11
        self.assertNotEqual(wire.prepare(x, altered), wire.expected(x))


if __name__ == '__main__':
    unittest.main()
