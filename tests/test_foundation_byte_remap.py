#!/usr/bin/env python3
"""Unit tests for the foundation byte-remap evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_byte_remap as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-byte-remap-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class ByteRemapTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        esi = 0xdeadbeef
        self.assertEqual(tool.rule(0x123456c0, esi), 0x123456c0)
        self.assertEqual(tool.rule(0x123456df, esi), 0x123456df)
        self.assertEqual(tool.rule(0xe0, esi), esi)
        self.assertEqual(tool.rule(0xbf, esi), esi)
        self.assertEqual(tool.rule(0x00, 0xabcdef12), 0xabcdef12)
        self.assertEqual(tool.rule(0x01, 0xabcdef12), 0x82)
        self.assertEqual(tool.rule(0x8f, 0x123456ff), 0x8f)
        self.assertEqual(tool.rule(0x90, 0x12345678), 0x98)
        self.assertEqual(tool.rule(0x91, 0x12345678), 0x12345678)
        self.assertEqual(tool.rule(0xa0, 0x12345678), 0xb8)
        self.assertEqual(tool.rule(0xa1, 0x12345678), 0x12345678)

    def test_early_range_boundaries(self):
        for b in range(0xc0, 0xe0):
            self.assertEqual(tool.rule(b, 0x12345678), b)
        self.assertEqual(tool.rule(0xbf, 0x12345678), 0x12345678)
        self.assertEqual(tool.rule(0xe0, 0x12345678), 0x12345678)

    def test_low_range_exhaustive(self):
        # Every low-range byte maps through the 4-bit mask, except 0 itself.
        for b in range(1, 0x90):
            self.assertEqual(tool.rule(b, 0xffffffff), 0x80 | (0xf & 0xf))
        self.assertEqual(tool.rule(0x00, 0xffffffff), 0xffffffff)

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x25acc20 - 0x1000, b'\x89', b'\x90')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x25acc6e - 0x1000, b'\xcc', b'\x90')]))

    def test_range_constant_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x25acc20 - 0x1000 + 13, b'\x20', b'\x21')]))

    def test_tag_constant_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x25acc20 - 0x1000 + 27, b'\x90\x00\x00\x00', b'\x91\x00\x00\x00')]))

    def test_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x94080
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x4e\x00\x00\x00', b'\x4f\x00\x00\x00')]))

    def test_caller_call_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x1dfe6d5 - 0x1000, b'\xe8', b'\x90')]))

    def test_caller_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x37444
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x48\x01\x00\x00', b'\x49\x01\x00\x00')]))


if __name__ == '__main__':
    unittest.main()
