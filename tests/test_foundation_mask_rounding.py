#!/usr/bin/env python3
"""Unit tests for the foundation mask-rounding evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_mask_rounding as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-mask-rounding-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class MaskRoundingTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        self.assertEqual(tool.rule(0), 64)
        self.assertEqual(tool.rule(1), 64)
        self.assertEqual(tool.rule(0x1ffff), 131582)
        self.assertEqual(tool.rule(0x20000), 131584)
        self.assertEqual(tool.rule(0xff00ff00ff00feff), 0xfffffffffffffffd)
        self.assertEqual(tool.rule(0xff00ff00ff00ff00), 0xffffffffffffffb8)
        self.assertEqual(tool.rule((1 << 64) - 1), 0xffffffffffffffb8)

    def test_small_domain_minimum(self):
        # Exhaustive over the small path: the v == 0 branch never fires there.
        values = [tool.rule(i) for i in range(0x20000)]
        self.assertEqual(min(values), 64)
        self.assertTrue(all(v > 0 for v in values))

    def test_large_path_positive_sample(self):
        for value in (0x20000, 0x123456, 0xdeadbeef, 0xff00ff00ff00feff):
            self.assertTrue(0 < tool.rule(value) < (1 << 64))

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555e610 - 0x1000, b'\xf3', b'\x90')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555e65b - 0x1000, b'\xcc', b'\x90')]))

    def test_mask_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555e610 - 0x1000 + 6, b'\xff', b'\xfe')]))

    def test_limit_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555e610 - 0x1000 + 39, b'\xff\xff\x01\x00', b'\xfe\xff\x01\x00')]))

    def test_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2cfd9c
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x4b\x00\x00\x00', b'\x4c\x00\x00\x00')]))

    def test_caller_call_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x5081df3 - 0x1000, b'\xe8', b'\x90')]))

    def test_caller_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2b10b0
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x48\x06\x00\x00', b'\x49\x06\x00\x00')]))


if __name__ == '__main__':
    unittest.main()
