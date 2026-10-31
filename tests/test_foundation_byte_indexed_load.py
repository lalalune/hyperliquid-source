#!/usr/bin/env python3
"""Unit tests for the foundation byte-indexed-load evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_byte_indexed_load as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-byte-indexed-load-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class ByteIndexedLoadTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        self.assertEqual(tool.rule(3, 5, 0x41), 0)
        self.assertEqual(tool.rule(10, 10, 0x7a), 0x7a)
        self.assertEqual(tool.rule(5, 3, 0x41), 0x41)
        self.assertEqual(tool.rule(255, 256, 0x41), 0)
        self.assertEqual(tool.rule(0, 0, 0x00), 0)
        self.assertEqual(tool.rule(200, 7, 0xff), 0xff)

    def test_rule_unsigned_index(self):
        # The compare is unsigned and full-width: a count byte (max 255)
        # is below any index above 255, and equal counts reach the load.
        for count in (0, 1, 127, 255):
            self.assertEqual(tool.rule(count, count, 0x55), 0x55)
            self.assertEqual(tool.rule(count, count + 1, 0x55), 0)
        self.assertEqual(tool.rule(255, 0x10000, 0x55), 0)

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x556bfe0 - 0x1000 + 4, b'\x0f', b'\x90')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x556bff6 - 0x1000, b'\xcc', b'\x90')]))

    def test_compare_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x556bfe0 - 0x1000 + 10, b'\x39', b'\x3b')]))

    def test_branch_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x556bfe0 - 0x1000 + 12, b'\x72', b'\x73')]))

    def test_indexed_load_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x556bfe0 - 0x1000 + 16, b'\x0f', b'\x90')]))

    def test_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2d0d78
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x16\x00\x00\x00', b'\x17\x00\x00\x00')]))

    def test_caller_call_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c8f0b - 0x1000, b'\xe8', b'\x90')]))

    def test_caller_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2d3c9c
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\xe4\x09\x00\x00', b'\xe5\x09\x00\x00')]))

    def test_extra_caller_fails(self):
        # Moving the caller's target away from the window must break the
        # locked scan count (1), not silently pass.
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c8f0b - 0x1000 + 1,
                                   bytes.fromhex('d030faff'), bytes.fromhex('d030fafe'))]))


if __name__ == '__main__':
    unittest.main()
