"""Unit tests for the node #94 multiply-subtract evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded rule. No target execution anywhere.
"""
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_multiply_subtract as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-multiply-subtract-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'
TOOL = ROOT / 'tools/foundation_multiply_subtract.py'


def fresh_data():
    return bytearray(BINARY.read_bytes())


def run_check(data):
    return tool.analyze(bytes(data))


def corrupt_va(data, va, new_bytes):
    secs = tool.sections(bytes(data))
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + len(new_bytes) <= s['address'] + s['size']]
    assert len(matches) == 1, 'Test setup: ambiguous VA'
    s = matches[0]
    off = s['offset'] + va - s['address']
    data[off:off + len(new_bytes)] = new_bytes


class MultiplySubtractPacketTests(unittest.TestCase):
    def test_check_passes_and_matches_retained(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x564a9fe, 0x564aa26])
        self.assertIsNone(result['naming_slot'])

    def test_cli_check_passes(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), '--check', str(EVIDENCE)],
            capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation multiply-subtract evidence reproduces exactly.',
                      proc.stdout)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565eeb8, b'\x90')  # repz ret prefix f3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_imul_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565eea7 + 2, b'\xaf\x1e')  # imul (%rsi) -> different op
        with self.assertRaises(ValueError):
            run_check(data)

    def test_scalar_store_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565eea0 + 23, b'\x10')  # store 0x8(%rdi) -> 0x10(%rdi)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565eeba, b'\xcc')  # nop -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x564a9fe + 1, struct.pack('<i', 0x1449e))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.multiply_subtract(100, 3, 7), (79, 7))
        self.assertEqual(tool.multiply_subtract(100, 3, 0), (100, 0))
        self.assertEqual(tool.multiply_subtract(5, 3, 7), ((1 << 64) - 16, 7))
        self.assertEqual(tool.multiply_subtract(0, 2, (1 << 64) - 1),
                         (2, (1 << 64) - 1))


if __name__ == '__main__':
    unittest.main()
