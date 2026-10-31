"""Unit tests for the node #94 global-clamp evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded rule. No target execution anywhere.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_global_clamp as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-global-clamp-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


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


class GlobalClampPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x54b9c6b, 0x54b9cc9])
        self.assertEqual(result['naming'], [])

    def test_check_cli_passes(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], tool.SHA256)
        self.assertEqual(retained['function']['start_va'], hex(tool.START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(tool.END))
        self.assertEqual(retained['function']['bytes'], tool.END - tool.START)
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(v) for v in result['call_sites']])
        self.assertIsNone(retained['naming_relocation']['slot'])
        self.assertIsNone(retained['naming_relocation']['type'])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5553a35, b'\xcc')  # final jmp -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_source_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x55539eb, struct.pack('<i', 0x2347f6))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_cap_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x55539fb, struct.pack('<I', 0x400001))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_store_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5553a18, struct.pack('<i', 0x45c27d))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_tail_jump_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5553a24, struct.pack('<i', -0x23fb7))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5553a36, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x54b9c6b, b'\xe8\x71\x9d\x09\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.clamp(-1), 0)
        self.assertEqual(tool.clamp(0), 1)
        self.assertEqual(tool.clamp(63), 1)
        self.assertEqual(tool.clamp(64), 1)
        self.assertEqual(tool.clamp(128), 2)
        self.assertEqual(tool.clamp(0x10000000), 0x400000)
        self.assertEqual(tool.clamp((1 << 63) - 1), 0x400000)


if __name__ == '__main__':
    unittest.main()
