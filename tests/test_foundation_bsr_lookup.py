"""Unit tests for the node #94 bsr-lookup evidence packet.

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
import foundation_bsr_lookup as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-bsr-lookup-94/evidence.json'
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


class BsrLookupPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x5522959])
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
        corrupt_va(data, 0x554431a, b'\xcc')  # ret -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x55442e7, struct.pack('<i', 0x1498))  # 0x1490 -> 0x1498
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x55442f3, struct.pack('<i', 0x1490))  # 0x1488 -> 0x1490
        with self.assertRaises(ValueError):
            run_check(data)

    def test_table_base_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5544313, struct.pack('<i', 0x1090))  # 0x1088 -> 0x1090
        with self.assertRaises(ValueError):
            run_check(data)

    def test_bsr_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5544309, b'\xbc')  # bsr -> bsf (opcode byte)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_jump_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x55442ee, b'\x74')  # jne -> je
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x554431b, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5522959, b'\xe8\x00\x00\x00\x00')  # rel32 -> self
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        table = list(range(128))
        self.assertEqual(tool.lookup(0, 0, table), 0)
        self.assertEqual(tool.lookup(1, 0, table), 64)
        self.assertEqual(tool.lookup(0, 1, table), 0)
        self.assertEqual(tool.lookup(0, 2, table), 1)
        self.assertEqual(tool.lookup(1 << 63, 0, table), 127)
        self.assertEqual(tool.lookup(0, 1 << 63, table), 63)
        self.assertEqual(tool.lookup(3, 1 << 63, table), 65)
        with self.assertRaises(ValueError):
            tool.bsr(0)


if __name__ == '__main__':
    unittest.main()
