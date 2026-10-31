"""Unit tests for the node #94 multiply-mix-div61 evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded rule and an independent mulhi-tail cross-check. No
target execution anywhere.
"""
import json
import random
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_multiply_mix_div61 as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-multiply-mix-div61-94/evidence.json'
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


class MultiplyMixDiv61PacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'],
                         [0x555585d, 0x5556412, 0x5556f7e])
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

    def test_body_byte_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, tool.START + 1, b'\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_mix_multiplier_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, tool.START + 2, b'\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_division_magic_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, tool.START + 51, b'\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, tool.END, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_table_byte_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, tool.TABLE_BASE + 5, b'\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_bytes_corruption_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x555585d + 1, b'\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        mixed, idx, stored, ret = tool.apply_window(0, 0)
        self.assertEqual((mixed, idx, stored, ret),
                         (tool.C_ADD, 5, 0, 1))
        self.assertEqual(tool.apply_window(0, 61)[2], 144)
        self.assertEqual(tool.apply_window(0, 1)[2], 2)
        self.assertEqual(tool.apply_window(0, -1)[2], 4013330093)

    def test_mulhi_tail_matches_div61(self):
        # Independent restatement of the retained mulhi tail, compared
        # against Python integer division, not against the tool's rule.
        magic = tool.DIV_MAGIC
        random.seed(20261031)
        values = list(range(0, 2000))
        values += [random.getrandbits(64) for _ in range(5000)]
        values += [2 ** 64 - 1, 2 ** 63]
        for x in values:
            hi = (magic * x) >> 64
            tail = (hi + ((x - hi) >> 1)) >> 5
            self.assertEqual(tail, x // 61)

    def test_rule_matches_mulhi_tail(self):
        # The tool's rule (integer //61) agrees with the mulhi tail on
        # realistic inputs: table bytes times sign-extended fields.
        magic = tool.DIV_MAGIC
        random.seed(4242)
        for _ in range(2000):
            table_byte = random.randint(0, 255)
            field = random.randint(-2 ** 31, 2 ** 31 - 1)
            product = (table_byte * (field % (1 << 64))) % (1 << 64)
            hi = (magic * product) >> 64
            tail = (hi + ((product - hi) >> 1)) >> 5
            self.assertEqual(tail % (1 << 32), (product // 61) % (1 << 32))


if __name__ == '__main__':
    unittest.main()
