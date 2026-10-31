"""Unit tests for the node #94 bsr clamp-ladder evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded rule. No target execution anywhere.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_bsr_clamp_ladder as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-bsr-clamp-ladder-94/evidence.json'
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


class BsrClampLadderPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['naming'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e980, b'\xf2')  # endbr64 -> endbr32 prefix
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rsi_minus_one_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e98a, b'\xfe')  # lea -1(%rsi) -> -2(%rsi)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_31_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e992, b'\x1e')  # mov $0x1f -> $0x1e
        with self.assertRaises(ValueError):
            run_check(data)

    def test_xor_31_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e99e, b'\x1e')  # xor $0x1f -> $0x1e
        with self.assertRaises(ValueError):
            run_check(data)

    def test_lo_min_cmova_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e9ad, b'\x42')  # cmova -> cmovb (min -> max)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_zero_default_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e9b2, b'\x0c')  # mov $0xb -> $0xc
        with self.assertRaises(ValueError):
            run_check(data)

    def test_clamp_12_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e9ba, b'\x0d')  # mov $0xc -> $0xd
        with self.assertRaises(ValueError):
            run_check(data)

    def test_clamp_5_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e9ce, b'\x06')  # mov $0x5 -> $0x6
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x556e9d8, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.bsr_clamp_ladder(0, 2, 4, 0), 5)
        self.assertEqual(tool.bsr_clamp_ladder(20, 256, 256, 3), 9)
        self.assertEqual(tool.bsr_clamp_ladder(7, 8, 8, 0), 5)
        self.assertEqual(tool.bsr_clamp_ladder(100, 1 << 20, 2, 0), 12)
        self.assertEqual(tool.bsr_clamp_ladder(6, 16, 16, 1), 5)

    def test_bsr_zero_inputs_undefined(self):
        with self.assertRaises(ValueError):
            tool.bsr_clamp_ladder(5, 0, 4, 0)  # bsr(rsi) of zero
        with self.assertRaises(ValueError):
            tool.bsr_clamp_ladder(5, 1, 4, 0)  # bsr(rsi-1) of zero
        with self.assertRaises(ValueError):
            tool.bsr_clamp_ladder(5, 2, 0, 0)  # bsr(rdx) of zero


if __name__ == '__main__':
    unittest.main()
