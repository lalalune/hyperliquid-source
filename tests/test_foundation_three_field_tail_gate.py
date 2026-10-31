"""Unit tests for the node #94 three-field tail-gate evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded rule. No target execution anywhere.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_three_field_tail_gate as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-three-field-tail-gate-94/evidence.json'
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


class ThreeFieldTailGatePacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x47b6f24])
        self.assertEqual(result['naming'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b120, b'\x81')  # cmpb -> cmp r/m32
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b122, b'\x89')  # +0x88 -> +0x89
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_branch_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b128, b'\x18')  # jne +0x19 -> +0x18
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_compare_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b12f, b'\x02')  # cmpb $0x3 -> $0x2
        with self.assertRaises(ValueError):
            run_check(data)

    def test_third_field_width_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b132, b'\x83')  # cmpw -> cmp r/m32, imm8
        with self.assertRaises(ValueError):
            run_check(data)

    def test_tail_add_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b13c, b'\x70')  # add $0x68 -> $0x70
        with self.assertRaises(ValueError):
            run_check(data)

    def test_tail_jump_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b13e, b'\x8f')  # rel32 low byte change
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x473b143, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_bytes_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x47b6f24, b'\xe9')  # call -> jmp
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.three_field_tail_gate(3, 3, 3, 0x1000),
                         ('tail', 0x1068))
        self.assertEqual(tool.three_field_tail_gate(2, 3, 3, 0x1000),
                         ('ret', 0x1000))
        self.assertEqual(tool.three_field_tail_gate(3, 2, 3, 0x1000),
                         ('ret', 0x1000))
        self.assertEqual(tool.three_field_tail_gate(3, 3, 2, 0x1000),
                         ('ret', 0x1000))
        self.assertEqual(tool.three_field_tail_gate(3, 3, 0x103, 0x1000),
                         ('ret', 0x1000))
        self.assertEqual(tool.three_field_tail_gate(0, 0, 0, 0x1000),
                         ('ret', 0x1000))


if __name__ == '__main__':
    unittest.main()
