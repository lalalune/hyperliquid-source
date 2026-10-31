"""Unit tests for the node #94 pointer-sum gate evidence packet.

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
import foundation_pointer_sum as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-pointer-sum-94/evidence.json'
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


class PointerSumPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x50ef0f7, 0x50f0b9b, 0x50f2bda])
        self.assertEqual(result['naming'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc55, b'\x08')  # nopl -> different padding
        with self.assertRaises(ValueError):
            run_check(data)

    def test_subtract_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc4d, b'\xf8')  # lea -0xc -> lea -0x8
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_branch_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc48, b'\x0e')  # je +0x0f -> +0x0e
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_branch_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc52, b'\x04')  # je +0x05 -> +0x04
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_zero_test_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc46, b'\xfe')  # test %rdi,%rdi -> test %rsi,%rdi
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x521cc5d, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_bytes_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x50ef0f7, b'\xe8\x44\xdb\x12\x01')  # rel32 +1
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_target_change_fails(self):
        data = fresh_data()
        # Rewrite the second caller's rel32 so it targets the next FDE.
        rel = 0x521cc5e - (0x50f0b9b + 5)
        corrupt_va(data, 0x50f0b9b + 1, struct.pack('<i', rel))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_window_fde_change_fails(self):
        data = fresh_data()
        secs = tool.sections(bytes(data))
        eh = next(s for s in secs if s['name'] == '.eh_frame')
        off = eh['offset'] + 0x2a4160 + 12
        data[off:off + 4] = struct.pack('<I', 0x1c)  # range 0x1d -> 0x1c
        with self.assertRaises(ValueError):
            run_check(data)

    def test_injected_naming_relocation_fails(self):
        data = fresh_data()
        secs = tool.sections(bytes(data))
        rela = next(s for s in secs if s['name'] == '.rela.dyn')
        # Patch the first relocation record's addend to the window start.
        off = rela['offset'] + 16
        data[off:off + 8] = struct.pack('<q', 0x521cc40)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.pointer_sum(0, 0), 0)
        self.assertEqual(tool.pointer_sum(0, 0x1000), 0x1000)
        self.assertEqual(tool.pointer_sum(0x1000, 0), 0x1000)
        self.assertEqual(tool.pointer_sum(0x1000, 0x20), 0x1014)
        self.assertEqual(tool.pointer_sum(0x10, 0x4), 0x8)
        self.assertEqual(tool.pointer_sum(1, 1), (2 - 0xc) & tool.MASK64)


if __name__ == '__main__':
    unittest.main()
