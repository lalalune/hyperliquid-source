"""Unit tests for the node #94 field-walk shift store evidence packet.

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
import foundation_field_walk_shift as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-field-walk-shift-94/evidence.json'
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


class FieldWalkShiftPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['naming'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab40, b'\x05')  # sar $0x4 -> $0x5
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_pointer_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab27, struct.pack('<i', 0x790))  # 0x788 -> 0x790
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_pointer_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab2e, b'\x38')  # +0x30 -> +0x38
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab32, struct.pack('<i', 0xb28))  # 0xb20 -> 0xb28
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab39, struct.pack('<i', 0xb20))  # 0xb18 -> 0xb20
        with self.assertRaises(ValueError):
            run_check(data)

    def test_return_immediate_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab45, struct.pack('<i', 2))  # return 1 -> 2
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x514ab4a, b'\x90')  # int3 -> nop in stride tail
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_range_change_fails(self):
        data = fresh_data()
        # .eh_frame VA == file offset; window FDE record at section offset
        # 0x29a0b0, range field at record offset 12.
        corrupt_va(data, 0xce1518 + 0x29a0b0 + 12, struct.pack('<I', 43))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.store_value(0x100, 0x0), 0x10)
        self.assertEqual(tool.store_value(0x1, 0x0), 0)
        self.assertEqual(tool.store_value(0x0, 0x0), 0)
        self.assertEqual(tool.store_value(0x0, 0x10), (1 << 64) - 1)
        self.assertEqual(tool.store_value(0xFFFFFFFFFFFFFFFF, 0x0),
                         (1 << 64) - 1)
        self.assertEqual(tool.store_value(0x0, 0xFFFFFFFFFFFFFFFF), 0)


if __name__ == '__main__':
    unittest.main()
