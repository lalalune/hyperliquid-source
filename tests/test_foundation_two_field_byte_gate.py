"""Unit tests for the node #94 two-field byte-gate evidence packet.

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
import foundation_two_field_byte_gate as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-two-field-byte-gate-94/evidence.json'
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


class TwoFieldByteGatePacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['naming_slot'], 0x575af60)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x51384f8, b'\x02')  # xor $0x1 -> xor $0x2
        with self.assertRaises(ValueError):
            run_check(data)

    def test_gate_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x51384e7, struct.pack('<i', 0x168))  # 0x160 -> 0x168
        with self.assertRaises(ValueError):
            run_check(data)

    def test_value_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x51384f2, struct.pack('<i', 0x190))  # 0x189 -> 0x190
        with self.assertRaises(ValueError):
            run_check(data)

    def test_branch_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x51384ee, b'\x09')  # je +0x0a -> +0x09
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x51384fa, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_slot_value_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x575af60, struct.pack('<Q', 1))  # file value 0 -> 1
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_range_change_fails(self):
        data = fresh_data()
        # .eh_frame VA 0xce1518 + FDE offset 0x299888, range field at +12.
        corrupt_va(data, 0xce1518 + 0x299888 + 12, struct.pack('<I', 0x1b))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.gate(0, 0), 0)
        self.assertEqual(tool.gate(0, 0xff), 0)
        self.assertEqual(tool.gate(1, 0), 1)
        self.assertEqual(tool.gate(1, 1), 0)
        self.assertEqual(tool.gate(1, 2), 3)
        self.assertEqual(tool.gate(0xff, 0xff), 0xfe)
        self.assertEqual(tool.gate(7, 0x80), 0x81)

    def test_cli_check_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'tools/foundation_two_field_byte_gate.py'),
             '--binary', str(BINARY), '--check', str(EVIDENCE)],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation two-field byte-gate evidence reproduces exactly.',
                      proc.stdout)


if __name__ == '__main__':
    unittest.main()
