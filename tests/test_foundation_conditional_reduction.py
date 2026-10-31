"""Unit tests for the node #94 conditional-reduction evidence packet.

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
import foundation_conditional_reduction as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-conditional-reduction-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'
TOOL = ROOT / 'tools/foundation_conditional_reduction.py'


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


class ConditionalReductionPacketTests(unittest.TestCase):
    def test_check_passes_and_matches_retained(self):
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'],
                         [0x564a9ae, 0x564a9e3, 0x5650496, 0x56504d5])
        self.assertIsNone(result['naming_slot'])

    def test_cli_check_passes(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), '--check', str(EVIDENCE)],
            capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation conditional-reduction evidence reproduces exactly.',
                      proc.stdout)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ee99, b'\x90')  # repz ret prefix f3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_mul_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ee40 + 0x19, b'\x10')  # mulq 0x8(%rsi) -> 0x10(%rsi)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_top_store_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ee40 + 0x55, b'\x18')  # store 0x10(%rdi) -> 0x18(%rdi)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ee9b, b'\xcc')  # nop -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_range_change_fails(self):
        data = fresh_data()
        # .eh_frame VA == file offset; window FDE range field at +12.
        corrupt_va(data, 0xce1518 + 0x2dc468 + 12, struct.pack('<I', 92))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_bytes_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x564a9ae + 1, struct.pack('<i', 0x14400))  # retarget call
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_injection_fails(self):
        data = fresh_data()
        secs = tool.sections(bytes(data))
        rela = [s for s in secs if s['name'] == '.rela.dyn'][0]
        # First entry's addend field (offset 16 within the 24-byte record).
        data[rela['offset'] + 16:rela['offset'] + 24] = struct.pack(
            '<q', tool.START)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_gate_rule_edges(self):
        self.assertEqual(tool.reduce_step(100, 200, 300, 3, 0, 7),
                         (79, 200, 7, 7))
        self.assertEqual(tool.reduce_step(3, 4, 0, 5, 9, 1), (3, 4, 0, 0))
        self.assertEqual(tool.reduce_step(3, 4, 0, 5, 9, 2),
                         ((1 << 64) - 2, (1 << 64) - 6, 1, 1))
        self.assertEqual(tool.reduce_step(0, 0, 0, 5, 9, 1), (0, 0, 0, 0))
        self.assertEqual(tool.reduce_step(3, 4, 7, 0, 0, 5)[2],
                         tool.reduce_step(3, 4, 9, 0, 0, 5)[2])
        self.assertEqual(tool.reduce_step(11, 22, 33, 7, 8, 0), (11, 22, 0, 0))


if __name__ == '__main__':
    unittest.main()
