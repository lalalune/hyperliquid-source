"""Unit tests for the node #94 tail-gate evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded gate rule. No target execution anywhere.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tail_gate as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-tail-gate-94/evidence.json'
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


class TailGatePacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x24fc82b, 0x24fdce3])
        self.assertEqual(result['tail_target'], 0x2508760)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x250ab10, b'\x48\x0f\x42\xca')  # cmovae -> cmovb
        with self.assertRaises(ValueError):
            run_check(data)

    def test_threshold_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x250ab0a, b'\x03')  # cmp $0x2 -> cmp $0x3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x250ab32, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_n1_jump_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x250ab19, b'\x0a')  # je lands one byte early
        with self.assertRaises(ValueError):
            run_check(data)

    def test_tail_jump_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x250ab2e, struct.pack('<i', -9067))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x24fc82b, b'\xe8\xd0\xe2\x00\x01')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x24fdce3, b'\xe8\x18\xce\x00\x01')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_gate_edges(self):
        self.assertEqual(tool.gate_outcome(0), ('jump', 0x28))
        self.assertEqual(tool.gate_outcome(1), ('jump', 0x28))
        self.assertEqual(tool.gate_outcome(2), ('jump', 0x30))
        # The scout correction: v == 3 tail-jumps with +0x28, it does not
        # return 0x30 as the scout note predicted for all v > 2.
        self.assertEqual(tool.gate_outcome(3), ('jump', 0x28))
        self.assertNotEqual(tool.gate_outcome(3), ('return', 0x30))
        self.assertEqual(tool.gate_outcome(4), ('return', 0x30))
        self.assertEqual(tool.gate_outcome(5), ('return', 0x30))
        self.assertEqual(tool.gate_outcome(0xffffffffffffffff),
                         ('return', 0x30))

    def test_cli_check_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'tools/foundation_tail_gate.py'),
             '--binary', str(BINARY), '--check', str(EVIDENCE)],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation tail-gate evidence reproduces exactly.',
                      proc.stdout)


if __name__ == '__main__':
    unittest.main()
