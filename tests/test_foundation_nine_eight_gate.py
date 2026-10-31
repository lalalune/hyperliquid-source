"""Unit tests for the node #94 two-condition 9/8 gate evidence packet.

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
import foundation_nine_eight_gate as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-nine-eight-gate-94/evidence.json'
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


class NineEightGatePacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x5154497, 0x5154726])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5229867, b'\x0f\x95\xc0')  # sete -> setne
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5229866, b'\x02')  # cmp $0x1 -> cmp $0x2
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x522986e, b'\x05')  # cmp $0x4 -> cmp $0x5
        with self.assertRaises(ValueError):
            run_check(data)

    def test_base_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5229875, b'\x08')  # mov $0x9 -> mov $0x8
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x522987c, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_target_change_fails(self):
        data = fresh_data()
        # Point the second caller's rel32 at a different window.
        corrupt_va(data, 0x5154727, struct.pack('<i', 0x0d5100))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_caller_setup_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5154717, b'\x02')  # mov $0x1,%esi -> mov $0x2,%esi
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_caller_setup_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5154482, b'\x31\xff')  # xor %esi,%esi -> xor %edi,%edi
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.gate_value(1, 4), 8)
        self.assertEqual(tool.gate_value(1, 5), 9)
        self.assertEqual(tool.gate_value(0, 4), 9)
        self.assertEqual(tool.gate_value(0, 0), 9)
        self.assertEqual(tool.gate_value(0x100000001, 0x100000004), 8)
        self.assertEqual(tool.gate_value(0x100000002, 4), 9)

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        old_argv = sys.argv
        sys.argv = ['tool', '--binary', str(BINARY), '--check', str(EVIDENCE)]
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation nine-eight-gate evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            sys.argv = old_argv


if __name__ == '__main__':
    unittest.main()
