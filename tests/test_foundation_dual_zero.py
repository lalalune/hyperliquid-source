"""Unit tests for the node #94 dual-zero test evidence packet.

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
import foundation_dual_zero as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-dual-zero-94/evidence.json'
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


class DualZeroPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['naming_slot'], 0x5762a78)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x534193e, b'\x0f\x95\xc0')  # sete -> setne
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x534192d, struct.pack('<i', 0x930))  # 0x928 -> 0x930
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5341937, struct.pack('<i', 0x950))  # 0x948 -> 0x950
        with self.assertRaises(ValueError):
            run_check(data)

    def test_branch_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5341933, b'\x0a')  # jne +0x0b -> +0x0a
        with self.assertRaises(ValueError):
            run_check(data)

    def test_pointer_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5341927, b'\x10')  # rdi+8 -> rdi+0x10
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_slot_value_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5762a78, struct.pack('<Q', 0x5341920))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_incoming_call_change_fails(self):
        data = fresh_data()
        # Plant a fake direct call: overwrite five bytes inside .text
        # that this checker does not otherwise lock (inside the next FDE's
        # code body, whose bytes are not locked here) with an e8 whose
        # rel32 targets the window. The scan must count it and fail.
        text = tool.sections(bytes(data))
        by_name = {s['name']: s for s in text}
        sec = by_name['.text']
        # Write e8 rel32 at a VA inside .text that is not a locked window:
        # use the window's own first byte region is locked, so use an
        # address 0x1000 past the window end (inside the next FDE, whose
        # bytes are not locked by this checker except the FDE record).
        va = 0x5341940 + 0x10
        off = sec['offset'] + va - sec['address']
        rel = 0x5341920 - (va + 5)
        data[off:off + 5] = b'\xe8' + struct.pack('<i', rel)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_rule_edges(self):
        self.assertEqual(tool.gate_value(0, 0), 1)
        self.assertEqual(tool.gate_value(0, 1), 0)
        self.assertEqual(tool.gate_value(1, 0), 0)
        self.assertEqual(tool.gate_value(5, 7), 0)
        self.assertEqual(tool.gate_value(0x100000000, 0), 0)
        self.assertEqual(tool.gate_value(0, 0xffffffffffffffff), 0)

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_dual_zero.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        _sys.argv = argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation dual-zero evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
