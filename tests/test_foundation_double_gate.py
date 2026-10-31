"""Unit tests for the node #94 double threshold gate evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded low-byte rule. No target execution anywhere.
"""
import json
import math
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_double_gate as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-double-gate-94/evidence.json'
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


class DoubleGatePacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['constant'], 1.0)
        self.assertEqual(result['slot'], 0x5759108)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5028a57, b'\x0f\x92\xc0')  # setae -> setb
        with self.assertRaises(ValueError):
            run_check(data)

    def test_field_offset_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5028a47, struct.pack('<i', 0xf39))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_constant_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5028a53, struct.pack('<i', -0x4e1e326))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_constant_bytes_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x20a730, bytes.fromhex('000000000000f03e'))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5028a5b, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        # Flip one byte of the window FDE's range field in .eh_frame.
        secs = tool.sections(bytes(data))
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        off = eh['offset'] + 0x291380 + 12
        data[off] = 0x1c
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_slot_addend_change_fails(self):
        data = fresh_data()
        # Point the RELATIVE record at slot 0x5759108 at a different VA.
        secs = tool.sections(bytes(data))
        relsec = [s for s in secs if s['name'] == '.rela.dyn'][0]
        raw = bytes(data[relsec['offset']:relsec['offset'] + relsec['size']])
        found = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if address == 0x5759108:
                found = relsec['offset'] + off + 16
                break
        assert found is not None, 'Test setup: slot not found'
        data[found:found + 8] = struct.pack('<q', 0x5028a41)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_gate_rule_edges(self):
        self.assertEqual(tool.gate_bit(1.0), 1)
        self.assertEqual(tool.gate_bit(0.9999999999999999), 0)
        self.assertEqual(tool.gate_bit(2.5), 1)
        self.assertEqual(tool.gate_bit(0.0), 0)
        self.assertEqual(tool.gate_bit(-1.0), 0)
        self.assertEqual(tool.gate_bit(float('nan')), 0)
        self.assertEqual(tool.gate_bit(float('inf')), 1)
        self.assertEqual(tool.gate_bit(float('-inf')), 0)

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_double_gate.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        try:
            _sys.argv = argv
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertEqual(
                buf.getvalue().strip(),
                'Foundation double-gate evidence reproduces exactly.')
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
