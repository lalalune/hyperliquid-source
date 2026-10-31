"""Unit tests for the node #94 field-inequality-gate evidence packet.

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
import foundation_field_inequality as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-field-inequality-94/evidence.json'
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


class FieldInequalityPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'],
                         [0x4fbcd61, 0x5035b3b, 0x50562cb])
        self.assertEqual(result['naming'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a85, b'\xcc')  # ret -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a77, struct.pack('<i', 0x1460))  # 0x1458 -> 0x1460
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a7e, struct.pack('<i', 0x1480))  # 0x1478 -> 0x1480
        with self.assertRaises(ValueError):
            run_check(data)

    def test_setne_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a83, b'\x94')  # setne -> sete
        with self.assertRaises(ValueError):
            run_check(data)

    def test_stub_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a86, b'\x90')  # stub mov -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5035a96, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        # Window FDE range field lives in .eh_frame at section offset 0x291bf4
        # + 12; .eh_frame VA == file offset here.
        data[0xce1518 + 0x291bf4 + 12] = 0x17  # range 0x16 -> 0x17
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x4fbcd62, struct.pack('<i', 0x78d0b))  # rel32 + 1
        with self.assertRaises(ValueError):
            run_check(data)

    def test_gate_rule_edges(self):
        self.assertEqual(tool.gate(123456789, 123456789), 0)
        self.assertEqual(tool.gate(1, 2), 1)
        # 64-bit compare: a difference in only the high bit still gates to 1.
        self.assertEqual(tool.gate(0, 1 << 63), 1)
        self.assertEqual(tool.gate((1 << 64) - 1, (1 << 64) - 1), 0)
        # Low-byte-only caveat is about the return register, not the rule:
        # the rule itself is a full 64-bit inequality.
        self.assertEqual(tool.gate(0x100000001, 0x1), 1)

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_field_inequality.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        _sys.argv = argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation field-inequality evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
