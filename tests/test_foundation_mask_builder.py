"""Unit tests for the node #94 bitmask-builder evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded mask rule. No target execution anywhere.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_mask_builder as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-mask-builder-94/evidence.json'
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


class MaskBuilderPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x54b9c3f])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5521d28, b'\x48\xd3\xe8')  # shl -> shr
        with self.assertRaises(ValueError):
            run_check(data)

    def test_global_slot_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5521d32, struct.pack('<i', 0x2663db))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5521d37, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_jump_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5521d20, b'\x0d')  # je lands one byte early
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x54b9c3f, b'\xe8\xcc\x80\x06\x01')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_mask_edges(self):
        self.assertEqual(tool.mask_value(0), 0)
        self.assertEqual(tool.mask_value(1), 1)
        self.assertEqual(tool.mask_value(63), 0x7fffffffffffffff)
        self.assertEqual(tool.mask_value(64), 0)
        self.assertEqual(tool.mask_value(65), 1)
        self.assertEqual(tool.mask_value(127), 0x7fffffffffffffff)
        self.assertEqual(tool.mask_value(255), 0x7fffffffffffffff)
        self.assertEqual(tool.mask_value((1 << 64) - 1), (1 << 64) - 1)
        # Low byte 0xff but value not -1: shift path, not the special case.
        self.assertEqual(tool.mask_value(0x1ff), 0x7fffffffffffffff)
        self.assertNotEqual(tool.mask_value(0x1ff), (1 << 64) - 1)

    def test_check_cli_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_mask_builder.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        _sys.argv = argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation mask-builder evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
