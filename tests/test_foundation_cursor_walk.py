"""Unit tests for the node #94 cursor-walk evidence packet.

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
import foundation_cursor_walk as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-cursor-walk-94/evidence.json'
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


def corrupt_eh_offset(data, offset, new_bytes):
    secs = tool.sections(bytes(data))
    eh = next(s for s in secs if s['name'] == '.eh_frame')
    off = eh['offset'] + offset
    data[off:off + len(new_bytes)] = new_bytes


class CursorWalkPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x3362fb8])
        self.assertIsNone(result['naming_slot'])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3c1d6a3, b'\x45')  # movzbl tag load opcode changed
        with self.assertRaises(ValueError):
            run_check(data)

    def test_step_constant_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3c1d69f, b'\x40')  # lea step 0x38 -> 0x40
        with self.assertRaises(ValueError):
            run_check(data)

    def test_entry_branch_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3c1d69b, b'\x41')  # je +0x42 -> +0x41
        with self.assertRaises(ValueError):
            run_check(data)

    def test_loop_back_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3c1d6dc, b'\xe2')  # je -0x1d -> -0x1e
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3c1d6e1, b'\x90')  # first int3 pad -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        corrupt_eh_offset(data, 0x1beec4 + 12, struct.pack('<I', 0x52))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_bytes_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x3362fb8, b'\xe9')  # call -> jmp
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_relocation_injection_fails(self):
        data = fresh_data()
        secs = tool.sections(bytes(data))
        rela = next(s for s in secs if s['name'] == '.rela.dyn')
        off = rela['offset']
        data[off + 16:off + 24] = struct.pack('<q', 0x3c1d690)
        with self.assertRaises(ValueError):
            run_check(data)

    def test_walk_edges(self):
        self.assertEqual(tool.walk(0x1000, 0x1000, {}), (0, 0x1000))
        self.assertEqual(tool.walk(0x1000, 0x1038, {0x1000: (2, 0)}),
                         (1, 0x1038))
        self.assertEqual(tool.walk(0x1000, 0x1038, {0x1000: (3, 0)}),
                         (0, 0x1038))
        self.assertEqual(tool.walk(0x1000, 0x1038, {0x1000: (2, 9)}),
                         (0, 0x1038))
        self.assertEqual(
            tool.walk(0x1000, 0x10a8,
                      {0x1000: (2, 0), 0x1038: (2, 0), 0x1070: (2, 0)}),
            (1, 0x10a8))
        self.assertEqual(
            tool.walk(0x1000, 0x10a8,
                      {0x1000: (2, 0), 0x1038: (0, 0), 0x1070: (2, 0)}),
            (0, 0x1070))

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_cursor_walk.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        _sys.argv = argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation cursor-walk evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
