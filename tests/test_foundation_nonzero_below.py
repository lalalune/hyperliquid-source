"""Unit tests for the node #94 256-bit nonzero-and-below evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded predicate rule. No target execution anywhere.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_nonzero_below as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-nonzero-below-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'
MASK64 = (1 << 64) - 1


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


class NonzeroBelowPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x56508a6, 0x5650c86, 0x5651e5f])
        self.assertEqual(result['naming_slots'], [])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ddbc, b'\x48\x0f\x44\xc2')  # cmovne -> cmove
        with self.assertRaises(ValueError):
            run_check(data)

    def test_or_chain_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565dd96, b'\x4c\x09\xc0')  # or %r9 -> or %r8
        with self.assertRaises(ValueError):
            run_check(data)

    def test_borrow_mask_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ddae, b'\x48\x19\xfe')  # sbb %rsi,%rsi -> %rdi
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x565ddc5, b'\xcc')  # nop -> int3 in padding
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        # Flip one byte of the window FDE's range field in .eh_frame.
        secs = tool.sections(bytes(data))
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        off = eh['offset'] + 0x2dc334 + 12
        data[off] = 0x44
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_target_change_fails(self):
        data = fresh_data()
        # Point the first caller's call at a different VA.
        corrupt_va(data, 0x56508a6 + 1, struct.pack('<i', 0xd4d6))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_predicate_rule_edges(self):
        self.assertEqual(tool.predicate((0, 0, 0, 0), (1, 0, 0, 0)), 0)
        self.assertEqual(tool.predicate((1, 0, 0, 0), (2, 0, 0, 0)), 1)
        self.assertEqual(tool.predicate((2, 0, 0, 0), (2, 0, 0, 0)), 0)
        self.assertEqual(tool.predicate((2, 0, 0, 0), (1, 0, 0, 0)), 0)
        self.assertEqual(tool.predicate((0, 0, 0, 1), (0, 0, 0, 1)), 0)
        self.assertEqual(tool.predicate((1, 0, 0, 0),
                                        (MASK64, MASK64, MASK64, MASK64)), 1)
        self.assertEqual(tool.predicate((0, 1, 0, 0), (1, 1, 0, 0)), 1)
        self.assertEqual(tool.predicate((MASK64, MASK64, MASK64, MASK64),
                                        (MASK64, MASK64, MASK64, MASK64)), 0)

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_nonzero_below.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        try:
            _sys.argv = argv
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertEqual(
                buf.getvalue().strip(),
                'Foundation nonzero-below evidence reproduces exactly.')
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
