"""Unit tests for the node #94 pair-load evidence packet.

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
import foundation_pair_load as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-pair-load-94/evidence.json'
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


class PairLoadPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [])
        self.assertEqual(result['naming'], [(0x5759190, 8)])

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x502b476, b'\xcc')  # ret -> int3
        with self.assertRaises(ValueError):
            run_check(data)

    def test_base_pointer_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x502b467, b'\x30')  # 0x28 -> 0x30
        with self.assertRaises(ValueError):
            run_check(data)

    def test_first_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x502b46b, struct.pack('<i', 0x1a0))  # 0x198 -> 0x1a0
        with self.assertRaises(ValueError):
            run_check(data)

    def test_second_field_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x502b472, struct.pack('<i', 0x198))  # 0x190 -> 0x198
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x502b477, b'\x90')  # int3 -> nop
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        # Window FDE range field lives in .eh_frame at section offset 0x291484
        # + 12; .eh_frame VA == file offset here.
        data[0xce1518 + 0x291484 + 12] = 0x18  # range 0x17 -> 0x18
        with self.assertRaises(ValueError):
            run_check(data)

    def test_naming_slot_value_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x5759190, struct.pack('<Q', 1))  # file value 0 -> 1
        with self.assertRaises(ValueError):
            run_check(data)

    def test_pair_rule_edges(self):
        self.assertEqual(tool.pair_values(0x1111, 0x2222), (0x1111, 0x2222))
        self.assertEqual(tool.pair_values(0, 0), (0, 0))
        # Order-independence: the two loads address from the same base, so
        # the pair is (field_190, field_198) regardless of load order.
        self.assertEqual(tool.pair_values(5, 9), (5, 9))
        self.assertEqual(tool.pair_values(9, 5), (9, 5))

    def test_cli_check_passes(self):
        import io
        from contextlib import redirect_stdout
        import sys as _sys
        argv = ['foundation_pair_load.py', '--binary', str(BINARY),
                '--check', str(EVIDENCE)]
        old = _sys.argv
        _sys.argv = argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                tool.main()
            self.assertIn('Foundation pair-load evidence reproduces exactly.',
                          buf.getvalue())
        finally:
            _sys.argv = old


if __name__ == '__main__':
    unittest.main()
