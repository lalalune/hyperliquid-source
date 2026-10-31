#!/usr/bin/env python3
"""Unit tests for the node #94 length-prefix-encoder checker.

Every test restates retained target bytes or the decoded rule; none executes
the captured binary. Corruption controls mutate one locked element at a time
and require the checker to fail.
"""
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_length_prefix_encoder import (  # noqa: E402
    BODY, CALLER_FDE, CALL_SITE, CALLER_START, CIE, END, FDE, PAD, PAD_END,
    SHA256, START, analyze, encode, inspect)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-length-prefix-encoder-94/evidence.json'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    # Apply replacements by VA using the .text VA/file-offset mapping.
    for va, old, new in replace:
        off = 0x1342c80 + (va - 0x1343c80)
        assert data[off:off + len(old)] == old, (hex(va), data[off:off + len(old)].hex())
        data[off:off + len(old)] = new
    return bytes(data)


class LengthPrefixEncoderTests(unittest.TestCase):
    def test_check_passes(self):
        result = inspect(str(BINARY))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['call_site'], CALL_SITE)

    def test_evidence_matches(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['target_sha256'], SHA256)
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'],
                         hashlib.sha256(BODY).hexdigest())
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(CALL_SITE)])

    def test_rule_edges(self):
        self.assertEqual(encode(0, 0x41), (b'\x01A', 2))
        self.assertEqual(encode(0x1f, 0x00), (b'\xf9\x00', 2))
        self.assertEqual(encode(0x20, 0x00), (b'\x05\x02\x00', 3))
        self.assertEqual(encode(0xfff, 0x00), (b'\xf5\xff\x00', 3))
        self.assertEqual(encode(0x1000, 0x00), (b'\x0d\x00\x01\x00', 4))
        self.assertEqual(encode(0x100000001, 0x00), (b'\x1d\x00\x00\x00', 4))
        self.assertEqual(encode(0xffffffff, 0x00), (b'\xfd\xff\xff\x00', 4))

    def test_body_shape(self):
        self.assertEqual(len(BODY), 106)
        self.assertEqual(BODY[0:4], bytes.fromhex('f30f1efa'))
        self.assertEqual(BODY[4:8], bytes.fromhex('4883f91f'))
        self.assertEqual(BODY[10:17], bytes.fromhex('8d0ccd01000000'))
        self.assertEqual(BODY[40:47], bytes.fromhex('4881f9ff0f0000'))
        self.assertEqual(BODY[105], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 6)
        self.assertEqual(PAD_END - END, 6)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 20)
        self.assertEqual(struct.unpack_from('<I', FDE, 12)[0], 0x6a)
        self.assertEqual(len(CALLER_FDE), 164)
        self.assertEqual(struct.unpack_from('<I', CALLER_FDE, 0)[0], 0xa0)
        self.assertEqual(CIE[:4], bytes.fromhex('14000000'))

    def test_window_byte_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START, bytes([BODY[0]]), b'\x90')]))

    def test_threshold_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 7, b'\x1f', b'\x1e')]))

    def test_path3_addend_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 64, b'\x0d', b'\x0c')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(END, b'\xcc', b'\x90')]))

    def test_call_site_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(CALL_SITE, b'\xe8', b'\x90')]))

    def test_call_target_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(CALL_SITE + 1, b'\x70', b'\x71')]))

    def test_caller_setup_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(0x5573e20, b'\x48', b'\x49')]))


if __name__ == '__main__':
    unittest.main()
