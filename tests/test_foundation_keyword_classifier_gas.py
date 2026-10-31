#!/usr/bin/env python3
"""Unit tests for the node #94 input/gas_limit keyword-classifier checker.

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

from foundation_keyword_classifier_gas import (  # noqa: E402
    BODY, CALLER_FDE, CALL_SITE, CALLER_START, CIE, END, FDE, PAD, PAD_END,
    SHA256, START, analyze, classify, inspect)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-keyword-classifier-gas-94/evidence.json'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    # Apply replacements by VA using the .text VA/file-offset mapping.
    for va, old, new in replace:
        off = 0x1342c80 + (va - 0x1343c80)
        assert data[off:off + len(old)] == old, (hex(va), data[off:off + len(old)].hex())
        data[off:off + len(old)] = new
    return bytes(data)


class ClassifierGasTests(unittest.TestCase):
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
        self.assertEqual(classify(b'input'), 0)
        self.assertEqual(classify(b'gas_limit'), 1)
        self.assertEqual(classify(b''), 2)
        self.assertEqual(classify(b'inputx'), 2)
        self.assertEqual(classify(b'gas_limix'), 2)
        self.assertEqual(classify(b'gas_limitx'), 2)
        self.assertEqual(classify(b'xxxxx'), 2)
        self.assertEqual(classify(b'xxxxxxxxx'), 2)
        self.assertEqual(classify(b'gaslimi'), 2)  # length 7, no test
        self.assertEqual(classify(b'gas_limit '), 2)  # length 10

    def test_body_shape(self):
        self.assertEqual(len(BODY), 86)
        self.assertEqual(BODY[0:3], bytes.fromhex('4889f8'))
        self.assertEqual(BODY[15:20], bytes.fromhex('b9696e7075'))
        self.assertEqual(BODY[42:52], bytes.fromhex('48b96761735f6c696d69'))
        self.assertEqual(BODY[85], 0xc3)
        self.assertEqual(PAD, b'\xcc' * 10)
        self.assertEqual(PAD_END - END, 10)

    def test_fde_records(self):
        self.assertEqual(len(FDE), 20)
        self.assertEqual(struct.unpack_from('<I', FDE, 12)[0], 0x56)
        self.assertEqual(len(CALLER_FDE), 84)
        self.assertEqual(struct.unpack_from('<I', CALLER_FDE, 0)[0], 0x50)
        self.assertEqual(CIE[:4], bytes.fromhex('14000000'))

    def test_window_byte_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START, bytes([BODY[0]]), b'\x90')]))

    def test_keyword_immediate_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 16, b'\x69', b'\x68')]))

    def test_gas_immediate_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(START + 44, b'\x67', b'\x66')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(END, b'\xcc', b'\x90')]))

    def test_call_site_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(CALL_SITE, b'\xe8', b'\x90')]))

    def test_call_target_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(CALL_SITE + 1, b'\xdd', b'\xde')]))

    def test_caller_setup_corruption_fails(self):
        with self.assertRaises(ValueError):
            analyze(mutated([(0x18fa9e9, b'\x48', b'\x49')]))


if __name__ == '__main__':
    unittest.main()
