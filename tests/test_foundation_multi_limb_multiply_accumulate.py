"""Unit tests for the node #94 multi-limb multiply-accumulate packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_multi_limb_multiply_accumulate import (  # noqa: E402
    BODY, CALLERS, CIE0, END, FDE, NEXT, PAD_END, START,
    multiply_accumulate, analyze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-multi-limb-multiply-accumulate-94'
            / 'evidence.json')
MASK52 = (1 << 52) - 1


def load():
    return bytearray(TARGET.read_bytes())


class MultiplyAccumulateTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(multiply_accumulate([0, 0, 0, 0, 0]),
                         [0, 0, 0, 0, 0])
        self.assertEqual(multiply_accumulate([0, 0, 0, 0, 1 << 48]),
                         [0x1000003d1, 0, 0, 0, 0])
        self.assertEqual(multiply_accumulate([0, 0, 0, 0, 1]),
                         [0, 0, 0, 0, 1])
        self.assertEqual(multiply_accumulate([0, 0, 0, 0, 1 << 49]),
                         [0x2000007a2, 0, 0, 0, 0])
        self.assertEqual(multiply_accumulate(
            [MASK52, MASK52, MASK52, MASK52, 1 << 48]),
            [0x1000003d0, 0, 0, 0, 1])

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 123]), BODY)
        self.assertEqual(bytes(data[off + 123:off + 128]), b'\xcc' * 5)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2d8140:eh + 0x2d8140 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2d8154:eh + 0x2d8154 + len(NEXT)]), NEXT)

    def test_callers_match_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual([hex(c) for c in CALLERS],
                         retained['incoming_pattern_scan']['e8_candidates'])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'], [])

    def test_corruption_fails(self):
        data = load()
        off = START - 0x1000
        # A changed byte inside the window must fail analysis.
        data[off + 0x2c] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed padding byte must fail analysis.
        data = load()
        data[off + 123] = 0x90
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed caller FDE record byte must fail analysis.
        data = load()
        data[0xce1518 + 0x2d87fc + 10] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
