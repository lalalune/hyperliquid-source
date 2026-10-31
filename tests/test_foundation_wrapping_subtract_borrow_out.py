"""Unit tests for the node #94 four-limb wrapping subtract packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_wrapping_subtract_borrow_out import (  # noqa: E402
    BODY, CALLERS, CIE0, END, FDE, NEXT, PAD_END, START,
    wrapping_subtract, analyze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-wrapping-subtract-borrow-out-94'
            / 'evidence.json')
MASK = (1 << 64) - 1


def load():
    return bytearray(TARGET.read_bytes())


class WrappingSubtractTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(wrapping_subtract([0, 0, 0, 0], [0, 0, 0, 0]),
                         ([0, 0, 0, 0], 0))
        self.assertEqual(wrapping_subtract([1, 0, 0, 0], [0, 0, 0, 0]),
                         ([1, 0, 0, 0], 0))
        self.assertEqual(wrapping_subtract([0, 0, 0, 0], [1, 0, 0, 0]),
                         ([MASK, MASK, MASK, MASK], 1))
        self.assertEqual(wrapping_subtract([0, 1, 0, 0], [1, 0, 0, 0]),
                         ([MASK, 0, 0, 0], 0))
        self.assertEqual(wrapping_subtract([MASK, MASK, MASK, MASK],
                                           [1, 0, 0, 0]),
                         ([MASK - 1, MASK, MASK, MASK], 0))

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 81]), BODY)
        self.assertEqual(bytes(data[off + 81:off + 96]), b'\xcc' * 15)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x1095cc:eh + 0x1095cc + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x1095e0:eh + 0x1095e0 + len(NEXT)]), NEXT)

    def test_window_byte_corruption_fails(self):
        data = load()
        data[START - 0x1000 + 3] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load()
        data[END - 0x1000] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_fde_corruption_fails(self):
        data = load()
        data[0xce1518 + 0x1095cc + 8] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_callers_match_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual([hex(c) for c in CALLERS],
                         retained['incoming_pattern_scan']['e8_candidates'])
        self.assertEqual(
            retained['incoming_pattern_scan']['caller_fdes'],
            [['0x3299180', '0x32996b6']])
        self.assertEqual(
            retained['incoming_pattern_scan']['relocation_slots'], [])


if __name__ == '__main__':
    unittest.main()
