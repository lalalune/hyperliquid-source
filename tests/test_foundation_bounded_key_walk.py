"""Unit tests for the node #94 bounded key-walk packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_bounded_key_walk import (  # noqa: E402
    BODY, CALLER, CALLER_END, CALLER_START, CALL_SITE, CIE0, END, FDE,
    NEXT, PAD_END, START, analyze, bounded_key_walk,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-bounded-key-walk-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class BoundedKeyWalkTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        # Path 1: key below the first gate word stores (node, index, key).
        self.assertEqual(
            bounded_key_walk({'a': (None, 10, 5)}, 'a', 3, 4), ('a', 3, 4))
        # Path 2: the stored third field is the GATE WORD (10), not the
        # input key (5) — the loop's movzwl clobbered rsi.
        self.assertEqual(
            bounded_key_walk({'a': ('b', 10, 5), 'b': (None, 7, 20)},
                             'a', 3, 5),
            ('b', 4, 10))
        # Path 3: an exhausted chain stores (0, last node, last index).
        self.assertEqual(
            bounded_key_walk({'a': (None, 10, 5)}, 'a', 3, 9), (0, 'a', 3))
        # Multi-step walk: two gates pass, then the chain ends.
        self.assertEqual(
            bounded_key_walk({'a': ('b', 10, 9), 'b': ('c', 30, 8),
                              'c': (None, 1, 25)}, 'a', 0, 9),
            (0, 'c', 2))
        # Equal gate words keep walking (unsigned jae continues on <=).
        self.assertEqual(
            bounded_key_walk({'a': ('b', 10, 5), 'b': (None, 7, 10)},
                             'a', 0, 5),
            (0, 'b', 1))

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 106]), BODY)
        self.assertEqual(bytes(data[off + 106:off + 112]), b'\xcc' * 6)
        self.assertEqual(bytes(data[off - 8:off]), b'\xcc' * 8)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2e56c:eh + 0x2e56c + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2e580:eh + 0x2e580 + len(NEXT)]), NEXT)
        self.assertEqual(
            bytes(data[eh + 0x3eb2cc:eh + 0x3eb2cc + len(CALLER)]), CALLER)

    def test_caller_site_inside_caller_fde(self):
        self.assertTrue(CALLER_START <= CALL_SITE < CALLER_END)
        data = load()
        off = CALL_SITE - 0x1000
        rel = struct.unpack_from('<i', data, off + 1)[0]
        self.assertEqual(CALL_SITE + 5 + rel, START)

    def test_corrupt_window_byte_fails(self):
        data = load()
        data[START - 0x1000 + 0x45] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_branch_target_fails(self):
        data = load()
        data[START - 0x1000 + 0x19] = 0x00
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_padding_fails(self):
        data = load()
        data[START - 0x1000 + 106] = 0x90
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_caller_fde_fails(self):
        data = load()
        data[0xce1518 + 0x3eb2cc + 12] ^= 0xff
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
