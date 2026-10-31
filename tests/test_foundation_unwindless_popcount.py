"""Unit tests for the node #94 unwindless SWAR popcount64 packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_unwindless_popcount import (  # noqa: E402
    BODY, CALLERS, CIE0, END, LEAD_START, NEXT, NEXT_START, PREV, START,
    swar_popcount, analyze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-unwindless-popcount-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class UnwindlessPopcountTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])
        self.assertEqual(len(BODY), 98)
        self.assertEqual(retained['function']['bytes'], 98)

    def test_rule_edges(self):
        for value, expected in [
                (0, 0),
                (1, 1),
                (0x8000000000000000, 1),
                (0x5555555555555555, 32),
                (0xaaaaaaaaaaaaaaaa, 32),
                (0xffffffffffffffff, 64),
                (0x123456789abcdef0, 32),
                (0xf0f0f0f0f0f0f0f0, 32)]:
            self.assertEqual(swar_popcount(value), expected)
            self.assertEqual(swar_popcount(value), bin(value).count('1'))

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 98]), BODY)
        self.assertEqual(bytes(data[off - 12:off]), b'\xcc' * 12)
        self.assertEqual(bytes(data[off + 98:off + 98 + 14]), b'\xcc' * 14)
        self.assertEqual(BODY[-1:], b'\xc3')

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2dc6cc:eh + 0x2dc6cc + len(PREV)]), PREV)
        self.assertEqual(bytes(data[eh + 0x2dc6e4:eh + 0x2dc6e4 + len(NEXT)]), NEXT)

    def test_callers_match_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual([hex(c) for c in CALLERS],
                         retained['incoming_pattern_scan']['e8_candidates'])
        self.assertEqual(len(CALLERS), 25)
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'], [])
        self.assertEqual(
            retained['unwindless']['bracketing_fdes'],
            [['0x565ff80', '0x5660004'], ['0x5660080', '0x5660092']])

    def test_corruption_fails(self):
        data = load()
        off = START - 0x1000
        # A changed byte inside the window must fail analysis.
        data[off + 0x06] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed leading int3 byte must fail analysis.
        data = load()
        data[off - 1] = 0x90
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed trailing int3 byte must fail analysis.
        data = load()
        data[off + 98] = 0x90
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed bracketing FDE record byte must fail analysis.
        data = load()
        data[0xce1518 + 0x2dc6cc + 10] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))
        # A changed caller FDE record byte must fail analysis.
        data = load()
        data[0xce1518 + 0x28ac50 + 10] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
