"""Unit tests for the node #94 three-field span sum packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_three_field_span_sum import (  # noqa: E402
    BODY, CIE0, END, FDE, NEXT, PAD_END, SLOT, START, analyze, span_rule,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-three-field-span-sum-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class SpanSumTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(span_rule(0, 0, 0), 0)
        self.assertEqual(span_rule(7, 7, 11), 11)
        self.assertEqual(span_rule(5, 9, 3), (1 << 64) - 1)
        self.assertEqual(span_rule((1 << 64) - 1, 0, 1), 0)

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 20]), BODY)
        self.assertEqual(bytes(data[off + 20:off + 32]), b'\xcc' * 12)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2a8a64:eh + 0x2a8a64 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2a8a78:eh + 0x2a8a78 + len(NEXT)]), NEXT)

    def test_relocation_slot(self):
        data = load()
        found = []
        for sec_off, sec_size in [(0x6bc0, 0x1d4e10), (0x1db9d0, 0x1a10)]:
            for i in range(0, sec_size, 24):
                _, _, addend = struct.unpack_from('<QQq', data, sec_off + i)
                if addend == START:
                    addr, _, _ = struct.unpack_from('<QQq', data, sec_off + i)
                    found.append(addr)
        self.assertEqual(found, [SLOT])

    def test_corruption_fails(self):
        data = load()
        data[START - 0x1000 + 8] ^= 0x01  # flip a byte in the subtract
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_padding_corruption_fails(self):
        data = load()
        data[END - 0x1000] = 0x90  # first padding byte is no longer int3
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_analyze_reports_window(self):
        result = analyze(TARGET.read_bytes())
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['relocation_slots'], [['.rela.dyn', hex(SLOT)]])
        self.assertEqual(result['direct_callers'], [])


if __name__ == '__main__':
    unittest.main()
