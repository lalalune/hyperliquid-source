"""Unit tests for the node #94 flag-gated span advance packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_flag_gated_span_advance import (  # noqa: E402
    BODY, CIE0, END, FDE, GATE_PREFIX, NEXT, PAD_END, START, analyze,
    span_rule,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-flag-gated-span-advance-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class SpanAdvanceTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(span_rule(True, 0, 0, 0x1000, 0x200, 0x1000, 0x100),
                         (0x100, False))
        self.assertEqual(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x100),
                         (0x300, True))
        self.assertEqual(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x200),
                         (0x200, False))
        self.assertEqual(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x300),
                         (0x300, False))
        self.assertEqual(span_rule(False, 0, 0, 0x1000, 0x200, 0x800, 0x100),
                         (0x100, False))
        self.assertEqual(
            span_rule(False, 0, 0, 0x1000, 0x200, (1 << 64) - 0x10, 0x20),
            (0x220, True))

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 71]), BODY)
        self.assertEqual(bytes(data[off + 71:off + 80]), b'\xcc' * 9)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2a9b80:eh + 0x2a9b80 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2a9b94:eh + 0x2a9b94 + len(NEXT)]), NEXT)

    def test_gate_prefix_unique(self):
        data = load()
        text_off = 0x1342c80
        text = bytes(data[text_off:text_off + 70370352])
        found = []
        pos = 0
        while True:
            pos = text.find(GATE_PREFIX, pos)
            if pos < 0:
                break
            found.append(0x1343c80 + pos)
            pos += 1
        self.assertEqual(found, [START])

    def test_incoming_scan_is_empty(self):
        data = load()
        text_off = 0x1342c80
        text = bytes(data[text_off:text_off + 70370352])
        found = []
        pos = 0
        while True:
            pos = text.find(b'\xe8', pos)
            if pos < 0:
                break
            rel = int.from_bytes(text[pos + 1:pos + 5], 'little', signed=True)
            if 0x1343c80 + pos + 5 + rel == START:
                found.append(pos)
            pos += 1
        self.assertEqual(found, [])

    def test_corruption_controls(self):
        data = load()
        good = analyze(bytes(data))
        self.assertEqual(good['direct_callers'], [])
        # Flip one body byte: the check must fail.
        bad = bytearray(data)
        bad[START - 0x1000 + 0x38] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(bad))
        # Flip one padding byte: the check must fail.
        bad = bytearray(data)
        bad[END - 0x1000] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(bad))

    def test_check_passes(self):
        result = analyze(TARGET.read_bytes())
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['relocation_slots'], [])
        self.assertEqual(result['gate_prefix_hits'], [hex(START)])


if __name__ == '__main__':
    unittest.main()
