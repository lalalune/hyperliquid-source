"""Unit tests for the node #94 bounded scaled cursor advance packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_bounded_scaled_cursor_advance import (  # noqa: E402
    BODY, CIE0, END, FDE, NEXT, PAD_END, SLOT, START, advance_rule, analyze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-bounded-scaled-cursor-advance-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class CursorAdvanceTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(advance_rule(0, 0, 0), (0, 0, 0))
        self.assertEqual(advance_rule(100, 0, 88), (1, 0x58, 99))
        self.assertEqual(advance_rule(10, 0, 40), (10, 0x370, 0))
        self.assertEqual(advance_rule(50, 16, 280), (3, 0x118, 47))
        self.assertEqual(advance_rule((1 << 64) - 1, 0, 8),
                         (0x2e8ba2e8ba2e8ba3, 8, 0xd1745d1745d1745c))

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 54]), BODY)
        self.assertEqual(bytes(data[off + 54:off + 64]), b'\xcc' * 10)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x27c87c:eh + 0x27c87c + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x27c890:eh + 0x27c890 + len(NEXT)]), NEXT)

    def test_relocation_slot(self):
        data = load()
        found = []
        for sec_off, sec_size in [(0x6bc0, 0x1d4e10), (0x1db9d0, 0x1a10)]:
            for i in range(0, sec_size, 24):
                address = int.from_bytes(data[sec_off + i:sec_off + i + 8], 'little')
                addend = int.from_bytes(data[sec_off + i + 16:sec_off + i + 24],
                                        'little', signed=True)
                if addend == START:
                    found.append(address)
        self.assertEqual(found, [SLOT])

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
        bad[START - 0x1000 + 0x23] ^= 0x01
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
        self.assertEqual(result['relocation_slots'], [['.rela.dyn', hex(SLOT)]])


if __name__ == '__main__':
    unittest.main()
