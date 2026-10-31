"""Unit tests for the node #94 byte-swapped reversed 4-qword copy packet.

All expectations are hand-computed from the retained instruction bytes.
No test executes the captured binary; corruption checks run in memory.
"""

import hashlib
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from foundation_bswap_reverse_copy import (  # noqa: E402
    BODY, CALLERS, CIE0, END, FDE, NEXT, PAD_END, START,
    bswap_reverse_copy, analyze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-bswap-reverse-copy-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class BswapReverseCopyTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(bswap_reverse_copy([0, 0, 0, 0]), [0, 0, 0, 0])
        self.assertEqual(bswap_reverse_copy([1, 2, 3, 4]),
                         [0x0400000000000000, 0x0300000000000000,
                          0x0200000000000000, 0x0100000000000000])
        self.assertEqual(bswap_reverse_copy([0x00000000000000ff, 0, 0, 0]),
                         [0, 0, 0, 0xff00000000000000])
        self.assertEqual(bswap_reverse_copy([0x0102030405060708,
                                             0x1112131415161718,
                                             0x2122232425262728,
                                             0x3132333435363738]),
                         [0x3837363534333231, 0x2827262524232221,
                          0x1817161514131211, 0x0807060504030201])

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 43]), BODY)
        self.assertEqual(bytes(data[off + 43:off + 48]), b'\xcc' * 5)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2d81c8:eh + 0x2d81c8 + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2d81dc:eh + 0x2d81dc + len(NEXT)]), NEXT)

    def test_no_relocation_slot(self):
        data = load()
        found = []
        for sec_off, sec_size in [(0x6bc0, 0x1d4e10), (0x1db9d0, 0x1a10)]:
            for i in range(0, sec_size, 24):
                address = int.from_bytes(data[sec_off + i:sec_off + i + 8], 'little')
                addend = int.from_bytes(data[sec_off + i + 16:sec_off + i + 24],
                                        'little', signed=True)
                if addend == START:
                    found.append(address)
        self.assertEqual(found, [])

    def test_incoming_scan_finds_two_callers(self):
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
                found.append(0x1343c80 + pos)
            pos += 1
        self.assertEqual(found, CALLERS)

    def test_corruption_controls(self):
        data = load()
        good = analyze(bytes(data))
        self.assertEqual(good['direct_callers'], CALLERS)
        # Flip one body byte: the check must fail.
        bad = bytearray(data)
        bad[START - 0x1000 + 0x04] ^= 0x01
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


if __name__ == '__main__':
    unittest.main()
