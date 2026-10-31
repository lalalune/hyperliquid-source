"""Unit tests for the node #94 cursor retreat-or-wrap packet.

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

from foundation_cursor_retreat_or_wrap import (  # noqa: E402
    BODY, CIE0, END, FDE, NEXT, PAD_END, START, analyze, retreat_or_wrap,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-cursor-retreat-or-wrap-94'
            / 'evidence.json')


def load():
    return bytearray(TARGET.read_bytes())


class RetreatOrWrapTests(unittest.TestCase):
    def test_body_hash_matches_retained(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(hashlib.sha256(BODY).hexdigest(),
                         retained['function']['sha256'])

    def test_rule_edges(self):
        self.assertEqual(retreat_or_wrap(100, 100, 200), 200)
        self.assertEqual(retreat_or_wrap(108, 100, 200), 100)
        self.assertEqual(retreat_or_wrap(0, 100, 200), (1 << 64) - 8)
        self.assertEqual(retreat_or_wrap(8, 0, 16), 0)
        self.assertEqual(retreat_or_wrap(16, 16, 16), 16)

    def test_window_bytes_and_padding(self):
        data = load()
        off = START - 0x1000
        self.assertEqual(bytes(data[off:off + 41]), BODY)
        self.assertEqual(bytes(data[off + 41:off + 48]), b'\xcc' * 7)
        self.assertEqual(bytes(data[off - 5:off]), b'\xcc' * 5)

    def test_fde_records(self):
        data = load()
        eh = 0xce1518
        self.assertEqual(bytes(data[eh:eh + len(CIE0)]), CIE0)
        self.assertEqual(bytes(data[eh + 0x2abcac:eh + 0x2abcac + len(FDE)]), FDE)
        self.assertEqual(bytes(data[eh + 0x2abcc0:eh + 0x2abcc0 + len(NEXT)]), NEXT)

    def test_relocation_slot(self):
        data = load()
        found = []
        for sec_off, sec_size in [(0x6bc0, 0x1d4e10), (0x1db9d0, 0x1a10)]:
            for i in range(0, sec_size, 24):
                address, info, addend = struct.unpack_from(
                    '<QQq', bytes(data[sec_off + i:sec_off + i + 24]))
                if addend == START:
                    found.append(hex(address))
        self.assertEqual(found, ['0x57615c8'])

    def test_je_target(self):
        # je at offset 0x0f, rel8 0x0f, lands on the wrap path 0x52c6ec0.
        self.assertEqual(BODY[0x0f:0x11], bytes.fromhex('740f'))
        self.assertEqual(START + 0x0f + 2 + BODY[0x10], 0x52c6ec0)

    def test_no_call_inside(self):
        starts = {0x00, 0x04, 0x08, 0x0c, 0x0f, 0x11, 0x15, 0x19,
                  0x1a, 0x20, 0x24, 0x28}
        for pos in starts:
            self.assertNotEqual(BODY[pos], 0xe8)

    def test_corruption_controls(self):
        data = load()
        mutated = bytearray(data)
        mutated[START - 0x1000 + 0x11] ^= 0x01  # sub $0x8 -> sub $0x9
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))
        mutated = bytearray(data)
        mutated[END - 0x1000] ^= 0x01  # padding byte
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))
        mutated = bytearray(data)
        mutated[0xce1518 + 0x2abcac] ^= 0x01  # FDE record byte
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
