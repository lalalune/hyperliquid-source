"""Controls for the duplicate-slot guard in tools/spot_wei_scale.py."""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'spot_wei_scale.py'

spec = importlib.util.spec_from_file_location('spot_wei_scale_relocs', TOOL)
sws = importlib.util.module_from_spec(spec)
sys.modules['spot_wei_scale_relocs'] = sws
spec.loader.exec_module(sws)


def build(entries):
    names = b'\0.shstrtab\0.rela.dyn\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    names_off = len(body)
    body += names
    rela_off = len(body)
    body += b''.join(struct.pack('<QQq', *e) for e in entries)
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 3, 1)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (names.index(b'.shstrtab\0'), 3, 0, 0, names_off, len(names), 0, 0, 0, 0),
            (names.index(b'.rela.dyn\0'), 1, 0, 0, rela_off, 24 * len(entries), 0, 0, 0, 0)]
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


class RelativeRelocsDuplicateTests(unittest.TestCase):
    def test_duplicate_slot_rejected(self):
        data = build([(0x5000, 8, 0x1111), (0x5000, 8, 0x2222)])
        with self.assertRaises(sws.EvidenceError):
            sws.Image(data).relative_relocs()

    def test_duplicate_slot_rejected_reversed(self):
        data = build([(0x5000, 8, 0x2222), (0x5000, 8, 0x1111)])
        with self.assertRaises(sws.EvidenceError):
            sws.Image(data).relative_relocs()

    def test_duplicate_slot_identical_addend_rejected(self):
        data = build([(0x5000, 8, 0x1111), (0x5000, 8, 0x1111)])
        with self.assertRaises(sws.EvidenceError):
            sws.Image(data).relative_relocs()

    def test_distinct_slots_still_parse(self):
        data = build([(0x5000, 8, 0x1111), (0x5008, 8, 0x2222), (0x5010, 0, 0x3333)])
        self.assertEqual(sws.Image(data).relative_relocs(), {0x5000: 0x1111, 0x5008: 0x2222})


if __name__ == '__main__':
    unittest.main()
