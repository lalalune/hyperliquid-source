"""Controls for the duplicate-slot guard in tools/wei_buffered_cap.py."""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'wei_buffered_cap.py'

spec = importlib.util.spec_from_file_location('wei_buffered_cap', TOOL)
wbc = importlib.util.module_from_spec(spec)
sys.modules['wei_buffered_cap'] = wbc
spec.loader.exec_module(wbc)


def build(entries):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00'
    hdr = bytearray(64)
    hdr[0:6] = b'\x7fELF\x02\x01'
    shoff = 64 + len(shstr)
    struct.pack_into('<Q', hdr, 0x28, shoff)
    struct.pack_into('<HHH', hdr, 0x3a, 64, 3, 2)

    def sh(name, off, size):
        return struct.pack('<IIQQQQIIQQ', name, 1, 0, 0, off, size, 0, 0, 1, 0)

    rela = b''.join(struct.pack('<QQq', *e) for e in entries)
    secs = sh(0, 0, 0) + sh(1, shoff + 3 * 64, len(rela)) + sh(11, 64, len(shstr))
    return bytes(hdr) + shstr + secs + rela


class RelativeRelocsDuplicateTests(unittest.TestCase):
    def test_duplicate_slot_rejected(self):
        data = build([(0x5000, 8, 0x1111), (0x5000, 8, 0x2222)])
        with self.assertRaises(wbc.EvidenceError):
            wbc.Image(data).relative_relocs()

    def test_duplicate_slot_rejected_reversed(self):
        data = build([(0x5000, 8, 0x2222), (0x5000, 8, 0x1111)])
        with self.assertRaises(wbc.EvidenceError):
            wbc.Image(data).relative_relocs()

    def test_duplicate_slot_identical_addend_rejected(self):
        data = build([(0x5000, 8, 0x1111), (0x5000, 8, 0x1111)])
        with self.assertRaises(wbc.EvidenceError):
            wbc.Image(data).relative_relocs()

    def test_distinct_slots_still_parse(self):
        data = build([(0x5000, 8, 0x1111), (0x5008, 8, 0x2222), (0x5010, 0, 0x3333)])
        self.assertEqual(wbc.Image(data).relative_relocs(), {0x5000: 0x1111, 0x5008: 0x2222})


if __name__ == '__main__':
    unittest.main()
