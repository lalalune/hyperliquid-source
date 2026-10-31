"""Controls for the truncated .rela.dyn guard in tools/evm_amount_scale.py."""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'evm_amount_scale.py'

spec = importlib.util.spec_from_file_location('evm_amount_scale', TOOL)
eas = importlib.util.module_from_spec(spec)
sys.modules['evm_amount_scale'] = eas
spec.loader.exec_module(eas)


def build(claimed_size, actual_bytes):
    names = b'\0.shstrtab\0.rela.dyn\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    names_off = len(body)
    body += names
    rela_off = len(body)
    body += actual_bytes
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 3, 1)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (names.index(b'.shstrtab\0'), 3, 0, 0, names_off, len(names), 0, 0, 0, 0),
            (names.index(b'.rela.dyn\0'), 1, 0, 0, rela_off, claimed_size, 0, 0, 0, 0)]
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


class RelativeRelocsTruncatedTests(unittest.TestCase):
    def test_ragged_tail_rejected(self):
        data = build(25, struct.pack('<QQq', 0x1000, 8, 0x2000) + b'\0')
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).relative_relocs()

    def test_section_past_eof_rejected(self):
        data = build(240, b'\0' * 24)
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).relative_relocs()

    def test_valid_section_still_parses(self):
        entries = struct.pack('<QQq', 0x1000, 8, 0x2000) + struct.pack('<QQq', 0x1008, 0, 0)
        data = build(48, entries)
        self.assertEqual(eas.Image(data).relative_relocs(), {0x1000: 0x2000})


if __name__ == '__main__':
    unittest.main()
