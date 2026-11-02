"""Synthetic-ELF tests for the decimal_scaled_u64 .rela.dyn size guard.

Builds a minimal ELF64-LE image with the sections Image.__init__ reads,
mirroring tools/decimal_scaled_u64.py::Image, with the section header
table placed before the contents so .rela.dyn can end exactly at EOF.
A declared .rela.dyn size running past EOF is silently shortened by the
slice feeding iter_unpack, so Image attests a partial slot map; a size
that is not a multiple of the 24-byte RELA entry escapes as a bare
struct.error. Both must fail closed as the module's ToolError, the guard
evm_amount_scale already applies to the same table. Well-formed tables
keep their exact prior slot map.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as dec  # noqa: E402

ENTRY = struct.pack('<QQq', 0x5000, 8, 0x777)
SECOND = struct.pack('<QQq', 0x5800, 8, 0x888)


def build(rela_payload, declared_size):
    specs = [
        (b'.text', 1, 6, 0x1000, b'\x90' * 16),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16),
        (b'.eh_frame_hdr', 1, 2, 0x3000,
         bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', 0)),
        (b'.shstrtab', 3, 0, 0, None),
        (b'.rela.dyn', 4, 3, 0x4000, rela_payload),
    ]
    shstr = b'\x00'
    name_off = {}
    for name, *_ in specs:
        name_off[name] = len(shstr)
        shstr += name + b'\x00'
    specs[3] = (b'.shstrtab', 3, 0, 0, shstr)
    count = 1 + len(specs)
    shoff = 64
    blob = bytearray(b'\x00' * (64 + 64 * count))
    laid = []
    for name, typ, flags, addr, payload in specs:
        off = len(blob)
        blob += payload
        size = declared_size if name == b'.rela.dyn' else len(payload)
        laid.append((name_off[name], typ, flags, addr, off, size))
    for i, row in enumerate(laid):
        struct.pack_into('<IIQQQQIIQQ', blob, shoff + 64 * (i + 1),
                         row[0], row[1], row[2], row[3], row[4], row[5],
                         0, 0, 1, 0)
    blob[0:16] = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HHIQQQIHHHHHH', blob, 16,
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, 4)
    return bytes(blob)


class DecimalRelaTruncationTests(unittest.TestCase):
    def test_declared_size_past_eof_fails_closed(self):
        # Declares two entries; only one is present before EOF. On base
        # Image constructs silently with the one-entry slot map.
        with self.assertRaisesRegex(dec.ToolError, '.rela.dyn is truncated'):
            dec.Image(build(ENTRY, 48))

    def test_partial_entry_fails_closed(self):
        # On base this escapes as struct.error, which is not a ToolError.
        with self.assertRaisesRegex(dec.ToolError, '.rela.dyn is truncated'):
            dec.Image(build(ENTRY + b'\x00', 25))

    def test_wellformed_slots_unchanged(self):
        self.assertEqual(dec.Image(build(ENTRY, 24)).slots, {0x5000: 0x777})
        self.assertEqual(dec.Image(build(ENTRY + SECOND, 48)).slots,
                         {0x5000: 0x777, 0x5800: 0x888})


if __name__ == '__main__':
    unittest.main()
