"""Synthetic-ELF tests for the decimal_scaled_u64 section name decode.

Builds a minimal ELF64-LE image with the sections Image.__init__ reads,
mirroring tools/decimal_scaled_u64.py::Image. A non-UTF-8 section name
must fail closed as the module's ToolError, the same contract the
constructor's duplicate-name guard beside the decode raises via fail().
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as dec  # noqa: E402


def build(extra_specs):
    specs = [
        (b'.text', 1, 6, 0x1000, b'\x90' * 16),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16),
        (b'.eh_frame_hdr', 1, 2, 0x3000,
         bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', 0)),
        (b'.rela.dyn', 4, 3, 0x4000, b''),
    ] + list(extra_specs)
    shstr = b'\x00'
    name_off = {}
    for name, *_ in specs + [(b'.shstrtab', 3, 0, 0, b'')]:
        if name not in name_off:
            name_off[name] = len(shstr)
            shstr += name + b'\x00'
    blob = bytearray(b'\x00' * 64)
    laid = []
    for name, typ, flags, addr, payload in specs:
        off = len(blob)
        blob += payload
        laid.append((name_off[name], typ, flags, addr, off, len(payload)))
    shstr_off = len(blob)
    blob += shstr
    laid.append((name_off[b'.shstrtab'], 3, 0, 0, shstr_off, len(shstr)))
    shoff = len(blob)
    count = 1 + len(laid)
    blob += b'\x00' * 64
    for row in laid:
        blob += struct.pack('<IIQQQQIIQQ', row[0], row[1], row[2], row[3],
                            row[4], row[5], 0, 0, 1, 0)
    blob[0:16] = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HHIQQQIHHHHHH', blob, 16,
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, count - 1)
    return bytes(blob)


class DecimalSectionNameEncodingTests(unittest.TestCase):
    def test_non_utf8_section_name_fails_closed(self):
        # On base the bare .decode() escapes as UnicodeDecodeError, which
        # is not a ToolError; with the fix it fails closed.
        with self.assertRaisesRegex(dec.ToolError,
                                    'section name is not valid UTF-8'):
            dec.Image(build([(b'\xfftext', 1, 6, 0x5000, b'\x90' * 8)]))

    def test_latin1_section_name_fails_closed(self):
        with self.assertRaisesRegex(dec.ToolError,
                                    'section name is not valid UTF-8'):
            dec.Image(build([(b'.tex\xe9t', 1, 6, 0x5000, b'\x90' * 8)]))

    def test_valid_section_names_unchanged(self):
        img = dec.Image(build([]))
        self.assertEqual(img.text_va, 0x1000)
        self.assertIn('.rodata', img.sections)


if __name__ == '__main__':
    unittest.main()
