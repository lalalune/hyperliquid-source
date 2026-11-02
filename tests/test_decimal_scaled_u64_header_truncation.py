"""Synthetic-ELF tests for the decimal_scaled_u64 header/section-table reads.

Image.__init__ checks the ELF magic through fail() but then read the ELF
header fields and the section header rows with raw struct.unpack_from, so
a truncated header or an overdeclared section table escaped as
struct.error (and an out-of-range name-table index as IndexError)
instead of the module's ToolError. elf_index.sections() -- the shared
parser -- guards exactly these reads before unpacking. The valid-image
builder mirrors tools/decimal_scaled_u64.py::Image like the section-name
encoding tests do.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as dec  # noqa: E402


def header(shoff, entsize, count, strndx, total):
    """A bare ELF header of `total` bytes with the given table fields."""
    blob = bytearray(total)
    blob[0:16] = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HHIQQQIHHHHHH', blob, 16,
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, entsize, count, strndx)
    return bytes(blob)


def build():
    specs = [
        (b'.text', 1, 6, 0x1000, b'\x90' * 16),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16),
        (b'.eh_frame_hdr', 1, 2, 0x3000,
         bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', 0)),
        (b'.rela.dyn', 4, 3, 0x4000, b''),
    ]
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


class DecimalHeaderTruncationTests(unittest.TestCase):
    def test_tiny_input_fails_closed(self):
        # Passes the 5-byte magic check, then must fail as ToolError,
        # not struct.error, on the header field reads.
        with self.assertRaisesRegex(dec.ToolError, 'truncated ELF header'):
            dec.Image(b'\x7fELF\x02' + b'\x00' * 5)

    def test_partial_header_fails_closed(self):
        with self.assertRaisesRegex(dec.ToolError, 'truncated ELF header'):
            dec.Image(b'\x7fELF\x02\x01' + b'\x00' * 44)

    def test_overdeclared_section_table_fails_closed(self):
        # Three rows declared, room for one: the row reads must fail as
        # ToolError, not struct.error.
        with self.assertRaisesRegex(dec.ToolError, 'invalid section table'):
            dec.Image(header(64, 64, 3, 2, 128))

    def test_name_table_index_out_of_range_fails_closed(self):
        # strndx == count indexed rows[strndx] on base (IndexError).
        with self.assertRaisesRegex(dec.ToolError, 'invalid section table'):
            dec.Image(header(64, 64, 1, 1, 128))

    def test_undersized_entry_size_fails_closed(self):
        # count * entsize fits the file, but the last 64-byte row read
        # overruns it: only the entsize guard closes this escape.
        with self.assertRaisesRegex(dec.ToolError, 'invalid section table'):
            dec.Image(header(64, 32, 3, 2, 164))

    def test_valid_image_unchanged(self):
        img = dec.Image(build())
        self.assertEqual(img.text_va, 0x1000)
        self.assertIn('.rodata', img.sections)


if __name__ == '__main__':
    unittest.main()
