"""Synthetic-ELF tests for the decimal_scaled_u64 .eh_frame_hdr table reads.

Image._fdes bounds-checks the table encoding through fail() but then read
the section through the raw row offset: the data[off + 3] encoding index,
the count unpack and the per-entry unpacks all trusted the section row, so
a row lying about its offset or size -- or a table that overruns the
declared section size -- escaped as IndexError / struct.error instead of
the module's ToolError, or was read silently out of section.
elf_index.unwind_index() -- the shared parser -- guards exactly these
reads: the section must lie inside the file, hold at least the 12-byte
header, and hold 12 + count * 8 table bytes. The builder mirrors
tools/decimal_scaled_u64.py::Image like the header-truncation tests do.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as dec  # noqa: E402

TEXT = 0x1000
EH = 0x3000


def eh_header(count):
    return bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', count)


def fde_stub(size):
    # 8 skipped bytes, then the (begin, size) pair _fdes reads at
    # fde_off + 8; begin == -8 when the FDE starts its own function.
    return b'\x00' * 8 + struct.pack('<iI', -8, size)


def build(specs, tail=b''):
    """specs: (name, type, flags, addr, payload, size_override, off_override).

    Payloads are laid out in order after the ELF header, then the section
    name table, then the section header rows, then `tail` verbatim.
    Overrides change only the row fields, never the layout.
    """
    shstr = b'\x00'
    name_off = {}
    for name, *_ in specs + [(b'.shstrtab', 3, 0, 0, b'', None, None)]:
        if name not in name_off:
            name_off[name] = len(shstr)
            shstr += name + b'\x00'
    blob = bytearray(b'\x00' * 64)
    laid = []
    for name, typ, flags, addr, payload, size_ov, off_ov in specs:
        off = len(blob)
        blob += payload
        laid.append([name_off[name], typ, flags, addr,
                     off if off_ov is None else off_ov,
                     len(payload) if size_ov is None else size_ov])
    shstr_off = len(blob)
    blob += shstr
    laid.append([name_off[b'.shstrtab'], 3, 0, 0, shstr_off, len(shstr)])
    shoff = len(blob)
    count = 1 + len(laid)
    blob += b'\x00' * 64
    for row in laid:
        blob += struct.pack('<IIQQQQIIQQ', *row, 0, 0, 1, 0)
    blob += tail
    blob[0:16] = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    struct.pack_into('<HHIQQQIHHHHHH', blob, 16,
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, count - 1)
    return bytes(blob)


def base_specs(eh_payload, eh_size=None, eh_off=None, text=b'\x90' * 16):
    return [
        (b'.text', 1, 6, TEXT, text, None, None),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16, None, None),
        (b'.eh_frame_hdr', 1, 2, EH, eh_payload, eh_size, eh_off),
        (b'.rela.dyn', 4, 3, 0x4000, b'', None, None),
    ]


class DecimalFdesTruncationTests(unittest.TestCase):
    def test_table_entry_at_end_of_file_fails_closed(self):
        # The 12-byte header sits at EOF declaring one entry; the entry
        # unpack ran off the buffer on base (struct.error).
        specs = base_specs(b'', eh_size=12)
        total = len(build(specs, tail=eh_header(1)))
        specs[2] = (b'.eh_frame_hdr', 1, 2, EH, b'', 12, total - 12)
        img = build(specs, tail=eh_header(1))
        with self.assertRaisesRegex(dec.ToolError,
                                    r'truncated \.eh_frame_hdr table'):
            dec.Image(img)

    def test_section_offset_beyond_end_of_file_fails_closed(self):
        # The row offset points at the last 2 bytes; the encoding index
        # data[off + 3] raised IndexError on base.
        specs = base_specs(eh_header(0))
        total = len(build(specs, tail=b'\x00' * 16))
        specs[2] = (b'.eh_frame_hdr', 1, 2, EH, eh_header(0), None, total - 2)
        img = build(specs, tail=b'\x00' * 16)
        with self.assertRaisesRegex(dec.ToolError,
                                    r'invalid \.eh_frame_hdr section'):
            dec.Image(img)

    def test_count_read_at_end_of_file_fails_closed(self):
        # The row offset sits at the last 8 bytes with a claimed size of
        # 12; the count unpack at off + 8 ran off the buffer on base.
        specs = base_specs(b'', eh_size=12)
        total = len(build(specs, tail=eh_header(0)[:8]))
        specs[2] = (b'.eh_frame_hdr', 1, 2, EH, b'', 12, total - 8)
        img = build(specs, tail=eh_header(0)[:8])
        with self.assertRaisesRegex(dec.ToolError,
                                    r'invalid \.eh_frame_hdr section'):
            dec.Image(img)

    def test_table_overrunning_section_size_fails_closed(self):
        # Declared size 12 with count 1, but a valid entry sits right
        # after the section in the file: base read it out of section and
        # accepted the table.
        entry = struct.pack('<ii', 0x1000 - EH, 0x1000 - EH)
        img = build(base_specs(eh_header(1) + entry, eh_size=12,
                               text=fde_stub(0x10)))
        with self.assertRaisesRegex(dec.ToolError,
                                    r'truncated \.eh_frame_hdr table'):
            dec.Image(img)

    def test_undersized_section_fails_closed(self):
        # Declared size 8, below the 12-byte header, at EOF: off + size
        # is in file, but the count field lies outside the section and
        # its unpack ran off the buffer on base.
        specs = base_specs(b'', eh_size=8)
        total = len(build(specs, tail=eh_header(0)[:8]))
        specs[2] = (b'.eh_frame_hdr', 1, 2, EH, b'', 8, total - 8)
        img = build(specs, tail=eh_header(0)[:8])
        with self.assertRaisesRegex(dec.ToolError, r'truncated \.eh_frame_hdr$'):
            dec.Image(img)

    def test_valid_image_fdes_unchanged(self):
        text = fde_stub(0x10) + fde_stub(0x20)
        entries = struct.pack('<ii', 0x1010 - EH, 0x1010 - EH) \
            + struct.pack('<ii', 0x1000 - EH, 0x1000 - EH)
        img = dec.Image(build(base_specs(eh_header(2) + entries, text=text)))
        self.assertEqual(img.fdes, [(0x1000, 0x1010), (0x1010, 0x1030)])

    def test_empty_table_unchanged(self):
        img = dec.Image(build(base_specs(eh_header(0))))
        self.assertEqual(img.fdes, [])


if __name__ == '__main__':
    unittest.main()
