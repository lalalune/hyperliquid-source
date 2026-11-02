"""Synthetic-ELF tests for the decimal_scaled_u64 FDE extent read.

Image._fdes resolves each search-table entry through file_offset(),
which checks the FDE pointer against the section rows -- but a row can
claim bytes past the end of the file, so the (begin, size) unpack at
fde_off + 8 ran off the buffer and escaped as struct.error instead of
the module's ToolError. The builder mirrors
tools/decimal_scaled_u64.py::Image like the other decimal tests do.
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


def base_specs(eh_payload, text=b'\x90' * 16):
    return [
        (b'.text', 1, 6, TEXT, text, None, None),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16, None, None),
        (b'.eh_frame_hdr', 1, 2, EH, eh_payload, None, None),
        (b'.rela.dyn', 4, 3, 0x4000, b'', None, None),
    ]


def tail_text_image(fde_va, tail):
    """One entry whose FDE VA lands in a .text row pointing at the file's
    final len(tail) bytes, so the extent read's reach is exact."""
    entry = struct.pack('<ii', fde_va - EH, fde_va - EH)
    specs = [
        (b'.text', 1, 6, TEXT, b'', len(tail), None),
        (b'.rodata', 1, 2, 0x2000, b'\x00' * 16, None, None),
        (b'.eh_frame_hdr', 1, 2, EH, eh_header(1) + entry, None, None),
        (b'.rela.dyn', 4, 3, 0x4000, b'', None, None),
    ]
    total = len(build(specs, tail=tail))
    specs[0] = (b'.text', 1, 6, TEXT, b'', len(tail), total - len(tail))
    img = build(specs, tail=tail)
    assert len(img) == total
    return img


class DecimalFdeExtentTruncationTests(unittest.TestCase):
    def test_extent_read_at_end_of_file_fails_closed(self):
        # FDE VA maps 8 bytes into a 16-byte tail section, so the extent
        # read at fde_off + 8 starts exactly at EOF (struct.error on base).
        img = tail_text_image(0x1008, b'\x90' * 16)
        with self.assertRaisesRegex(dec.ToolError, r'truncated FDE'):
            dec.Image(img)

    def test_extent_read_partially_past_end_of_file_fails_closed(self):
        # Only 4 of the 8 extent bytes remain in the file.
        img = tail_text_image(0x1004, b'\x90' * 16)
        with self.assertRaisesRegex(dec.ToolError, r'truncated FDE'):
            dec.Image(img)

    def test_extent_read_exact_fit_unchanged(self):
        # The extent read's last byte is the file's last byte: the read
        # fits exactly and the row is returned as on base.
        img = dec.Image(tail_text_image(0x1000, fde_stub(0x10)))
        self.assertEqual(img.fdes, [(0x1000, 0x1010)])

    def test_fde_outside_sections_still_fails_closed(self):
        # file_offset() already rejected wild FDE pointers on base; the
        # extent guard must not change that path.
        entry = struct.pack('<ii', 0x9000 - EH, 0x9000 - EH)
        with self.assertRaisesRegex(dec.ToolError, r'outside every section'):
            dec.Image(build(base_specs(eh_header(1) + entry)))

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
