"""Section rows extending past EOF and unterminated names must fail closed.

Image.__init__ accepted any section row whose bytes the file did not
contain: a later read into the phantom span escaped as IndexError, and
a section name with no NUL terminator escaped data.index as ValueError.
Both must refuse as the module's ToolError at construction, the same
guards the shared elf_index parser applies. The builders mirror the
section-name encoding tests' layout.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import decimal_scaled_u64 as dec


def build(span_override=None, shstrtab_last=False, drop_final_nul=False):
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
    if drop_final_nul:
        shstr = shstr[:-1]
    blob = bytearray(b'\x00' * 64)
    laid = []
    for name, typ, flags, addr, payload in specs:
        off = len(blob)
        blob += payload
        size = len(payload)
        if span_override and name == span_override[0]:
            size = span_override[1]
        laid.append((name_off[name], typ, flags, addr, off, size))
    if shstrtab_last:
        shoff = len(blob)
        count = 1 + len(laid) + 1
        shstr_off = shoff + 64 * count
        laid.append((name_off[b'.shstrtab'], 3, 0, 0, shstr_off, len(shstr)))
        blob += b'\x00' * 64
        for row in laid:
            blob += struct.pack('<IIQQQQIIQQ', row[0], row[1], row[2], row[3],
                                row[4], row[5], 0, 0, 1, 0)
        blob += shstr
    else:
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


class SectionSpanTests(unittest.TestCase):
    def test_section_past_end_of_file_refuses(self):
        with self.assertRaisesRegex(dec.ToolError, 'section extends past end of file'):
            dec.Image(build(span_override=(b'.rodata', 0x1000)))

    def test_unterminated_section_name_refuses(self):
        with self.assertRaisesRegex(dec.ToolError, 'unterminated section name'):
            dec.Image(build(shstrtab_last=True, drop_final_nul=True))

    def test_valid_image_constructs(self):
        image = dec.Image(build())
        self.assertEqual(image.text_va, 0x1000)
        self.assertEqual(image.read_only(0x2000), 0)


if __name__ == '__main__':
    unittest.main()
