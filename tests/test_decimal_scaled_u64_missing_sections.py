"""Synthetic-ELF tests for decimal_scaled_u64 missing required sections.

Image.__init__ fails closed through fail()/ToolError on a duplicate
section name, a non-ELF64 magic and an out-of-section address, but the
four sections the parser unconditionally requires -- .text and .rodata
in __init__, .eh_frame_hdr in _fdes and .rela.dyn in _slots -- were read
by raw dict indexing, so an otherwise well-formed ELF that simply lacks
one of them escaped as a bare KeyError instead of the module's
ToolError. The valid-image builder mirrors the section-name encoding
tests' layout.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as dec  # noqa: E402

ALL = [
    (b'.text', 1, 6, 0x1000, b'\x90' * 16),
    (b'.rodata', 1, 2, 0x2000, b'\x00' * 16),
    (b'.eh_frame_hdr', 1, 2, 0x3000,
     bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', 0)),
    (b'.rela.dyn', 4, 3, 0x4000, b''),
]


def build(specs):
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


def without(name):
    return build([s for s in ALL if s[0] != name])


class MissingRequiredSectionTests(unittest.TestCase):
    def test_valid_image_constructs(self):
        img = dec.Image(build(ALL))
        self.assertEqual(sorted(img.sections),
                         ['', '.eh_frame_hdr', '.rela.dyn', '.rodata',
                          '.shstrtab', '.text'])

    def test_missing_text_fails_closed(self):
        with self.assertRaises(dec.ToolError) as cm:
            dec.Image(without(b'.text'))
        self.assertIn('.text', str(cm.exception))

    def test_missing_rodata_fails_closed(self):
        with self.assertRaises(dec.ToolError) as cm:
            dec.Image(without(b'.rodata'))
        self.assertIn('.rodata', str(cm.exception))

    def test_missing_eh_frame_hdr_fails_closed(self):
        with self.assertRaises(dec.ToolError) as cm:
            dec.Image(without(b'.eh_frame_hdr'))
        self.assertIn('.eh_frame_hdr', str(cm.exception))

    def test_missing_rela_dyn_fails_closed(self):
        with self.assertRaises(dec.ToolError) as cm:
            dec.Image(without(b'.rela.dyn'))
        self.assertIn('.rela.dyn', str(cm.exception))

    def test_borrowed_fdes_fails_closed(self):
        # node115_snapshot_selectors_rust.Image borrows _fdes/_slots as
        # unbound class attributes without inheriting from Image, so the
        # guard must not rely on state or methods of this class alone.
        class Borrowed:
            _fdes = dec.Image._fdes

        img = dec.Image(build(ALL))
        borrowed = Borrowed()
        borrowed.data = img.data
        borrowed.sections = {k: v for k, v in img.sections.items()
                             if k != '.eh_frame_hdr'}
        with self.assertRaises(dec.ToolError) as cm:
            borrowed._fdes()
        self.assertIn('.eh_frame_hdr', str(cm.exception))

    def test_borrowed_slots_fails_closed(self):
        class Borrowed:
            _slots = dec.Image._slots

        img = dec.Image(build(ALL))
        borrowed = Borrowed()
        borrowed.data = img.data
        borrowed.sections = {k: v for k, v in img.sections.items()
                             if k != '.rela.dyn'}
        with self.assertRaises(dec.ToolError) as cm:
            borrowed._slots()
        self.assertIn('.rela.dyn', str(cm.exception))


if __name__ == '__main__':
    unittest.main()
