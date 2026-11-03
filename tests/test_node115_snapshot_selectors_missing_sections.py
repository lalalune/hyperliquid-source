"""Synthetic-ELF tests for node115_snapshot_selectors_rust missing sections.

Image.__init__ read .text and .rodata by raw dict indexing, so an
otherwise well-formed ELF that simply lacks one of them escaped as a
bare KeyError instead of the module's ValueError. The builder mirrors
the decimal_scaled_u64 missing-section tests' layout.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_snapshot_selectors_rust as snap  # noqa: E402

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
                     2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count,
                     count - 1)
    return bytes(blob)


def without(name):
    return build([s for s in ALL if s[0] != name])


class SnapshotSelectorsMissingSectionTests(unittest.TestCase):
    def test_valid_image_constructs(self):
        img = snap.Image(build(ALL))
        self.assertEqual(sorted(img.sections),
                         ['', '.eh_frame_hdr', '.rela.dyn', '.rodata',
                          '.shstrtab', '.text'])

    def test_missing_text_fails_closed(self):
        with self.assertRaisesRegex(ValueError,
                                    'missing required section .text'):
            snap.Image(without(b'.text'))

    def test_missing_rodata_fails_closed(self):
        with self.assertRaisesRegex(ValueError,
                                    'missing required section .rodata'):
            snap.Image(without(b'.rodata'))


if __name__ == '__main__':
    unittest.main()
