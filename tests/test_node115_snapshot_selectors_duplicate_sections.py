"""Synthetic-ELF tests for node115_snapshot_selectors_rust duplicate sections.

Image.__init__ built its section dict with a comprehension, so a second
section of the same name silently overwrote the first and .text resolved
to the wrong bytes, while the decimal_scaled_u64 Image whose methods this
class borrows refuses duplicate names. The builder mirrors the
missing-section tests' layout.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_snapshot_selectors_rust as snap  # noqa: E402


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


BASE = [
    (b'.text', 1, 6, 0x1000, b'\x90' * 16),
    (b'.rodata', 1, 2, 0x2000, b'\x00' * 16),
    (b'.eh_frame_hdr', 1, 2, 0x3000,
     bytes([1, 0x1B, 0x03, 0x3B]) + b'\x00' * 4 + struct.pack('<I', 0)),
    (b'.rela.dyn', 4, 3, 0x4000, b''),
]


class SnapshotSelectorsDuplicateTests(unittest.TestCase):
    def test_single_text_constructs(self):
        image = snap.Image(build(BASE))
        self.assertEqual(image.text_va, 0x1000)

    def test_duplicate_text_refuses(self):
        dup = BASE + [(b'.text', 1, 6, 0x5000, b'\xcc' * 16)]
        with self.assertRaisesRegex(ValueError, 'Duplicate section: .text'):
            snap.Image(build(dup))

    def test_duplicate_nobits_text_is_not_a_duplicate(self):
        # SHT_NOBITS sections have no file bytes and never resolve an
        # address, so a NOBITS row sharing the name must not refuse.
        nobits = BASE + [(b'.text', 8, 6, 0x5000, b'')]
        image = snap.Image(build(nobits))
        self.assertEqual(image.text_va, 0x1000)


if __name__ == '__main__':
    unittest.main()
