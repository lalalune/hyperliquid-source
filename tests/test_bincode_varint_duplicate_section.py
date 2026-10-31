"""Synthetic controls for duplicate section names in bincode_varint.sections()."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

NAMES = b'\0.shstrtab\0.text\0.eh_frame\0.eh_frame_hdr\0.rela.dyn\0.data.rel.ro\0.rodata\0.comment\0'


def build(extra_rows=()):
    """Minimal ELF whose section table passes sections()'s own checks."""
    blobs = {'.shstrtab': NAMES, '.text': b'\x90' * 16, '.eh_frame': b'\0' * 16,
             '.eh_frame_hdr': b'\0' * 16, '.rela.dyn': b'\0' * 24,
             '.data.rel.ro': b'\0' * 8, '.rodata': b'\0' * 8, '.comment': b'v1\0'}
    order = ['.shstrtab', '.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn',
             '.data.rel.ro', '.rodata', '.comment']
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    offsets = {}
    for name in order:
        offsets[name] = len(body)
        body += blobs[name]
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name in order:
        typ = 3 if name == '.shstrtab' else 1
        rows.append((NAMES.index(name.encode() + b'\0'), typ, 0, 0,
                     offsets[name], len(blobs[name]), 0, 0, 1, 0))
    for name, blob in extra_rows:
        off = len(body)
        body += blob
        rows.append((NAMES.index(name.encode() + b'\0'), 1, 0, 0,
                     off, len(blob), 0, 0, 1, 0))
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body), offsets


class DuplicateSectionTests(unittest.TestCase):
    def test_duplicate_required_section_name_raises(self):
        data, _ = build(extra_rows=[('.text', b'\xcc' * 16)])
        with self.assertRaisesRegex(bv.EvidenceError, 'Duplicate section: .text'):
            bv.sections(data)

    def test_duplicate_other_section_name_raises(self):
        data, _ = build(extra_rows=[('.comment', b'v2\0')])
        with self.assertRaisesRegex(bv.EvidenceError, 'Duplicate section: .comment'):
            bv.sections(data)

    def test_unique_section_names_parse(self):
        data, offsets = build()
        secs = bv.sections(data)
        self.assertEqual(secs['.text']['offset'], offsets['.text'])
        self.assertEqual(secs['.text']['size'], 16)


if __name__ == '__main__':
    unittest.main()
