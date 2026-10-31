"""GNU property identity follows note headers, not the section-name spelling."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import derive


def note(owner=b'GNU\0', kind=5, descriptor=bytes.fromhex('028000c0040000000100000000000000'), alignment=8):
    raw = bytearray(struct.pack('<III', len(owner), len(descriptor), kind) + owner)
    raw += b'\0' * (-len(raw) % alignment)
    raw += descriptor
    return bytes(raw)


def elf(name, payload, kind=7, alignment=8):
    names = b'\0.shstrtab\0' + name + b'\0'
    body = bytearray(64)
    body[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', body, 16, 1, 0x3e)
    struct.pack_into('<I', body, 20, 1)
    struct.pack_into('<H', body, 52, 64)
    names_offset = len(body)
    body += names
    body += b'\0' * (-len(body) % alignment)
    offset = len(body)
    body += payload
    body += b'\0' * (-len(body) % 8)
    struct.pack_into('<Q', body, 40, len(body))
    struct.pack_into('<HHH', body, 58, 64, 3, 1)
    body += bytes(64)
    body += struct.pack('<IIQQQQIIQQ', names.index(b'.shstrtab'), 3, 0, 0,
                        names_offset, len(names), 0, 0, 1, 0)
    body += struct.pack('<IIQQQQIIQQ', names.index(name), kind, 0, 0,
                        offset, len(payload), 0, 0, alignment, 0)
    return bytes(body)


def present(data):
    return next(f['value'] for f in derive(data) if f['key'] == 'elf.has_gnu_property_note')


class GNUPropertyNoteTests(unittest.TestCase):
    def test_property_survives_a_section_rename(self):
        for name in (b'.note.gnu.property', b'.note.provenance-control'):
            with self.subTest(name=name):
                self.assertIs(present(elf(name, note())), True)

    def test_name_alone_does_not_establish_the_note_identity(self):
        for payload, kind in ((note(), 1), (note(owner=b'BAD\0'), 7),
                              (note(kind=1), 7)):
            with self.subTest(payload=payload.hex(), section_type=kind):
                self.assertIs(present(elf(b'.note.gnu.property', payload, kind)), False)

    def test_later_property_follows_an_eight_byte_aligned_note(self):
        first = note(kind=3, descriptor=b'X' * 20)
        self.assertEqual(len(first), 36)
        payload = first + b'\0' * (-len(first) % 8) + note()
        self.assertIs(present(elf(b'.note.combined', payload)), True)

    def test_truncated_note_payload_is_not_presence_evidence(self):
        with self.assertRaisesRegex(ValueError, 'Note payload outside section'):
            present(elf(b'.note.provenance-control', note()[:-1]))


if __name__ == '__main__':
    unittest.main()
