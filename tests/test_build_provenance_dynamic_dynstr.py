"""A .dynamic section without its .dynstr must fail as ValueError, not KeyError."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import derive


def elf(sections):
    """Minimal ELF64-LE image from (name, type, bytes, link, entsize) rows.

    Builder idiom follows tests/test_build_provenance.py dynamic_elf();
    the section set is the variable under test here.
    """
    names = b'\0.shstrtab\0' + b''.join(name + b'\0' for name, *_ in sections)
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    body += b'\0' * (-len(body) % 8)
    rows.append((1, 3, 0, 0, len(body), len(names), 0, 0, 8, 0))
    body += names
    for name, kind, data, link, entsize in sections:
        body += b'\0' * (-len(body) % 8)
        rows.append((names.index(name + b'\0'), kind, 0, 0, len(body), len(data), link, 0, 8, entsize))
        body += data
    body += b'\0' * (-len(body) % 8)
    struct.pack_into('<Q', body, 40, len(body))
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


TAGS = struct.pack('<qQ', 1, 1) + struct.pack('<qQ', 0, 0)  # DT_NEEDED 1, DT_NULL
DYNSTR = (b'.dynstr', 3, b'\0libfixture.so\0', 0, 0)
DYNAMIC = (b'.dynamic', 6, TAGS, 2, 16)


class DynamicWithoutDynstrTests(unittest.TestCase):
    def test_dynamic_without_dynstr_is_a_value_error(self):
        # derive() raises ValueError diagnostics for every other malformed
        # section shape (NOBITS .dynstr, unterminated .dynamic, bad string
        # offsets); a missing .dynstr escaped as a raw KeyError instead.
        with self.assertRaises(ValueError) as ctx:
            derive(elf([DYNAMIC]))
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), '.dynamic section without a .dynstr section')

    def test_dynamic_with_dynstr_still_derives(self):
        facts = {i['key']: i['value'] for i in derive(elf([DYNSTR, DYNAMIC]))}
        self.assertEqual(facts['dynamic.needed'], ['libfixture.so'])

    def test_dynstr_without_dynamic_is_not_an_error(self):
        facts = {i['key']: i['value'] for i in derive(elf([DYNSTR]))}
        self.assertNotIn('dynamic.needed', facts)

    def test_nobits_dynstr_still_rejected(self):
        nobits = (b'.dynstr', 8, b'', 0, 0)
        with self.assertRaisesRegex(ValueError, 'NOBITS section: .dynstr'):
            derive(elf([nobits, DYNAMIC]))


if __name__ == '__main__':
    unittest.main()
