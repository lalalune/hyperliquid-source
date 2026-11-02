import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import derive


def elf(comment, rodata):
    """Minimal ELF64-LE image with .shstrtab, .comment and .rodata.

    Mirrors the builder in tests/test_build_provenance_comment_encoding.py.
    """
    names = b'\0.shstrtab\0.comment\0.rodata\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    blobs = [names, comment, rodata]
    offsets = []
    for blob in blobs:
        offsets.append(len(body))
        body += blob
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 4, 1)
    rows = [(0, 0, 0, 0, 0, 0)]
    for name, blob, off in zip((b'.shstrtab', b'.comment', b'.rodata'), blobs, offsets):
        rows.append((names.index(name + b'\0'), 3 if name == b'.shstrtab' else 1, 0, 0, off, len(blob)))
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row, 0, 0, 1, 0)
    return bytes(body)


class GroupedEncodingTests(unittest.TestCase):
    def test_non_utf8_registry_index_rejected(self):
        # derive() raises ValueError diagnostics for malformed input (bad
        # section tables, non-UTF-8 .comment/.interp/.dynstr strings); a
        # non-UTF-8 cargo registry index directory captured by grouped()'s
        # [^/\0] pattern must fail the same way, not escape as a raw codec
        # error. UnicodeDecodeError is a ValueError subclass, so the type
        # check is what separates the defect from the fix.
        with self.assertRaises(ValueError) as ctx:
            derive(elf(b'', b'.cargo/registry/src/\xff\xfe/'))
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), 'Invalid encoding in matched binary string')

    def test_latin1_registry_index_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            derive(elf(b'', b'.cargo/registry/src/index\xe9/'))
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), 'Invalid encoding in matched binary string')

    def test_valid_registry_index_accepted(self):
        items = derive(elf(b'', b'.cargo/registry/src/github.com-1ecc6299db9ec823/'))
        index = [i['value'] for i in items if i['key'] == 'cargo.registry_index_dir']
        self.assertEqual(index, ['github.com-1ecc6299db9ec823'])


if __name__ == '__main__':
    unittest.main()
