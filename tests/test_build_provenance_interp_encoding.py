import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import derive


def elf(interp):
    """Minimal ELF64-LE image with .shstrtab and .interp.

    Mirrors the builder in tests/test_build_provenance.py on base,
    with the .comment section replaced by .interp.
    """
    names = b'\0.shstrtab\0.interp\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    blobs = [names, interp]
    offsets = []
    for blob in blobs:
        offsets.append(len(body))
        body += blob
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 3, 1)
    rows = [(0, 0, 0, 0, 0, 0)]
    for name, blob, off in zip((b'.shstrtab', b'.interp'), blobs, offsets):
        rows.append((names.index(name + b'\0'), 3 if name == b'.shstrtab' else 1, 0, 0, off, len(blob)))
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row, 0, 0, 1, 0)
    return bytes(body)


class InterpEncodingTests(unittest.TestCase):
    def test_non_utf8_interp_rejected(self):
        # derive() raises ValueError diagnostics for malformed input
        # (non-ELF input, bad section tables); a non-UTF-8 .interp
        # string must fail the same way, not escape as a raw codec
        # error. UnicodeDecodeError is a ValueError subclass, so the
        # type check is what separates the defect from the fix.
        with self.assertRaises(ValueError) as ctx:
            derive(elf(b'/lib64/ld-linux\xff.so\0'))
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), 'Invalid interp encoding')

    def test_valid_interp_accepted(self):
        items = derive(elf(b'/lib64/ld-linux-x86-64.so.2\0'))
        interps = [i['value'] for i in items if i['key'] == 'interp']
        self.assertEqual(interps, ['/lib64/ld-linux-x86-64.so.2'])


if __name__ == '__main__':
    unittest.main()
