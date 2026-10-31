"""RE-005: a non-UTF-8 panic location path must fail closed as EvidenceError.

Synthetic minimal input for bv.panic_location(): one section holding the
lea, the Location record, and the path bytes. Same construction style as
the sibling section-name encoding test (test_bincode_varint_section_name_encoding.py).
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

LEA_VA, LOC, PATH_VA = 0x1000, 0x1020, 0x1100


def build(path_bytes):
    data = bytearray(0x200)
    secs = {'.text': {'addr': 0x1000, 'offset': 0, 'size': 0x200}}
    data[0:3] = b'\x48\x8d\x3d'
    struct.pack_into('<i', data, 3, LOC - (LEA_VA + 7))
    struct.pack_into('<QII', data, 0x20 + 8, len(path_bytes), 42, 7)
    data[0x100:0x100 + len(path_bytes)] = path_bytes
    return bytes(data), secs, {LOC: PATH_VA}


class PanicPathEncodingTests(unittest.TestCase):
    def test_nonutf8_panic_path_fails_closed(self):
        # On base the bare .decode() in panic_location() escapes as
        # UnicodeDecodeError; with the fix it raises EvidenceError.
        data, secs, relocs = build(b'a\xffbc')
        with self.assertRaisesRegex(bv.EvidenceError,
                                    'panic location path is not valid UTF-8'):
            bv.panic_location(data, secs, relocs, LEA_VA)

    def test_ascii_panic_path_still_parses(self):
        data, secs, relocs = build(b'src/x.rs')
        r = bv.panic_location(data, secs, relocs, LEA_VA)
        self.assertEqual(r['path'], 'src/x.rs')
        self.assertEqual((r['line'], r['column']), (42, 7))


if __name__ == '__main__':
    unittest.main()
