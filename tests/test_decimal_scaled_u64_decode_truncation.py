"""Truncated instruction encodings must fail closed as the module's ToolError.

decode() walked the input with bare indexing and struct.unpack_from, so
an encoding cut short at the end of the buffer escaped as IndexError or
struct.error instead of ToolError. fetch() is the only in-repo caller,
so the guard sits on decode() itself and covers every caller.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import decimal_scaled_u64 as dec


class DecodeTruncationTests(unittest.TestCase):
    def test_truncated_encodings_refuse(self):
        cases = {
            'lone REX': b'\x48',
            'REX plus opcode, no ModRM': b'\x48\x8b',
            'conditional jump, short displacement': b'\x0f\x80\x01\x02',
            'VEX prefix, no payload': b'\xc4\xe1',
            'lone repeat prefix': b'\xf3',
            'opcode needing an immediate': b'\xb8\x01',
            'add with a short immediate': b'\x81\xc0\x01',
            'return with a short immediate': b'\xc2\x01',
        }
        for label, blob in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(dec.ToolError, 'truncated instruction encoding'):
                    dec.decode(blob, 0, 0x1000)

    def test_complete_encodings_still_decode(self):
        nop = dec.decode(b'\x90', 0, 0x1000)
        self.assertEqual((nop.key, nop.size), (0x90, 1))
        mov = dec.decode(b'\x48\x89\xd8', 0, 0x1000)
        self.assertEqual((mov.key, mov.size), (0x89, 3))
        ret = dec.decode(b'\xc3', 0, 0x1000)
        self.assertEqual((ret.key, ret.size), (0xc3, 1))


if __name__ == '__main__':
    unittest.main()
