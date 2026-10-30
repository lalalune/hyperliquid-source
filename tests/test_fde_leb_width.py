"""64-bit unwind LEB boundaries, including actual CIE-parser integration."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from fde_extents import uleb,sleb,parse_cie

class LebWidthTests(unittest.TestCase):
    def test_unsigned_boundaries(self):
        for raw,value in [(b'\0',0),(b'\xff'*9+b'\x01',(1<<64)-1),(b'\x80'*9+b'\0',0)]:
            self.assertEqual(uleb(raw,0,len(raw)),(value,len(raw)))

    def test_unsigned_tenth_byte_overflow(self):
        for terminal in range(2,128):
            raw=b'\x80'*9+bytes([terminal])
            with self.subTest(terminal=terminal),self.assertRaisesRegex(ValueError,'ULEB128'):
                uleb(raw,0,len(raw))

    def test_signed_boundaries_and_sign_extension(self):
        for raw,value in [(b'\x7f',-1),(b'\xff'*9+b'\0',(1<<63)-1),(b'\x80'*9+b'\x7f',-(1<<63)),(b'\xff'*9+b'\x7f',-1),(b'\x80'*9+b'\0',0)]:
            self.assertEqual(sleb(raw,0,len(raw)),(value,len(raw)))

    def test_signed_tenth_byte_overflow(self):
        for terminal in range(1,127):
            raw=b'\x80'*9+bytes([terminal])
            with self.subTest(terminal=terminal),self.assertRaisesRegex(ValueError,'SLEB128'):
                sleb(raw,0,len(raw))

    def test_cie_alignment_overflow_rejected(self):
        for alignment in (b'\x80'*9+b'\x02',):
            raw=b'\1zR\0'+alignment+b'\x78\x10\1\x1b'
            with self.assertRaisesRegex(ValueError,'ULEB128'):
                parse_cie(raw,0,0,len(raw),0,0)
        raw=b'\1zR\0\1'+b'\x80'*9+b'\x01'+b'\x10\1\x1b'
        with self.assertRaisesRegex(ValueError,'SLEB128'):
            parse_cie(raw,0,0,len(raw),0,0)

    def test_truncation_and_continuation_still_fail(self):
        for decoder in (uleb,sleb):
            for raw in (b'',b'\x80',b'\x80'*10,b'\x80'*10+b'\0'):
                with self.subTest(decoder=decoder.__name__,raw=raw),self.assertRaises(ValueError):
                    decoder(raw,0,len(raw))

if __name__=='__main__':unittest.main()
