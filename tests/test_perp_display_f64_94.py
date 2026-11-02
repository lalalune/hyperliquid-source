import struct
import unittest
from fractions import Fraction
from pathlib import Path

from tools import perp_display_f64_94 as m


class PerpDisplayEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (m.ROOT / m.TARGET).read_bytes()
        m.checked_input(cls.data)
        cls.sections = m.elf_index.sections(cls.data)
        _, fdes, _ = m.fde_extents.fde_extents(cls.data)
        cls.frames = {f['start']: f for f in fdes if f['start'] in m.BODIES}
        cls.words, _ = m.table_words(cls.data, cls.sections)

    def patch(self, va, byte, *, executable=True):
        result = bytearray(self.data)
        off = m.file_offset(self.sections, va, 1, executable=executable)
        result[off] ^= byte
        return result

    def test_target_and_fde_bodies(self):
        self.assertEqual(set(self.frames), set(m.BODIES))
        for f in self.frames.values():
            self.assertIn('index', f)
            m.body_check(self.data, self.sections, f)
        with self.assertRaises(ValueError):
            m.checked_input(self.patch(0x45a47a0, 1))
        with self.assertRaises(ValueError):
            m.body_check(self.patch(0x45a47e3, 1), self.sections, self.frames[0x45a47a0])
        with self.assertRaises(ValueError):
            m.file_offset(self.sections, (1 << 64) - 1, 8)
        with self.assertRaises(ValueError):
            m.file_offset(self.sections, 0, 0)
        with self.assertRaises(ValueError):
            m.file_offset([{'type': 8, 'flags': 4, 'address': 10, 'size': 10, 'offset': 0}], 10)

    def test_location_relocations_unique(self):
        rel = m.relative_relocations(self.data, self.sections, (0x56f21c0,0x56f3350,0x576e470,0x576e150))
        self.assertEqual(rel[0x576e470],0x157a9f0)
        self.assertEqual(rel[0x576e150],0x157b520)
        with self.assertRaises(ValueError):
            m.relative_relocations(self.data, self.sections, (0xffffffffffffffff,))

    def test_rounding_ties_and_boundaries(self):
        self.assertEqual(m.rounded_binary64(Fraction((1<<53)+1)),0x4340000000000000)
        self.assertEqual(m.rounded_binary64(Fraction((1<<53)+3)),0x4340000000000002)
        self.assertEqual(m.rounded_binary64(Fraction(1,1<<1075)),0)
        self.assertEqual(m.rounded_binary64(Fraction(3,1<<1075)),2)
        self.assertEqual(m.rounded_binary64(Fraction(1,1<<1022)),0x0010000000000000)
        with self.assertRaises(ValueError):
            m.rounded_binary64(Fraction(-1))
        with self.assertRaises(ValueError):
            m.bits_to_fraction(0x7ff0000000000000)

    def test_independent_hardware_double_reference(self):
        # Integers are converted then divided, mirroring two distinct SSE operations.
        # This test is supplementary; packet vectors use exact rational rounding.
        for raw in (0,1,999999,(1<<53)-1,(1<<53)+1,(1<<53)+3,(1<<63)-1,(1<<64)-1):
            for k in (0,1,2,6,25,80,255):
                divisor=struct.unpack('<d',struct.pack('<Q',self.words[k]))[0]
                expected=struct.unpack('<Q',struct.pack('<d',float(raw)/divisor))[0]
                self.assertEqual(m.scale_bits(raw,self.words[k]),expected)

    def test_scaling_and_decimal_table_regressions(self):
        self.assertEqual(len(self.words),256)
        prior=m.file_offset(self.sections,0x5b8f60,256*8)
        self.assertEqual(self.words,struct.unpack_from('<256Q',self.data,prior))
        self.assertEqual(sum(m.rounded_binary64(m.bits_to_fraction(self.words[i-1])*10)!=self.words[i] for i in range(1,256)),0)
        self.assertEqual(sum(m.rounded_binary64(Fraction(10**i))!=w for i,w in enumerate(self.words)),195)
        self.assertEqual(self.words[25],0x45208b2a2c280290)
        self.assertEqual(m.rounded_binary64(Fraction(10**25)),0x45208b2a2c280291)
        self.assertEqual(m.scale_bits((1<<53)+1,self.words[2]),0x42d47ae147ae147b)
        self.assertEqual(m.rounded_binary64(Fraction((1<<53)+1,100)),0x42d47ae147ae147c)
        with self.assertRaises(ValueError):
            m.scale_bits(1,0)
        with self.assertRaises(ValueError):
            m.scale_bits(1<<64,self.words[0])
        patched=self.patch(m.TABLE+25*8,1,executable=False)
        modified,_=m.table_words(patched,self.sections)
        self.assertNotEqual(modified[25],self.words[25])
        with self.assertRaises(ValueError):
            m.checked_input(patched)

    def test_control_flow_and_mutations(self):
        interp=lambda kind,raw,asset,ns,length,dec: m.interpreted(self.data,self.sections,kind,raw,asset,ns,length,dec,self.words)
        self.assertEqual(interp('size',0,0,1,0,255),('zero',None,0))
        self.assertEqual(interp('price',0,0,1,0,255)[:2],('asset_failure',None))
        self.assertEqual(interp('price',0,0,0,1,7)[:2],('decimal_failure',None))
        self.assertEqual(interp('price',1,0,0,1,6),('divide',0,0x3ff0000000000000))
        self.assertEqual(interp('size',1,0,0,1,255)[1],255)
        for dec in range(256):
            result, index, _ = interp('price',1,9999,0,10000,dec)
            self.assertEqual((result,index),m.classify('price',1,9999,0,10000,dec))
        damaged=self.patch(0x45a4b83,1)
        with self.assertRaises(ValueError):
            m.interpreted(damaged,self.sections,'size',0,0,0,1,0,self.words)
        damaged=self.patch(0x45a47e2,1)
        self.assertEqual(m.interpreted(damaged,self.sections,'price',1,0,0,1,6,self.words)[0],'decimal_failure')
        with self.assertRaises(ValueError):
            m.body_check(damaged,self.sections,self.frames[0x45a47a0])
        with self.assertRaises(ValueError):
            m.interpreted(self.data,self.sections,'size',-1,0,0,1,0,self.words)

    def test_reciprocal_full_domain_bound(self):
        magic=0x346dc5d63886594b
        error=10000*magic-(1<<75)
        self.assertEqual(error,432)
        self.assertLess(((1<<64)-1)*error,1<<75)
        for x in (0,1,9999,10000,10001,(1<<64)-1):
            self.assertEqual(((x*magic)>>64)>>11,x//10000)
        self.assertNotEqual((10000*(magic-1)>>64)>>11,1)


if __name__ == '__main__':
    unittest.main()
