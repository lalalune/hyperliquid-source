"""Static counter order, checked partial writes and declared sequential controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import lz4_counter_order as tool

class Lz4CounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_writer_wrapping_prefix(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(tool.record_prefix((tool.MASK,tool.MASK,tool.MASK),1,2),(0,1,0))
        self.assertEqual(tool.record_prefix((0,0,0),0,0),(0,0,1))

    def test_checked_accumulation_partial_write_order(self):
        counts=(2,3,4)
        for flags in range(8):
            totals=[tool.MASK if flags&(1<<n) else 10 for n in range(3)]
            result=tool.drain(self.img,counts,totals,0)
            first=next((n for n in range(3) if flags&(1<<n)),None)
            expected=list(totals)
            for n in range(3 if first is None else first):expected[n]+=counts[n]
            self.assertEqual(result['totals'],expected)
            self.assertEqual(result['remaining'],[0,0,0])
            self.assertEqual(result['route'],'emit' if first is None else 'overflow_'+str(first))
        self.assertEqual(tool.drain(self.img,(0,1,0),(0,tool.MASK,0),0)['route'],'overflow_1')

    def test_filter_after_accumulation_and_no_division_on_zero(self):
        for flag in range(256):
            for input_bytes in (0,1,tool.MASK):
                result=tool.drain(self.img,(input_bytes,7,3),(0,0,0),flag<<48)
                self.assertEqual(result['totals'],[input_bytes,7,3])
                self.assertEqual(result['route'],'skip' if input_bytes==0 or flag==2 else 'emit')
                if result['record']:
                    self.assertEqual(result['record']['samples'],3)
                    self.assertEqual(result['record']['ratio'],float(7)/float(input_bytes))

    def test_captured_unsigned_conversion_magic_at_boundaries(self):
        values={0,tool.MASK}
        for exponent in range(64):
            for delta in (-1,0,1):
                value=(1<<exponent)+delta
                if 0<=value<=tool.MASK:values.add(value)
        for value in values:
            self.assertEqual(struct.pack('<d',tool.uint_float(self.img,value)),struct.pack('<d',float(value)))

    def test_real_accumulator_and_filter_mutations_change_model(self):
        changed=self.changed(0x3d23188+1,b'\x29')
        result=tool.drain(tool.Image(changed),(2,3,4),(10,10,10),0)
        self.assertEqual(result['totals'],[8,13,14])
        with self.assertRaisesRegex(ValueError,'operand/order'):tool.observe(changed)
        changed=self.changed(0x3d231c3,b'\x03')
        self.assertEqual(tool.drain(tool.Image(changed),(1,1,1),(0,0,0),2<<48)['route'],'emit')
        with self.assertRaisesRegex(ValueError,'operand/order'):tool.observe(changed)

    def test_real_operands_sources_fdes_and_identity(self):
        for va in (0x3d2a74c,0x3d2a755+3,0x3d2a75e+3,0x3d23166+4,0x3d23173+4,
                   0x3d23180+4,0x3d2318b+1,0x3d23225+2,0x3d23241+3,0x203e80,0x202ea0,0x57199c0+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
