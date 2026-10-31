"""Capture-bound raw arithmetic; synthetic words only, no transaction execution."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import response_fee_limbs as tool

class ResponseFeeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data);cls.code=cls.img.read(tool.LOWER,tool.JOIN-tool.LOWER)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_owner(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['source']['line'],51)

    def test_actual_arithmetic_boundary_matrix(self):
        values=(0,1,2,(1<<64)-2,(1<<64)-1,1<<64,(1<<64)+1,(1<<127),(1<<128)-1)
        for tag in range(5):
            for base in values:
                for maximum in values:
                    for priority in values:
                        low=base% (1<<64)
                        if maximum<low:expected=base
                        else:
                            delta=maximum-low
                            total=base+(delta if tag<2 else min(delta,priority))
                            expected=total if total<1<<128 else None
                        self.assertEqual(tool.lower(self.code,tag,base,maximum,priority),expected,(tag,base,maximum,priority))

    def test_high_limb_and_carry_distinctions(self):
        self.assertEqual(tool.lower(self.code,0,1<<64,7,0),(1<<64)+7)
        self.assertEqual(tool.lower(self.code,2,1<<64,7,3),(1<<64)+3)
        self.assertIsNone(tool.lower(self.code,0,(1<<128)-1,1<<64,0))
        self.assertEqual(tool.lower(self.code,0,(1<<128)-1,0,0),(1<<128)-1)
        # Raw classes are not assertions about valid original context states.
        with self.assertRaises(ValueError):tool.lower(self.code,5,0,0,0)

    def test_actual_sbb_mutation_changes_interpretation(self):
        code=bytearray(self.code);code[0x1606a6e-tool.LOWER+3]=1
        self.assertNotEqual(tool.lower(code,0,0,1<<64,0),tool.lower(self.code,0,0,1<<64,0))
        with self.assertRaisesRegex(ValueError,'operand/guard'):
            tool.observe(self.changed(0x1606a6e+3,b'\x01'))
        code=bytearray(self.code);code[0]=0x90
        with self.assertRaisesRegex(ValueError,'Unmodelled'):tool.lower(code,0,0,1,0)

    def test_real_selected_operands_branches_and_source(self):
        for va in (0x1606a0f+3,0x1606a23,0x1606a36+3,0x1606a54+3,
                   0x1606a3a+9,0x1606abe+8,0x1606acf+7,0x1606b2e+3,0x5677fa8+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_and_identity(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
