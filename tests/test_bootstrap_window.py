"""Actual selected arithmetic and target-bound corruption controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap_window as tool

class BootstrapWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data);cls.code=cls.img.read(tool.LOWER,tool.JOIN-tool.LOWER)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_owner_and_exact_idiom_census(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['exact_idiom_sites'],['0x43892cd'])

    def check_pair(self,current,target):
        actual=tool.lower(self.code,current,target)
        if current==target:self.assertEqual(actual,dict(route='equal_branch',window=None))
        elif current>target:self.assertEqual(actual,dict(route='ahead_branch',window=None))
        else:
            expected=(current+1,min(target,current+100,tool.MASK))
            self.assertEqual(actual,dict(route='window',window=expected))
            first,last=actual['window']
            self.assertTrue(current<first<=last<=target)
            self.assertLessEqual(last-first+1,100)

    def test_actual_small_and_wrap_boundary_grid(self):
        values=list(range(0,161))+[tool.MASK-n for n in range(161)]+[(1<<63)-1,1<<63,(1<<63)+1]
        for current in values:
            for target in values:self.check_pair(current,target)

    def test_inclusive_edges_and_saturation(self):
        for current in (0,1,1000,tool.MASK-101,tool.MASK-100,tool.MASK-99,tool.MASK-1,tool.MASK):
            for delta in (-1,0,1,99,100,101):
                target=current+delta
                if 0<=target<=tool.MASK:self.check_pair(current,target)
        self.assertEqual(tool.lower(self.code,tool.MASK-100,tool.MASK)['window'],(tool.MASK-99,tool.MASK))
        with self.assertRaises(ValueError):tool.lower(self.code,-1,0)

    def test_actual_lea_immediate_mutation_changes_count(self):
        code=bytearray(self.code);code[0x43892cd-tool.LOWER+3]=0x62
        self.assertEqual(tool.lower(code,0,1000)['window'],(1,99))
        with self.assertRaisesRegex(ValueError,'operand/route'):
            tool.observe(self.changed(0x43892cd+3,b'\x62'))
        code=bytearray(self.code);code[0]=0x90
        with self.assertRaisesRegex(ValueError,'Unmodelled'):tool.lower(code,0,1000)

    def test_actual_gates_saturations_min_and_argument_copies(self):
        for va in (0x4389298+4,0x43892a9+1,0x43892af+1,0x43892c2+2,0x43892d1+3,
                   0x43892d7+3,0x43892db+2,0x43892e5+2,0x43892e9+3,0x43892fe+3,0x4389321+3):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_and_identity(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
