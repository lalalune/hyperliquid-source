"""Conditional enumeration outcomes and successful age-result folds."""
import itertools
import json
import math
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fod_age_static as tool


class FodAgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_fallback_domains(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        for tag,root,count in itertools.product((0,1,2,0xffffffff),(0,1,1<<63,(1<<64)-1),(0,1,5,(1<<64)-1)):
            expected='own_path_age' if tag!=1 else 'own_path_age_fallback' if root==0 or count==0 else 'entry_age_fold'
            self.assertEqual(tool.selected_path(tag,root,count),expected)

    def test_declared_result_vectors_against_independent_minimum(self):
        bits=[0xfff0000000000000,0xc059000000000000,0xbff0000000000000,1<<63,0,
              1,0x3ff0000000000000,0x4059000000000000,0x7ff0000000000000,0x7ff8000000000000]
        checked=0
        for length in (1,2,3):
            for words in itertools.product(bits,repeat=length):
                values=[struct.unpack('<d',struct.pack('<Q',w))[0] for w in words]
                if length>1 and any(math.isnan(v) for v in values):
                    with self.assertRaisesRegex(ValueError,'unordered'):
                        tool.age_fold(words)
                else:
                    expected=words[0] if length==1 else words[min(range(length),key=lambda i:values[i])]
                    self.assertEqual(tool.age_fold(words),expected)
                checked+=1
        self.assertEqual(checked,1110)

    def test_first_equal_bits_and_singleton_nan(self):
        self.assertEqual(tool.age_fold([1<<63,0]),1<<63)
        self.assertEqual(tool.age_fold([0,1<<63]),0)
        self.assertEqual(tool.age_fold([0x7ff8000000001234]),0x7ff8000000001234)
        with self.assertRaisesRegex(ValueError,'nonempty'):
            tool.age_fold([])

    def test_actual_tag_root_count_and_fold_conditions(self):
        for va in (0x13d1b11,0x13d1b63,0x13d1b7a,0x13d1ede,0x13d1ee6,0x13d1eef,0x13d1ef7):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_callback_and_source_bindings(self):
        for slot,target in ((0x576ead8,0x144bfd0),(0x576eae0,0x144fe90)):
            data=bytearray(self.data);needle=struct.pack('<QQq',slot,8,target);off=data.find(needle)
            self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1);data[off+16]^=1
            with self.assertRaisesRegex(ValueError,'helper binding'):
                tool.observe(data)
        for loc in (0x5666e80,0x5666e98,0x5666eb0,0x5666ec8,0x566ad30):
            with self.assertRaisesRegex(ValueError,'source'):
                tool.observe(self.changed(loc+16,struct.pack('<I',999)))

    def test_actual_fde_and_identity(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',1587)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))


if __name__=='__main__':unittest.main()
