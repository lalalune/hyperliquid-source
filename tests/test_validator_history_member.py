"""Declared synthetic RAM trees, not native snapshot/history execution."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import validator_history_member as tool

def key(value):return value.to_bytes(20,'big')
def leaf(*values):return ([key(v) for v in values],[])

class ValidatorMemberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_external_comparator_and_key_width(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['comparator']['symbol'],'memcmp')
        self.assertEqual(self.record['comparator']['bytes'],20)

    def test_synthetic_empty_leaf_and_two_tree_heights(self):
        trees=[(None,set()),(leaf(),set()),(leaf(10,30,50),{10,30,50}),
               (([key(20),key(40)],[leaf(10),leaf(30),leaf(50)]),{10,20,30,40,50}),
               (([key(40)],[([key(20)],[leaf(10),leaf(30)]),([key(60)],[leaf(50),leaf(70)])]),set(range(10,71,10)))]
        for tree,expected in trees:
            memory,root,height=tool.make_tree(tree)
            for value in range(82):self.assertEqual(tool.member(self.img,memory,root,height,key(value)),value in expected)

    def test_twenty_byte_identity_and_comparison_order(self):
        original=bytes(range(20));memory,root,height=tool.make_tree(([original],[]))
        for pos in range(20):
            for value in range(256):
                query=original[:pos]+bytes([value])+original[pos+1:]
                self.assertEqual(tool.member(self.img,memory,root,height,query),query==original)

    def test_actual_compare_width_mutation_changes_prefix_match(self):
        stored=b'x'*19+b'a';query=b'x'*19+b'b'
        memory,root,height=tool.make_tree(([stored],[]))
        self.assertFalse(tool.member(self.img,memory,root,height,query))
        changed=self.changed(0x44b317a,struct.pack('<I',19))
        self.assertTrue(tool.member(tool.Image(changed),memory,root,height,query))
        with self.assertRaisesRegex(ValueError,'operand/route'):tool.observe(changed)

    def test_real_warning_lookup_comparator_offsets_and_branches(self):
        for va in (0x44b3066,0x44b30eb+1,0x44b3114+3,0x44b312a+2,0x44b313f+3,
                   0x44b3149,0x44b3152,0x44b3189+1,0x44b319d,0x44b31b9,0x44b31c4,0x5738668+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_synthetic_bounds_fde_and_identity(self):
        with self.assertRaises(ValueError):tool.member(self.img,{},0x1000,0,key(1))
        with self.assertRaises(ValueError):tool.make_tree(([key(2),key(1)],[]))
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
