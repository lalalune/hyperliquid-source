"""Real output-arm interpretation and static identity/dispatch corruption controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import string_result_wrappers as tool

class StringResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_complete_five_owner_family(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(len(self.record['owners']),5)
        self.assertEqual(sum(n for _,n,_ in tool.CASES),6687)

    def test_actual_selected_arms_declared_tags_and_word_boundaries(self):
        words=[(0,0,0),(0,1,0),(1,2,3),((1<<64)-1,1<<63,0),(0,0,(1<<64)-1)]
        for index in range(5):
            for tag in range(9):
                for payload in words:
                    self.assertEqual(tool.selected_output(self.data,index,tag,payload),payload if tag==8 else (0,1,0))
        with self.assertRaises(ValueError):tool.selected_output(self.data,0,9,(0,0,0))

    def test_collapse_immediate_mutation_changes_interpreted_output(self):
        for index,owner in enumerate(self.record['owners']):
            va=int(owner['error'],16)+20+11
            changed=self.changed(va,struct.pack('<I',2))
            self.assertEqual(tool.selected_output(changed,index,0,(99,88,77)),(0,2,0))
            with self.assertRaisesRegex(ValueError,'collapse stores'):tool.observe(changed)

    def test_real_guards_and_payload_operands(self):
        for owner in self.record['owners']:
            for va in (int(owner['tag_compare'],16)+4,int(owner['success'],16)+4,int(owner['success'],16)+15):
                with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                    tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_real_table_targets_and_cleanup_helper(self):
        for owner in self.record['owners']:
            table=int(owner['table'],16)
            for n in range(8):
                va=table+4*n
                with self.subTest(tag=n,table=hex(table)),self.assertRaises(ValueError):
                    tool.observe(self.changed(va,struct.pack('<i',0)))
            va=int(owner['cleanup_targets'][5],16)+9
            with self.assertRaisesRegex(ValueError,'cleanup helper'):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_all_fde_extents_and_digest(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
