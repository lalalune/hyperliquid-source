"""Resolved lookup fixtures and actual sequence-join mutations; no mempool IO."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import mempool_parent_walk as tool

def key(n):return n.to_bytes(32,'big')

class ParentWalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_complete_owner(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['element_bytes'],32)

    def test_single_chain_order_duplicates_and_unrelated_fork(self):
        records={key(3):(30,key(2),[key(100),key(101)]),key(2):(20,key(1),[key(100)]),
                 key(1):(10,key(0),[key(999)]),key(4):(25,key(1),[key(888)])}
        result=tool.walk(self.img,key(3),10,records)
        self.assertEqual(result['status'],0)
        self.assertEqual(result['insert_calls'],[key(100),key(101),key(100)])
        self.assertEqual(result['visited'],[key(3),key(2),key(1)])

    def test_equal_below_missing_and_empty_payload_edges(self):
        for sequence in (0,1,10,11,(1<<64)-1):
            for watermark in (0,1,10,11,(1<<64)-1):
                records={key(1):(sequence,key(0),[])}
                result=tool.walk(self.img,key(1),watermark,records)
                self.assertEqual(result['status'],0 if sequence==watermark else 1)
                self.assertEqual(result['key'],None if sequence==watermark else key(1) if sequence<watermark else key(0))
                self.assertEqual(result['insert_calls'],[])
        self.assertEqual(tool.walk(self.img,key(9),0,{})['key'],key(9))

    def test_actual_equality_join_mutation_changes_termination(self):
        changed=self.changed(0x44b99d0,b'\x74')
        self.assertEqual(tool.walk(tool.Image(changed),key(1),10,{key(1):(9,key(0),[])})['status'],0)
        self.assertEqual(tool.walk(tool.Image(changed),key(1),10,{key(1):(10,key(0),[])})['status'],1)
        with self.assertRaisesRegex(ValueError,'operand/route'):tool.observe(changed)

    def test_actual_key_offsets_watermark_insert_stride_and_returns(self):
        for va in (0x44b9827+3,0x44b9839+3,0x44b984e+3,0x44b9870+3,0x44b9925+3,
                   0x44b9932,0x44b9937+3,0x44b9960+4,0x44b997e+1,0x44b9983+3,0x44b99b1+2,0x44b99e8+2):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_and_target_identity(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
