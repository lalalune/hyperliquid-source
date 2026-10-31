"""Raw-code partition and real capture controls; no network/native execution."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import rpc_code_static as tool


class RpcCodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_packet_and_stores(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual([(r['code_i32'],r['tag']) for r in self.record['table_rows']],
                         [(-32603,6),(-32602,5),(-32601,3),(-32600,2)])
        self.assertEqual(self.record['emitted_tags'],[0,1,2,3,5,6,7])
        self.assertEqual(self.record['result_stores']['kind_u32_offset'],'0x30')
        self.assertEqual(self.record['result_stores']['original_code_u32_offset'],'0x34')

    def test_signed_windows_against_independent_dictionary(self):
        expected={-32700:0,-32007:1,-32600:2,-32601:3,-32602:5,-32603:6}
        # All signed values in two declared 65536-value windows, not all u32s.
        for signed in range(-65536,65536):
            self.assertEqual(tool.classify(signed & tool.MASK),expected.get(signed,7))
        for word in [0,1,tool.MASK,0x7fffffff,0x80000000,0x12348044,0x123482f9]:
            signed=word-(1<<32) if word>>31 else word
            self.assertEqual(tool.classify(word),expected.get(signed,7))

    def test_partition_and_width(self):
        bias=self.record['wrapping_add_u32']
        preimages={((i-bias)&tool.MASK) for i in range(4)}
        special={0xffff8044,0xffff82f9}
        self.assertEqual(len(preimages),4);self.assertFalse(preimages & special)
        self.assertEqual(self.record['primitive_partition']['default_words'],(1<<32)-6)
        for word in preimages|special:
            for delta in [-1,0,1]:
                value=(word+delta)&tool.MASK
                self.assertEqual(((value+bias)&tool.MASK)<=3,value in preimages)
        for word in [-1,1<<32,True,1.5]:
            with self.assertRaisesRegex(ValueError,'u32'):
                tool.classify(word)

    def test_actual_range_and_handler_changes(self):
        for va in (0x15bba19,0x15bba21,0x15bba24,0x15bba3d,0x15bba4b):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))
        for target in tool.HANDLERS:
            with self.subTest(target=hex(target)),self.assertRaisesRegex(ValueError,'handler tag'):
                tool.observe(self.changed(target+1,struct.pack('<I',4)))

    def test_actual_table_pointer_and_targets(self):
        for index in range(4):
            off=struct.unpack('<i',self.img.read(0x261458+index*4,4))[0]
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'table target'):
                tool.observe(self.changed(0x261458+index*4,struct.pack('<i',off+1)))
        raw=bytearray.fromhex(tool.ANCHORS[0x15bba26]);raw[-1]^=1
        with self.assertRaisesRegex(ValueError,'operand/control'):
            tool.observe(self.changed(0x15bba26,raw))

    def test_actual_caller_results_fde_and_identity(self):
        for va in (0x161434b,0x1614381,0x15bba8c,0x15bba90,0x15bba94):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))
        fde=int(self.record['owners'][0]['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',532)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x15bb930,b'\x90'))


if __name__=='__main__':unittest.main()
