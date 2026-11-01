"""Whole raw-u8 domain, independent expected bytes, and original-byte mutants."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import nodeip_value_encoding as tool

class LocalValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)
    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data
    def test_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))
    def test_all_256_raw_values_in_both_numeric_forms(self):
        for value in range(256):
            encoded=tool.local_messagepack(self.image,value)
            expected=bytes.fromhex('81a9')+b'LocalNode'+(bytes([value]) if value<=127 else bytes([204,value]))
            self.assertEqual(encoded,expected)
            self.assertEqual(tool.decimal_payload(self.image,value),str(value).encode('ascii'))
            # Minimal independent decoder of this one spec-derived envelope.
            self.assertEqual(encoded[0]&15,1);size=encoded[1]&31
            self.assertEqual(encoded[2:2+size].decode(),'LocalNode')
            payload=encoded[2+size:]
            self.assertEqual(payload[0] if payload[0]<128 else payload[1],value)
        for position in range(4):
            for value in range(256):
                octets=bytearray([1,2,3,4]);octets[position]=value
                expected=bytes.fromhex('81a2497094')+b''.join(bytes([n]) if n<128 else bytes([204,n]) for n in octets)
                self.assertEqual(tool.ip_pre_finalizer(self.image,octets),expected)
    def test_actual_signed_branch_and_hundred_boundary_mutations(self):
        data=self.changed(0x4aec6d3+1,b'\x89')
        self.assertNotEqual(tool.local_messagepack(tool.Image(data),0),tool.local_messagepack(self.image,0))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
        data=self.changed(0x4aa440a+3,b'\x10')
        self.assertNotEqual(tool.ip_pre_finalizer(tool.Image(data),bytes([1,2,3,4])),tool.ip_pre_finalizer(self.image,bytes([1,2,3,4])))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
        data=self.changed(0x45bc9fe+1,b'\x62')
        self.assertEqual(tool.decimal_payload(tool.Image(data),99),b'099')
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_original_map_and_key_stores_change_envelope(self):
        for va,value in ((0x45bcd2c+3,0x82),(0x45bcd47+3,0xa8),(0x45bcd69+2,ord('X')),(0x45bcd77+4,ord('X'))):
            data=self.changed(va,bytes([value]))
            self.assertNotEqual(tool.local_messagepack(tool.Image(data),128),tool.local_messagepack(self.image,128))
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_literal_table_and_call_bindings_reject_changes(self):
        for va,raw in ((0x6f7096,b'X'),(0x6f7dfd,b'X'),(0x45bcd91,b'\x00'),(0x45bc9c0,b'\x00')):
            with self.assertRaises(ValueError):tool.observe(self.changed(va,raw))
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
    def test_raw_domain_and_decoder_rejection(self):
        for value in (-1,256):
            with self.assertRaises(ValueError):tool.local_messagepack(self.image,value)
            with self.assertRaises(ValueError):tool.decimal_payload(self.image,value)
        with self.assertRaises(ValueError):tool.local_messagepack(self.image,0,tag=0)
        with self.assertRaises(ValueError):tool.ip_pre_finalizer(self.image,bytes(4),flag_1a=1)
        with self.assertRaises(ValueError):tool.ip_pre_finalizer(self.image,bytes(4),flag_1c=2)
        data=self.changed(0x4aec6d3,b'\xcc')
        with self.assertRaisesRegex(ValueError,'unsupported'):tool.local_messagepack(tool.Image(data),0)
if __name__=='__main__':unittest.main()
