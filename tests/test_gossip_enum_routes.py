"""Actual enum selectors with conditional helper outcomes, not a wire decoder."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import gossip_enum_routes as tool

class GossipEnumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_both_owners(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(len(self.record['owners']),2)

    def test_real_tag_selector_domain(self):
        for tag in list(range(256))+[65535,(1<<31)-1,1<<31,(1<<32)-1]:
            self.assertEqual(tool.request_arm(self.img,tag),{0:'two_u64',1:'unit_1',2:'unit_2'}.get(tag,'invalid'))
            arm=tool.response_arm(self.img,tag)
            if tag<4:self.assertEqual(arm['callee'],hex(tool.ARMS[tag][2]))
            else:self.assertIsNone(arm)
        with self.assertRaises(ValueError):tool.request_arm(self.img,-1)

    def test_declared_header_and_payload_status_domain(self):
        for status in range(256):
            for tag in range(4):
                result=tool.request_route(self.img,tag,status)
                self.assertEqual(result['route'],'header_error' if status!=18 else ['two_u64','unit_1','unit_2','invalid'][tag])
            first=tool.request_route(self.img,0,18,(status,18))
            second=tool.request_route(self.img,0,18,(18,status))
            self.assertEqual(len(first['calls']),2 if status==18 else 1)
            self.assertEqual(len(second['calls']),2)
            self.assertEqual(first['route'],'two_u64' if status==18 else 'payload_error')
            self.assertEqual(second['route'],'two_u64' if status==18 else 'payload_error')

    def test_real_selector_and_table_mutations_change_routes(self):
        changed=self.changed(0x438b5ee,b'\x03')
        self.assertEqual(tool.request_arm(tool.Image(changed),2),'invalid')
        with self.assertRaisesRegex(ValueError,'selector'):tool.observe(changed)
        changed=self.changed(tool.TABLE,self.img.read(tool.TABLE+4,4))
        self.assertEqual(tool.response_arm(tool.Image(changed),0)['callee'],'0x496f730')
        with self.assertRaisesRegex(ValueError,'arm binding'):tool.observe(changed)
        changed=self.changed(0x438b5dc,b'\x11')
        self.assertEqual(tool.request_route(tool.Image(changed),1,18)['route'],'header_error')
        with self.assertRaisesRegex(ValueError,'status branch'):tool.observe(changed)

    def test_real_helpers_literals_limits_and_output_fields(self):
        for va in (0x438b5d2+1,0x438b646+1,0x438b65e+1,0x438b64f+1,
                   0x438b707,0x438b72b+1,0x438b837+1,0x438b79b+1,0x438b7d7+1,
                   0x438b670+4,0x438b860+4,0x438b92f+3,0x204640,0x6f160f,0x209410+12,0x2032d0+12):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_extents_and_identity(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
