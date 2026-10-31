"""Capture-bound caller controls; no shell, network or captured binary execution."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import host_ip_admission as tool

class HostIpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_capture_packet_and_all_probe_sites(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual([p['endpoint'] for p in self.record['probes']],['ifconfig.me','api.ipify.org','icanhazip.com'])

    def test_boundary_and_low_bit_domain(self):
        for length in (0,1,14,15,16,17,64,(1<<63)-1,1<<63,(1<<64)-1):
            for al in range(256):
                for remaining in (0,1,15,1<<63,(1<<64)-1):
                    expected='reject_before_parser' if length>=16 else 'admit_to_collection' if al%2==1 and remaining==0 else 'reject_after_parser'
                    self.assertEqual(tool.admission(length,al,remaining),expected)
        self.assertEqual(tool.admission(15,2,0),'reject_after_parser')
        for word in (0,1,15,tool.MIN-1,tool.MIN,tool.MIN+1,(1<<64)-1):
            self.assertEqual(tool.override_route(word),'probe_path' if word==tool.MIN else 'override_path')
        with self.assertRaises(ValueError):tool.admission(-1,1,0)

    def test_all_three_callsite_guards_reject_corruption(self):
        for site in tool.SITES:
            limit,parse=site[6:8]
            for va in (limit+3,parse+5+5,parse+5+8,parse+5+10):
                raw=bytes([self.img.read(va,1)[0]^1])
                with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                    tool.observe(self.changed(va,raw))

    def test_real_targets_literals_and_relocations(self):
        for site in tool.SITES:
            for va in (site[1],site[2]+3,site[4]+3,site[5]+2,site[7]+1):
                with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                    tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        for va in (0x1e3739+1,0x1e71f1+2,0x13ca4ce+1,0x13ca759+1):
            with self.assertRaises(ValueError):tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_real_override_sentinel_and_source(self):
        for va in (0x13ca4bc+9,0x13ca4c6+4,0x13ca4b6+2,0x5666bb0+16):
            with self.assertRaises(ValueError):tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_owner_extent_and_digest(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))

if __name__=='__main__':unittest.main()
