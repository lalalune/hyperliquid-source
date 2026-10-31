"""Raw-byte selector priority, not valid original Rust enum reachability."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_mode_selector as tool

class BuildModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_source(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['source']['line'],199)

    def test_complete_declared_mode_bytes_for_two_name_classes(self):
        for kind in range(256):
            for flag in range(256):
                for name in (b'run-client',b'node'):
                    route='local' if kind==flag==0 else 'special_client' if name==b'run-client' else 'debug' if kind==1 else 'release' if kind==2 else 'invalid_kind'
                    expected={'route':route,'tag':1 if route in ('debug','release') else None if route=='invalid_kind' else 0}
                    self.assertEqual(tool.select(self.img,kind,flag,name),expected)

    def test_name_byte_mutations_and_local_precedence(self):
        name=b'run-client'
        for pos in range(10):
            for value in range(256):
                changed=name[:pos]+bytes([value])+name[pos+1:]
                self.assertEqual(tool.select(self.img,255,255,changed)['route'],'special_client' if changed==name else 'invalid_kind')
        for name in (b'',b'run-client',b'Run-client',b'xrun-client',b'run-client\x00'):
            self.assertEqual(tool.select(self.img,0,0,name),{'route':'local','tag':0})

    def test_actual_name_and_kind_immediates_change_model(self):
        changed=self.changed(0x13cd437,b's')
        self.assertEqual(tool.select(tool.Image(changed),255,1,b'sun-client')['route'],'special_client')
        self.assertEqual(tool.select(tool.Image(changed),255,1,b'run-client')['route'],'invalid_kind')
        with self.assertRaisesRegex(ValueError,'selector/operand'):tool.observe(changed)
        changed=self.changed(0x13cd469,b'\x03')
        self.assertEqual(tool.select(tool.Image(changed),3,0,b'node')['route'],'release')
        with self.assertRaisesRegex(ValueError,'selector/operand'):tool.observe(changed)

    def test_real_guards_tags_templates_and_source(self):
        for va in (0x13cd42d,0x13cd432,0x13cd450+1,0x13cd46a+1,0x13cd54d+3,
                   0x13cd5f2+3,0x13cd501+3,0x13cd5a9+3,0x1fae07+2,0x1e4c77+2,
                   0x13cd536+2,0x566a0c0+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_and_target_identity(self):
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
