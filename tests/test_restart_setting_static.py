"""Static codec/helper-result/floor controls; no actual configuration file read."""
import itertools
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import restart_setting_static as tool


class RestartSettingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_codec_component_population(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        accepted={bytes(x) for x in itertools.product(b'rR',b'mM',b'pP')}
        checked=0
        for position in range(3):
            for byte in range(256):
                suffix=b'rmp'[:position]+bytes([byte])+b'rmp'[position+1:]
                expected='rmp_candidate' if suffix in accepted else 'json_candidate'
                self.assertEqual(tool.component_codec(b'file.'+suffix),expected);checked+=1
        self.assertEqual(checked,768)
        for suffix in accepted:
            self.assertEqual(tool.component_codec(b'file.'+suffix),'rmp_candidate')
        for value in (b'.rmp',b'..',b'file',b'file.',b'file.rmp.extra',b'file.rmp ',b'.json'):
            self.assertEqual(tool.component_codec(value),'json_candidate')

    def test_normal_helper_result_population(self):
        checked=0
        for codec,eligible,read_word,tag,payload in itertools.product(
                ('rmp_candidate','json_candidate'),(False,True),(0,tool.MIN),range(256),(0,tool.MAX)):
            success=tag==9 if codec=='rmp_candidate' else tag%2==0
            expected=payload if eligible and read_word!=tool.MIN and success else 0
            self.assertEqual(tool.loader_value(codec,eligible,read_word,tag,payload),expected);checked+=1
        self.assertEqual(checked,4096)
        self.assertEqual(tool.loader_value('rmp_candidate',True,0,0x109,7),7)

    def test_u64_floor_and_unchanged_nonzero_payload(self):
        for word in list(range(4096))+[tool.MIN-1,tool.MIN,tool.MIN+1,tool.MAX]:
            self.assertEqual(tool.page_count(word),max(1,word))
        with self.assertRaisesRegex(ValueError,'u64'):
            tool.page_count(-1)

    def test_actual_extension_read_parser_and_floor_operands(self):
        for va in (0x13ca072,0x13ca076,0x144b9e3,0x144ba1e,0x144ba24,
                   0x144ba48,0x144ba69,0x144ba86,0x144bab8,0x144bceb,0x144be14):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_decoder_and_global_relocation_bindings(self):
        for va in (0x13ca052,0x144bce0,0x144be0f):
            raw=bytearray(self.img.read(va,5));raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'decoder call'):
                tool.observe(self.changed(va,raw))
        data=bytearray(self.data);needle=struct.pack('<QQq',0x576e928,8,0x577b288);off=data.find(needle)
        self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1);data[off+16]^=1
        with self.assertRaisesRegex(ValueError,'helper/global binding'):
            tool.observe(data)

    def test_actual_path_label_source_fdes_and_identity(self):
        for va in (0x1de68f+2,0x1fd0ce+1,0x5666b80+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x13ca000,b'\x90'))


if __name__=='__main__':unittest.main()
