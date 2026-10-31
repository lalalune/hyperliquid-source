"""Pinned operands and independent ASCII-language checks, no node execution."""
import json
import re
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import address_parser_static as tool


class AddressParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes()
        cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_packet_and_layout(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['tail_bytes'],40)
        self.assertEqual(self.record['required_decoded_bytes'],20)
        self.assertEqual(self.record['iterator_whitespace_bytes'],[9,10,13,32])
        self.assertEqual(self.record['nibble_domain'],{'inputs':256,'accepted':22})
        self.assertEqual(self.record['result_observation']['success_payload_offsets'],[1,21])

    def test_all_nibble_bytes_and_pairs(self):
        digits=b'0123456789abcdef'
        independent={c:i for i,c in enumerate(digits)}
        independent.update({c:i+10 for i,c in enumerate(b'ABCDEF')})
        for byte in range(256):
            self.assertEqual(tool.nibble(byte),independent.get(byte))
        for a in range(256):
            for b in range(256):
                hi,lo=tool.nibble(a),tool.nibble(b)
                actual=None if hi is None or lo is None else hi*16+lo
                expected=None if a not in independent or b not in independent else independent[a]*16+independent[b]
                self.assertEqual(actual,expected)

    def test_ascii_position_population_against_independent_language(self):
        pattern=re.compile(rb'(?:0x)?0*[0-9a-fA-F]{40}')
        tail=b'0123456789aBcDeF0123456789aBcDeF01234567'
        checked=0
        for prefix in (b'',b'0x'):
            for pos in range(40):
                for byte in range(128):
                    value=prefix+tail[:pos]+bytes([byte])+tail[pos+1:]
                    actual=tool.ascii_decode(value)
                    self.assertEqual(actual is not None,pattern.fullmatch(value) is not None)
                    if actual is not None:
                        self.assertEqual(actual,bytes.fromhex(value[-40:].decode('ascii')))
                    checked+=1
        self.assertEqual(checked,10240)
        for count in range(97):
            for prefix in (b'',b'0x',b'0X'):
                for padding in (b'0'*count,b'1'*count):
                    value=prefix+padding+tail
                    self.assertEqual(tool.ascii_decode(value) is not None,pattern.fullmatch(value) is not None)

    def test_lengths_inner_prefix_and_domain(self):
        for n in range(40):
            self.assertIsNone(tool.ascii_decode(b'f'*n))
        self.assertEqual(tool.ascii_decode(b'0x'+b'f'*40),b'\xff'*20)
        self.assertIsNone(tool.ascii_decode(b'0x'+b'f'*38))
        self.assertIsNone(tool.ascii_decode(b'0x0x'+b'f'*38))
        for space in (b' ',b'\t',b'\r',b'\n',b'\v',b'\f'):
            self.assertIsNone(tool.ascii_decode(b'f'*39+space))
        with self.assertRaisesRegex(ValueError,'ASCII'):
            tool.ascii_decode('é'.encode())
        with self.assertRaisesRegex(ValueError,'one byte'):
            tool.nibble(256)

    def test_actual_framing_hex_and_result_operands(self):
        for va in (0x1444a2a,0x1444a38,0x1444a73,0x1444bd1,0x1444be7,
                   0x1444c14,0x4eb653d,0x4eb6569,0x4eb65e4,0x4eb661f):
            original=bytes.fromhex(tool.ANCHORS[va]);changed=bytearray(original);changed[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,changed))

    def test_actual_source_relocation_fde_and_identity(self):
        for va in (0x7166d0,0x219834,0x566a410+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        for slot,target in [(0x576f580,0x4eb64f0),(0x566a410,0x1fd07e)]:
            data=bytearray(self.data);needle=struct.pack('<QQq',slot,8,target)
            off=data.find(needle);self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1)
            data[off+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):
                tool.observe(data)
        fde=int(self.record['owners'][0]['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',875)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x1444a00,b'\x90'))


if __name__=='__main__':
    unittest.main()
