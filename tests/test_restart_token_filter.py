"""Captured token classifier and ASCII-only normal-output controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import restart_token_filter as tool

class RestartTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_ascii_separator_census(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['ascii_separator_values'],[9,10,11,12,13,32])
        for value in range(128):
            expected=b'a b' if value in (9,10,11,12,13,32) else b'a'+bytes([value])+b'b'
            self.assertEqual(tool.normalize_ascii(self.img,b'a'+bytes([value])+b'b'),expected)

    def test_all_single_byte_flag_mutations(self):
        flag=b'--backup-logs'
        self.assertTrue(tool.skip_token(self.img,flag))
        for pos in range(len(flag)):
            for value in range(256):
                changed=flag[:pos]+bytes([value])+flag[pos+1:]
                self.assertEqual(tool.skip_token(self.img,changed),changed==flag)
        for value in (b'',b'--backup-log',flag+b's',b'x'+flag,flag+b'=true'):
            self.assertFalse(tool.skip_token(self.img,value))

    def test_normalization_order_repetition_quotes_and_empty(self):
        cases=[(b'  node\t--restart-style LoopChild  --backup-logs\n',b'node --restart-style LoopChild'),
               (b'--backup-logs a --backup-logs b --backup-logs',b'a b'),
               (b'--backup-logs --backup-logs',b''),(b' \t\n',b''),
               (b'"--backup-logs" --backup-logs=true x--backup-logs',b'"--backup-logs" --backup-logs=true x--backup-logs')]
        for source,expected in cases:self.assertEqual(tool.normalize_ascii(self.img,source),expected)
        with self.assertRaises(ValueError):tool.normalize_ascii(self.img,b'\xc2\xa0')

    def test_actual_mask_and_literal_mutations_affect_model(self):
        mask=0x100003e00^(1<<9)
        changed=self.changed(0x13df3f1,struct.pack('<Q',mask))
        self.assertEqual(tool.normalize_ascii(tool.Image(changed),b'a\tb'),b'a\tb')
        with self.assertRaisesRegex(ValueError,'whitespace mask'):tool.observe(changed)
        changed=self.changed(0x219582,b'x')
        self.assertFalse(tool.skip_token(tool.Image(changed),b'--backup-logs'))
        with self.assertRaisesRegex(ValueError,'literal'):tool.observe(changed)

    def test_actual_call_and_filter_join_operands(self):
        for va in (0x1438eb7+1,0x1438eeb+1,0x1438ec4+4,0x1438f3a+1,0x1438f55+2,
                   0x13df5b5+3,0x13df5c5+3,0x13df5d3+1,0x21b94c+4,0x14b1398+2,0x566a138+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_four_fde_extents_and_target_identity(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
