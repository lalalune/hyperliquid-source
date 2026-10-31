"""Actual capture controls and declared raw decision domains, no file writes."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import daily_rotation_static as tool


class DailyRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_every_accepted_raw_second(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        for second in range(90000):
            self.assertEqual(tool.hour(second),second//3600)
        self.assertEqual(tool.hour(89999),24)

    def test_raw_rotation_population_and_precondition_order(self):
        for mode in range(256):
            for old_hour in range(256):
                for same_date in (False,True):
                    for second in (0,3600,86400):
                        expected='no_rotation'
                        if mode==1 and (not same_date or old_hour!=second//3600):expected='hourly_template'
                        elif mode!=1 and not same_date:expected='daily_template'
                        self.assertEqual(tool.selected_route(0,second,mode,same_date,old_hour),expected)
        for second,path in [(89999,'no_rotation'),(90000,'hour_assert_arm'),
                            (921599,'hour_assert_arm'),(921600,'time_unwrap_arm'),((1<<32)-1,'time_unwrap_arm')]:
            self.assertEqual(tool.selected_route(0,second,0,True,0),path)
            self.assertEqual(tool.selected_route(tool.MIN,second,0,True,0),'skip')

    def test_all_local_global_byte_pairs_and_two_post_heads(self):
        for local in range(256):
            for global_byte in range(256):
                for post_head in (0,tool.MIN):
                    expected=local!=0 and global_byte!=0 and post_head==0
                    self.assertEqual(tool.flush_gate(local,global_byte,post_head),expected)
        for head in (1,tool.MIN-1,tool.MIN+1,(1<<64)-1):
            self.assertTrue(tool.flush_gate(1,1,head))
        with self.assertRaisesRegex(ValueError,'raw byte'):
            tool.flush_gate(256,1,0)

    def test_actual_rotation_and_flush_operands(self):
        for va in (0x1401d57,0x1401d63,0x1401d6e,0x1401d92,0x1401d9c,
                   0x1401d83,0x1401fa5,0x1401fb4,0x1402454,0x1402633,0x1402641):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_shared_global_flush_and_write_bindings(self):
        for slot,target in [(0x576ef18,0x5788312),(0x576eaa8,0x13d1880)]:
            data=bytearray(self.data);needle=struct.pack('<QQq',slot,8,target);off=data.find(needle)
            self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1);data[off+16]^=1
            with self.assertRaisesRegex(ValueError,'Flush relocation'):
                tool.observe(data)
        for va in (0x1401f75,0x1402612):
            raw=bytearray(self.img.read(va,5));raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'helper changed'):
                tool.observe(self.changed(va,raw))

    def test_actual_sources_template_fde_and_identity(self):
        for va in (0x566aac8+16,0x5666dd8+16,0x1e9393+2):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        fde=int(self.record['owners'][0]['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',776)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x1401d40,b'\x90'))


if __name__=='__main__':unittest.main()
