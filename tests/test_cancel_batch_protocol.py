"""Conditional normal-helper controls; no order or chain actions."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cancel_batch_protocol as tool

class CancelBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_both_cores_and_twelve_byte_marker(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['snapshot']['bytes'],12)
        self.assertEqual(len(self.record['owners']),2)

    def test_input_bound_and_prepared_count_saturation(self):
        values=(0,1,2,9999,10000,10001,1<<63,tool.MASK-1,tool.MASK)
        for index in range(2):
            for length in (0,1,10000,10001,tool.MASK):
                for old in values:
                    for prepared in values:
                        result=tool.model(self.img,index,length,prepared,old,0,0)
                        self.assertEqual(result['status'],323 if length>=10001 else 390)
                        self.assertEqual(result['counter'],old if length>=10001 else min(old+prepared,tool.MASK))
                        self.assertEqual(result['worker'],length<10001)
                        if length>=10001:self.assertEqual(result['predicate_calls'],0)
        self.assertEqual(tool.model(self.img,0,2,1,4,0,0)['counter'],5)

    def test_two_predicate_raw_status_classes_and_short_circuit(self):
        for index in range(2):
            for first in range(256):
                for second in (0,1,255):
                    result=tool.model(self.img,index,1,1,0,first,second)
                    self.assertEqual(result['predicate_calls'],1 if first else 2)
                    self.assertEqual(result['snapshot_bytes'],12 if first or second else 0)

    def test_real_limit_and_second_cmov_mutations_change_model(self):
        for index,c in enumerate(tool.CASES):
            changed=self.changed(c['bound']+3,struct.pack('<I',10000))
            self.assertEqual(tool.model(tool.Image(changed),index,10000,1,0,0,0)['status'],323)
            with self.assertRaisesRegex(ValueError,'length limit'):tool.observe(changed)
            changed=self.changed(c['second']+2,b'\x42')
            self.assertEqual(tool.model(tool.Image(changed),index,1,1,tool.MASK,0,0)['counter'],0)
            with self.assertRaisesRegex(ValueError,'CMOV'):tool.observe(changed)

    def test_real_helpers_snapshot_offsets_kinds_and_statuses(self):
        for c in tool.CASES:
            for va in (c['prepare']+1,c['prepare']+13,c['pred1']+2,c['pred1']+8,c['pred2']+8,
                       c['snapshot']+3,c['snapshot']+8,c['tag']+4,c['worker']+1,c['normal']+2):
                with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                    tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_fde_and_target_identity(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0]['start'],b'\x90'))
if __name__=='__main__':unittest.main()
