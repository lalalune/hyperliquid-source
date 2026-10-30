"""Captured comparator controls and declared-field/ASCII models, no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import compound_ascii_static as tool

PACKET=tool.ROOT/'research/work-items/RE-001-compound-ascii-comparator-94'


class CompoundAsciiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.secs=tool.sections(cls.data);cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        off=s['offset']+va-s['address'];changed=bytearray(self.data);changed[off:off+len(raw)]=raw
        return changed

    def test_real_record_and_complete_byte_pair_comparison(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['range']['bytes'],283)
        self.assertEqual(self.record['byte_comparison'],{'byte_inputs':256,'byte_mismatches':0,'byte_pairs':65536,'pair_mismatches':0})
        self.assertEqual(self.record['source_location']['line'],136)

    def test_declared_tag_and_two_component_model(self):
        c=self.record['fold_constants']
        one={'tag':1,'byte1':0,'common_bytes':b'Tail'}
        self.assertTrue(tool.compound_model(one,dict(one,common_bytes=b'tAIL'),c))
        self.assertFalse(tool.compound_model(one,dict(one,byte1=1),c))
        self.assertFalse(tool.compound_model(one,dict(one,common_bytes=b'Tail!'),c))
        two={'tag':2,'indirect_bytes':b'First','common_bytes':b'Second'}
        self.assertTrue(tool.compound_model(two,dict(two,indirect_bytes=b'fIRST',common_bytes=b'sECOND'),c))
        self.assertFalse(tool.compound_model(two,dict(two,indirect_bytes=b'Other'),c))
        self.assertFalse(tool.compound_model(one,two,c))

    def test_ascii_boundaries_and_non_ascii_bytes(self):
        c=self.record['fold_constants']
        self.assertEqual([tool.fold_observed(v,**c) for v in (64,65,90,91,127,128,255)],[64,97,122,91,127,128,255])
        self.assertFalse(tool.byte_string_equal(b'[',b'{',c))
        self.assertFalse(tool.byte_string_equal('\u00c4'.encode(),'\u00e4'.encode(),c))
        self.assertTrue(tool.byte_string_equal(b'A\0Z',b'a\0z',c))

    def test_actual_fold_instruction_corruptions(self):
        for va,raw,reason in [(0x284b47d,b'\xc0','ASCII fold constants'),
                              (0x284b481,b'\x19','ASCII fold constants'),
                              (0x284b489,b'\x04','ASCII fold constants'),
                              (0x284b484,b'\x93','ASCII range condition')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_actual_field_and_source_corruptions(self):
        for va,raw,reason in [(0x284b4d9,b'\x10','Common component'),
                              (0x284b454,b'\x18','Indirect component'),
                              (0x284b4bd,b'\x01','Tag-1 byte-zero')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))
        changed=bytearray(self.data);needle=struct.pack('<QQq',0x56c9370,8,0x1fd235)
        off=changed.find(needle);self.assertGreaterEqual(off,0)
        self.assertEqual(changed.find(needle,off+1),-1);changed[off+16]^=1
        with self.assertRaisesRegex(ValueError,'HTTP scheme source binding'):tool.observe(changed)

    def test_fde_identity_and_model_domain(self):
        fde=int(self.record['range']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'Compound comparator FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',282)))
        with self.assertRaisesRegex(ValueError,'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
        with self.assertRaisesRegex(ValueError,'modeled tag domain'):
            tool.compound_model({'tag':0},{'tag':1},self.record['fold_constants'])
