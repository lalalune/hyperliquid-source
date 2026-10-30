"""Actual-capture corruption controls; model output never means signature acceptance."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import tc_batch_guards_static as tool

PACKET=tool.ROOT/'research/work-items/RE-001-tc-batch-guards-94'


class TcBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.secs=tool.sections(cls.data);cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        off=s['offset']+va-s['address'];result=bytearray(self.data);result[off:off+len(raw)]=raw
        return result

    def test_real_record_and_raw_layout(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['range']['bytes'],1139)
        self.assertEqual(self.record['input_words'],{'header_offset':'0x18','count_offset':'0x10',
                         'buffer_offset':'0x8','element_stride':184,'element_word_offset':'0x50'})
        self.assertEqual(len(self.record['model_vectors']),9)

    def test_raw_error_precedence_and_first_mismatch_model(self):
        tags=self.record['raw_tags']
        self.assertEqual(tool.prefix_model(0,9,[],tags),{'stage':'raw_error_store','tag':'0x8000000000000028','payload_qwords':[9]})
        self.assertEqual(tool.prefix_model(1,9,[],tags),{'stage':'raw_error_store','tag':'0x800000000000000b','payload_qwords':[]})
        self.assertEqual(tool.prefix_model(1,9,[9,10,8],tags),
                         {'stage':'raw_error_store','tag':'0x800000000000000f','payload_qwords':[10,9]})
        self.assertEqual(tool.prefix_model(1,tool.MASK,[0],tags)['payload_qwords'],[0,tool.MASK])

    def test_actual_layout_and_loop_mutations(self):
        for va,raw,reason in [(0x47595f5,struct.pack('<I',192),'Entry stride'),
                              (0x4759604,b'\x48','Entry word offset'),
                              (0x47595e4,b'\x18','Batch count'),
                              (0x47595f1,b'\x10','Entry buffer'),
                              (0x475960c,struct.pack('<I',192),'Stride advance')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_actual_branch_tag_and_payload_mutations(self):
        for va,raw,reason in [(0x4759608,b'\x74','Instruction changed'),
                              (0x4759613,b'\x74','Instruction changed'),
                              (0x47595bc,struct.pack('<Q',0x800000000000002b),'Raw tag base'),
                              (0x4759676,b'\xe0','Raw error tag stores'),
                              (0x4759693,b'\x10','Mismatch payload stores')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_actual_source_relocation_and_fde_mutations(self):
        changed=bytearray(self.data);needle=struct.pack('<QQq',0x5738668,8,0x1f7ea2)
        off=changed.find(needle);self.assertGreaterEqual(off,0)
        self.assertEqual(changed.find(needle,off+1),-1);changed[off+16]^=1
        with self.assertRaisesRegex(ValueError,'Validator-set source relocation'):tool.observe(changed)
        fde=int(self.record['range']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'TC guard FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',1138)))

    def test_identity_and_later_checks_boundary(self):
        with self.assertRaisesRegex(ValueError,'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
        for value in (0,1,2,tool.MASK):
            for count in (1,2,8):
                self.assertEqual(tool.prefix_model(1,value,[value]*count,self.record['raw_tags']),{'stage':'later_checks'})
