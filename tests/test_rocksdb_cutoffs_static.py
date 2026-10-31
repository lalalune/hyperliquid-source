"""Counter predicates and actual-capture corruptions; no TCP/database execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import rocksdb_cutoffs_static as tool

PACKET=tool.ROOT/'research/work-items/RE-001-rocksdb-transfer-cutoffs-94'


class RocksdbCutoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.secs=tool.sections(cls.data);cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        off=s['offset']+va-s['address'];data=bytearray(self.data);data[off:off+len(raw)]=raw
        return data

    def changed_relocation(self,slot,target):
        data=bytearray(self.data);needle=struct.pack('<QQq',slot,8,target);off=data.find(needle)
        self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1)
        data[off+16]^=1;return data

    def test_real_record_and_source_bound_thresholds(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['selected_predicates'],5)
        self.assertEqual([c['large_arm_threshold'] for c in self.record['comparisons']],
                         [50000000000,100000000000,100000000000,100000000000,100000000000])
        self.assertEqual([c['line'] for c in self.record['comparisons']],[96,151,151,151,151])

    def test_exact_bucket_edges_and_u64_boundaries(self):
        for shift in (10,11):
            threshold=(tool.K+1)<<shift
            self.assertFalse(tool.enters_large_arm(0,shift,tool.K))
            self.assertFalse(tool.enters_large_arm(threshold-1,shift,tool.K))
            self.assertTrue(tool.enters_large_arm(threshold,shift,tool.K))
            self.assertTrue(tool.enters_large_arm(tool.MAX,shift,tool.K))
            for residue in range(1<<shift):
                word=(tool.K<<shift)+residue
                self.assertFalse(tool.enters_large_arm(word,shift,tool.K))
                self.assertEqual(tool.enters_large_arm(word,shift,tool.K),word>=threshold)
        self.assertEqual((tool.K+1)<<11,100000000000)
        self.assertEqual(100000000000-(tool.K<<11),2048)

    def test_actual_shift_constant_and_branch_changes(self):
        cases=[(0x1fd665f,b'\x0b','Counter shift/compare'),
               (0x2266b47,struct.pack('<I',tool.K+1),'Counter shift/compare'),
               (0x1fd6666,b'\x77','Instruction changed'),
               (0x47475c6,b'\x86','Instruction changed')]
        for va,raw,reason in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_actual_counter_and_flag_gap_changes(self):
        with self.assertRaisesRegex(ValueError,'Counter word load'):
            tool.observe(self.changed(0x1fd665b,b'\x60'))
        with self.assertRaisesRegex(ValueError,'Flag-preserving move gap'):
            tool.observe(self.changed(0x2266b4b,b'\x49'))

    def test_actual_templates_and_relocated_bindings(self):
        with self.assertRaisesRegex(ValueError,'diagnostic template'):
            tool.observe(self.changed(0x1f2117,b'R'))
        with self.assertRaisesRegex(ValueError,'EVM KVS source binding'):
            tool.observe(self.changed_relocation(0x5692d58,0x1f3f0f))
        with self.assertRaisesRegex(ValueError,'Critical-message call binding'):
            tool.observe(self.changed_relocation(0x576e978,0x143d010))

    def test_owner_fde_identity_and_model_domain(self):
        fde=int(self.record['comparisons'][0]['owner']['fde_va'],16)
        length=tool.CASES[0]['owner_end']-tool.CASES[0]['owner_start']
        with self.assertRaisesRegex(ValueError,'owner FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',length-1)))
        with self.assertRaisesRegex(ValueError,'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
        with self.assertRaisesRegex(ValueError,'unsigned 64-bit'):
            tool.enters_large_arm(-1,11,tool.K)
