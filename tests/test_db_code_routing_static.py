"""Controls against real DB wrapper bytes/tables; no database or target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import db_code_routing_static as tool

PACKET=tool.ROOT/'research/work-items/RE-001-db-code-routing-94'


class DbRoutingTests(unittest.TestCase):
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

    def test_real_record_and_case_sensitive_label_span(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(len(self.record['consumers']),6)
        for table in self.record['tables']:
            self.assertEqual(len(table['entries']),28)
            self.assertEqual(table['entries'][4]['label'],'Ps')
            self.assertEqual(table['entries'][27]['label'],'ps')
        self.assertEqual(self.record['code_rows'][27]['home_key'],0)
        self.assertEqual([sum(r['home_key']==k for r in self.record['code_rows']) for k in range(3)],[21,4,3])

    def test_global_dependency_and_actual_caller_codes(self):
        mask=int(self.record['mask_values']['global_state'],16)
        self.assertEqual(self.record['gate_comparison'],{'pairs':7168,'construction_pairs':738,'mismatches':0})
        self.assertTrue(tool.construction_arm(21,0,mask))
        self.assertFalse(tool.construction_arm(21,10,mask))
        self.assertEqual(self.record['construction_excluded_global_bytes'],[10,18,19,20,21,22,23,24,25,31])
        values={c['code'] for c in self.record['direct_call_windows']}
        self.assertEqual(values,{21,22,23,24,25,26})
        for c in (24,25,26):
            self.assertFalse(any(tool.construction_arm(c,g,mask) for g in range(256)))

    def test_actual_label_and_pointer_changes(self):
        with self.assertRaisesRegex(ValueError,'DB label bytes changed'):
            tool.observe(self.changed(0x595028,b'P'))
        with self.assertRaisesRegex(ValueError,'DB label pointer/stride'):
            tool.observe(self.changed_relocation(0x56f1920+27*8,0x595028))

    def test_actual_mask_changes(self):
        start=next(iter(tool.CONSUMERS))
        for offset,value in ((0x26,0x081ffeff^1),(0x54,0x00e00100^1),(0x1ea,0x0020ff01^1)):
            with self.subTest(offset=hex(offset)):
                original=self.changed(start+offset,struct.pack('<I',value))
                with self.assertRaisesRegex(ValueError,'routing masks'):
                    tool.observe(original)

    def test_actual_global_and_code_gate_changes(self):
        start=next(iter(tool.CONSUMERS))
        for va,raw,reason in [(start+0x1e0,b'\x49','Global-byte/code'),
                              (start+0x3d,b'\xec','code subtraction'),
                              (start+0x1f4,b'\x04','Global-byte/code')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_caller_binding_fde_and_identity_changes(self):
        with self.assertRaisesRegex(ValueError,'Caller code immediate'):
            tool.observe(self.changed(0x3269c55,struct.pack('<I',27)))
        with self.assertRaisesRegex(ValueError,'Global-state slot binding'):
            tool.observe(self.changed_relocation(0x576e928,0x577b288))
        fde=int(self.record['consumers'][0]['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'DB wrapper FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',1080)))
        with self.assertRaisesRegex(ValueError,'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
