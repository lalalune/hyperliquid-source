"""Native target evidence and flag-group first-byte counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import flag_group_first_byte_static as subject
from elf_index import sections


class FlagGroupFirstByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),10617)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_store_census_group_bytes(self):
        census=self.report['store_census']
        self.assertEqual(census['group']['0x14'],
                         [['0x15a3f10','0x1'],['0x15a420c','0x0']])
        self.assertEqual(census['group']['0x15'],[['0x15a3c5e','al']])
        self.assertEqual(census['group']['0x16'],[['0x15a3c55','al']])
        self.assertEqual(census['group']['0x17'],[['0x15a3d14','cl']])
        self.assertEqual(census['rsp_store_count'],267)
        self.assertEqual(len(census['indirect_store_sites']),81)

    def test_segment_gating(self):
        segs=self.report['segments']
        a,b=segs['A'],segs['B']
        self.assertEqual(a['entry_branches'],['0x15a3ee2'])
        self.assertFalse(a['fallthrough_entry'])
        self.assertEqual(a['predecessor']['mnemonic'],'jmp')
        self.assertEqual(a['predecessor']['target'],'0x15a44e0')
        self.assertEqual(b['entry_branches'],['0x15a4161'])
        self.assertTrue(b['fallthrough_entry'])
        self.assertEqual(b['predecessor']['mnemonic'],'je')
        self.assertEqual(b['predecessor']['target'],'0x15a44e0')
        for seg in (a,b):
            self.assertTrue(seg['interior_origins_inside'])
            self.assertEqual(seg['window_indirect_stores'],[])
            self.assertEqual(seg['window_push_pop'],[])

    def test_callee_call_census(self):
        census=self.report['callee_call_census']
        self.assertEqual(census['direct_e8_sites'],
                         ['0x15a3f5f','0x15a401e','0x15a4263','0x15a431c'])
        self.assertTrue(census['binary_wide'])
        self.assertEqual(self.report['consumer']['group_lea_sites'],
                         ['0x15a3f52','0x15a400a','0x15a4256','0x15a4308'])

    def test_chain_selection_model(self):
        self.assertEqual(subject.first_byte_value('A'),1)
        self.assertEqual(subject.first_byte_value('B'),0)
        self.assertEqual(subject.selection_for_block('A'),
                         {'block':'A','flag_byte':1,'pointer':'0x459e50',
                          'length':4,'text':'Warn'})
        self.assertEqual(subject.selection_for_block('B'),
                         {'block':'B','flag_byte':0,'pointer':'0x46a5c4',
                          'length':5,'text':'Error'})
        self.assertEqual(self.report['chain_selections'],
                         [subject.selection_for_block('A'),
                          subject.selection_for_block('B')])
        with self.assertRaisesRegex(ValueError,'unknown field block'):
            subject.first_byte_value('C')

    def test_formatter_selection_context(self):
        # All four established formatter indices exist as context,
        # but the chain model only ever produces 0 and 1.
        self.assertEqual(subject.formatter_selection(2),(0x45a19c,4,b'Info'))
        self.assertEqual(subject.formatter_selection(3),(0x46a5c9,5,b'Debug'))
        with self.assertRaisesRegex(ValueError,'not pinned'):
            subject.formatter_selection(4)
        self.assertEqual([(s['index'],s['text']) for s in self.report['formatter_selections']],
                         [(0,'Error'),(1,'Warn'),(2,'Info'),(3,'Debug')])

    def test_first_byte_write_counterfactuals(self):
        # The immediate byte of each first-byte store (value 1 -> 0
        # and 0 -> 1) is rejected by the write pin.
        with self.assertRaisesRegex(ValueError,'first-byte write A'):
            subject.analyze(self.mutate(0x15a3f14))
        with self.assertRaisesRegex(ValueError,'first-byte write B'):
            subject.analyze(self.mutate(0x15a4210))

    def test_gate_counterfactuals(self):
        with self.assertRaisesRegex(ValueError,'segment A gate'):
            subject.analyze(self.mutate(0x15a3ee3))
        with self.assertRaisesRegex(ValueError,'segment B gate'):
            subject.analyze(self.mutate(0x15a4163))

    def test_population_store_counterfactuals(self):
        for va,what in ((0x15a3c55,'flag byte store'),
                        (0x15a3c5e,'derived byte store'),
                        (0x15a3d14,'counter byte store')):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,what):
                    subject.analyze(self.mutate(va))

    def test_group_lea_and_call_counterfactuals(self):
        with self.assertRaisesRegex(ValueError,'group lea'):
            subject.analyze(self.mutate(0x15a3f52))
        with self.assertRaisesRegex(ValueError,'direct call census'):
            subject.analyze(self.mutate(0x15a3f60))

    def test_selection_counterfactuals(self):
        for va in (subject.LENGTH_TABLE,subject.POINTER_TABLE,0x459e50,0x46a5c4):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'selection'):
                    subject.analyze(self.mutate(va))

    def test_body_counterfactual(self):
        with self.assertRaisesRegex(ValueError,'body changed'):
            subject.analyze(self.mutate(0x15a5000))

    def test_scans_reject_synthetic_extra_store(self):
        insns,rows=subject.decoded_consumer(self.data)
        extra=insns+[(0x15a3f20,'mov','BYTE PTR [rsp+0x14],0x7')]
        with self.assertRaisesRegex(ValueError,'store census'):
            subject.validate_scans(extra,rows)

    def test_scans_reject_synthetic_outside_branch(self):
        insns,rows=subject.decoded_consumer(self.data)
        extra=insns+[(0x15a5000,'je','15a3fd2 <_x>')]
        with self.assertRaisesRegex(ValueError,'gating'):
            subject.validate_scans(extra,rows)

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x15a3f10))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
