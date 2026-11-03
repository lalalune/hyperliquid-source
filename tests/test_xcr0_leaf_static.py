"""Native target evidence and actual leaf-constant counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import xcr0_leaf_static as subject
from elf_index import sections


class Xcr0LeafTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),1687)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_leaf_result_rule_and_census(self):
        leaf=self.report['leaf']
        self.assertEqual(leaf['index_register'],'ecx')
        self.assertEqual(leaf['index_value'],0)
        self.assertEqual(leaf['shift'],32)
        owners={x['role']:x for x in self.report['owners']}
        self.assertEqual(owners['xcr0_leaf']['bytes'],13)
        self.assertEqual(owners['xcr0_leaf']['sha256'],
                         'f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be')
        self.assertEqual(owners['consumer_refresh']['bytes'],1674)
        self.assertEqual(self.report['direct_callers'],1)
        self.assertEqual(self.report['call_census']['direct_call_sites'],['0x5cae04c'])
        self.assertEqual(self.report['call_census']['relocation_references'],0)
        self.assertFalse(self.report['captured_code_executed'])

    def test_consumer_trace_pinned(self):
        trace=self.report['consumer_trace']
        self.assertEqual(trace['consumer'],'consumer_refresh')
        self.assertEqual(trace['call_site'],'0x5cae04c')
        self.assertEqual(trace['result_register'],'r14')
        self.assertEqual(trace['high_field']['mask'],'0x60000')
        self.assertEqual(trace['high_field']['bits'],[17,18])
        self.assertEqual(trace['first_branch']['mask'],'0x6')
        self.assertEqual(trace['first_branch']['bits'],[1,2])
        self.assertEqual(trace['first_branch']['target'],'0x5cae260')
        self.assertEqual(trace['first_branch']['taken_when'],'(xcr0 & 0x6) != 0x6')
        self.assertEqual(trace['mask_field']['mask'],'0xe0')
        self.assertEqual(trace['mask_field']['bits'],[5,6,7])
        self.assertEqual(trace['mask_field']['h_set']['value'],'0x8000000000000000')
        self.assertEqual(trace['mask_field']['complement_xor'],'0x5cae0c4')
        self.assertEqual(trace['mask_field']['composed_or'],'0x5cae157')
        self.assertEqual(trace['convergence'],{'shared_block':'0x5cae274','site':'0x5cae2f3'})

    def test_leaf_byte_counterfactuals(self):
        # Index-clear opcode, XGETBV opcode byte, shift immediate, RET byte.
        for va in [0x5cae3e0,0x5cae3e4,0x5cae3e8,0x5cae3ec]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'xcr0'):
                    subject.analyze(self.mutate(va))

    def test_consumer_pin_counterfactuals(self):
        # Mutations inside the consumer body are stopped by its pinned body
        # hash before the trace pins are consulted (same control shape as
        # the merged packet's owner hash).
        for va in [0x5cae04c,0x5cae060,0x5cae065,0x5cae06d,0x5cae0c8]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_fde_record_control(self):
        fde=int(self.report['owners'][0]['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+8))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x5cae3e0))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
