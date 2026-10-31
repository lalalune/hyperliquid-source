"""Static target-bound integer-domain and actual counterfactual certificates."""
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import wire_qty_normal_form as subject
from elf_index import sections


class WireQtyNormalFormTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data);cls.params=subject.parameters(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_and_retained_domain_certificates(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((self.report['bytes'],self.report['instructions']),(915,237))
        self.assertEqual(len(self.report['reciprocal_certificates']),13)
        self.assertTrue(all(p['complete_integer_domain'] for p in self.report['reciprocal_certificates']))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_fraction_identity_and_minimality_at_decimal_limb_and_domain_edges(self):
        values=set(range(1001))|{(1<<63)-1,(1<<63)-2,1234567800000000}
        for power in range(19):
            values.update(n for n in [10**power-1,10**power,10**power+1] if 0<=n<(1<<63))
        for high in [0,1,9,10,11,99,100,subject.HMAX-1,subject.HMAX]:
            for low in [0,1,9,10,100,subject.U32-1,subject.U32]:values.add((high<<32)|low)
        for n in values:
            coefficient,scale=subject.limb_relation(n,self.params)
            self.assertEqual((coefficient,scale),subject.normal_form(n),n)
            self.assertEqual(Fraction(coefficient,10**scale),Fraction(n,10**8),n)
            self.assertTrue(0<=scale<=8 and 0<=coefficient<(1<<63))
            self.assertTrue(scale==0 or coefficient%10!=0,n)
        self.assertEqual(subject.normal_form(0),(0,0))
        self.assertEqual(subject.normal_form(10**8),(1,0))
        self.assertEqual(subject.normal_form((1<<63)-1),((1<<63)-1,8))
        for bad in [-1,1<<63]:
            with self.assertRaises(ValueError):subject.limb_relation(bad,self.params)

    def test_actual_inverse_reciprocal_and_shift_counterfactuals(self):
        # Real inverse-five immediate cd->ce; x=5 becomes a false match.
        changed=self.mutate(0x41c5861,0xce);p=subject.parameters(changed)
        self.assertFalse(subject.divisible_ten(5,self.params['inverse_five'],self.params['divisibility_bound']))
        self.assertTrue(subject.divisible_ten(5,p['inverse_five'],p['divisibility_bound']))
        with self.assertRaisesRegex(ValueError,'modular divisibility'):
            subject.analyze(changed)
        # Actual high byte of the low-word division reciprocal, not a spec edit.
        changed=self.mutate(0x41c5858,0);p=subject.parameters(changed)
        self.assertEqual((10*self.params['low_multiplier'])>>64,1)
        self.assertEqual((10*p['low_multiplier'])>>64,0)
        with self.assertRaisesRegex(ValueError,'rounds downward'):
            subject.analyze(changed)
        changed=self.mutate(0x41c5839,34);p=subject.parameters(changed)
        self.assertEqual((10*p['high'][0]['multiplier'])>>p['high'][0]['shift'],2)
        with self.assertRaisesRegex(ValueError,'fails declared domain'):
            subject.analyze(changed)

    def test_actual_scale_masks_pack_and_input_path_controls(self):
        for site in subject.FLAGS:
            with self.assertRaisesRegex(ValueError,'scale-selection'):
                subject.analyze(self.mutate(site+3))
        for site in subject.TEST_BRANCHES:
            with self.assertRaisesRegex(ValueError,'polarity'):
                subject.analyze(self.mutate(site))
        for va in [0x41c59c0,0x41c5a0f,0x41c5a52]:
            with self.assertRaisesRegex(ValueError,'mask/product'):
                subject.analyze(self.mutate(va))
        for va in [0x41c57ff,0x41c5820,0x41c5a95,0x41c5a9a,0x41c5aa1,0x41c5aa6]:
            with self.assertRaisesRegex(ValueError,'dataflow'):
                subject.analyze(self.mutate(va))

    def test_actual_relocations_source_diagnostics_and_fde(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in subject.BINDINGS:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):
                subject.analyze(changed)
        for va in [0x6482060,0x7c66fd,0x7c66c0]:
            with self.assertRaisesRegex(ValueError,'Location|diagnostic'):
                subject.analyze(self.mutate(va))
        fde=int(self.report['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejects_modified_truncated_and_other_release(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x41c5861))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())
