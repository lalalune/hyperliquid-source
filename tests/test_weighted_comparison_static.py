"""Target-derived checked-fold bounds and wide-comparison corruption controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import weighted_comparison_static as subject
from elf_index import sections


class WeightedComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data)
        cls.params=subject.parameters(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_and_retained_records(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(1657,422))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_limb_borrow_identity_and_checked_fold_boundaries(self):
        # Boundary grid spans both carry bits, strict ties, low-limb borrow,
        # and products beyond u64. The all-domain proof is in the packet.
        values={0,1,2,3,4,subject.U64//3,subject.U64//2,1<<62,1<<63,subject.U64-1,subject.U64}
        for b in list(values):
            for s in [3*b//2-1,3*b//2,3*b//2+1]:
                if 0<=s<=subject.U64:values.add(s)
        for s in values:
            for b in values:self.assertEqual(subject.wide_relation(self.params,s,b),2*s<3*b,(s,b))
        self.assertFalse(subject.wide_relation(self.params,3,2))
        self.assertTrue(subject.wide_relation(self.params,subject.U64,subject.U64))
        for row,expected in [([],0),([0],0),([subject.U64],subject.U64),([subject.U64-1,1],subject.U64),([subject.U64,1],None),([1<<63,1<<63],None)]:
            self.assertEqual(subject.checked_sum(row),expected)
        with self.assertRaises(ValueError):subject.checked_sum([-1])

    def test_actual_factor_shift_and_carry_condition_counterfactuals(self):
        for va,value,s,b in [(0x422e3de,2,1,1),(0x422e3d9,62,1<<62,1<<62),(0x422e3ef,0x93,3,2)]:
            changed=self.mutate(va,value);p=subject.parameters(changed)
            self.assertNotEqual(subject.wide_relation(self.params,s,b),subject.wide_relation(p,s,b))
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_actual_carry_branches_status_row_operands_and_calls(self):
        for va in [0x422e2f9,0x422e3b5,0x435171e]:
            with self.assertRaisesRegex(ValueError,'transfer changed'):subject.analyze(self.mutate(va))
        for va in [0x422e3d0,0x422e2f3,0x422e30e,0x422e3ab]:
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(self.mutate(va))
        for site in subject.CALLS:
            with self.assertRaisesRegex(ValueError,'call changed'):subject.analyze(self.mutate(site+1))
        for va in [0x422e2f0,0x422e3b1,0x4351714,0x37c4430]:
            with self.assertRaisesRegex(ValueError,'dataflow changed'):subject.analyze(self.mutate(va))

    def test_real_source_relocations_and_fde_bounds(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in [0x6475bd8,0x64dfb50]:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(changed)
        for va in [0x449efc,0x6475be0]:
            with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(va))
        with self.assertRaisesRegex(ValueError,'LEA changed'):subject.analyze(self.mutate(0x3bcae67))
        for owner in self.report['owners']:
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(fde+12))

    def test_public_identity_gate_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x422e3de))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
