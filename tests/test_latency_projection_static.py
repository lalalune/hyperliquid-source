"""Digest-bound latency argument-flow controls; never executes the capture."""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import latency_projection_static as subject
from elf_index import sections


class LatencyProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:raise ValueError('wrong capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data);cls.params=subject.parameters(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_retained_native_full_fde_and_argument_records(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((self.report['bytes'],self.report['instructions']),(573,143))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_normalization_exact_rational_identity_and_finite_projection(self):
        for s in [-(1<<63),-2,-1,0,1,60,120,(1<<63)-1]:
            for n in [-(1<<31),-1000000000,-1,0,1,999999999,1000000000,(1<<31)-1]:
                a,b=subject.corrected_pair(s,n)
                self.assertEqual(Fraction(s)+Fraction(n,10**9),Fraction(a)+Fraction(b,10**9))
                self.assertTrue(-(1<<63)<=a<(1<<63));self.assertTrue(-(1<<31)<=b<(1<<31))
                r=subject.numeric_projection(self.params,s,n)
                self.assertTrue(math.isfinite(r['record_value']))
                self.assertGreaterEqual(r['record_value'],0)
                self.assertEqual(r['observer_value'],min(60,r['record_value']))
        self.assertEqual(subject.numeric_projection(self.params,120,0),{'observer_value':60,'record_value':120})
        self.assertEqual(subject.numeric_projection(self.params,1,500000000),{'observer_value':1.5,'record_value':1.5})
        self.assertEqual(subject.numeric_projection(self.params,-1,500000000),{'observer_value':0,'record_value':0})

    def test_real_cap_and_divisor_counterfactuals(self):
        changed=bytearray(self.data);o=self.offset(0x459718);changed[o:o+8]=struct.pack('<d',120)
        p=subject.parameters(changed)
        self.assertEqual(subject.numeric_projection(p,120,0),{'observer_value':120,'record_value':120})
        self.assertEqual(subject.numeric_projection(self.params,120,0)['observer_value'],60)
        with self.assertRaisesRegex(ValueError,'parameters changed'):subject.analyze(changed)
        changed=bytearray(self.data);o=self.offset(0x458d50);changed[o:o+8]=struct.pack('<d',1e6)
        p=subject.parameters(changed)
        self.assertEqual(subject.numeric_projection(p,1,500000000),{'observer_value':60,'record_value':501})
        with self.assertRaisesRegex(ValueError,'parameters changed'):subject.analyze(changed)

    def test_actual_guards_signed_normalization_observer_and_record_operands(self):
        for va in [0x51c9aa8,0x51c9acb]:
            with self.assertRaisesRegex(ValueError,'guard transfer changed'):subject.analyze(self.mutate(va))
        for va in [0x51c9b3e,0x51c9bb3,0x51c9bf2,0x51c9c54,0x51c9c5a,0x51c9c5f,0x459010]:
            with self.assertRaisesRegex(ValueError,'parameters changed'):subject.analyze(self.mutate(va))
        for va in [0x51c9aa1,0x51c9ac6,0x51c9af7,0x51c9b00,0x51c9b0c,0x51c9b30,0x51c9ba5,0x51c9b65,0x51c9bdd,0x51c9c04,0x51c9ad2,0x51c9bf6]:
            with self.assertRaisesRegex(ValueError,'dataflow changed'):subject.analyze(self.mutate(va))
        for site in subject.DIRECT:
            with self.assertRaisesRegex(ValueError,'direct call changed'):subject.analyze(self.mutate(site+1))
        for site,(prefix,_) in subject.RIP.items():
            with self.assertRaisesRegex(ValueError,'RIP binding changed'):subject.analyze(self.mutate(site+len(prefix)))

    def test_actual_source_relocations_and_unwind_extent(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in subject.BINDINGS:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(changed)
        with self.assertRaisesRegex(ValueError,'source path changed'):subject.analyze(self.mutate(0x44bf3e))
        for slot in [0x64a3618,0x64a3630]:
            with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(slot+16))
        fde=int(self.report['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(fde+12))

    def test_public_identity_gate_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out';p.write_bytes(self.mutate(0x459718))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
