"""Native five-body controls and independent logical-ring ordering checks."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import nonce_ordering_static as subject
from elf_index import sections


class NonceOrderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:raise ValueError('wrong capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data);cls.spec=subject.specification()

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_full_native_regeneration_and_retained_records(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(1685,480))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_two_span_obligations_equal_every_logical_neighbor(self):
        for cap in range(1,17):
            for head in range(cap):
                for count in range(cap+1):
                    logical=[(head+i)%cap for i in range(count)]
                    expected=list(zip(logical,logical[1:]))
                    got=[(a,b) for _,a,b in subject.obligations(cap,head,count)]
                    self.assertEqual(got,expected,(cap,head,count))
                    self.assertEqual(len(got),max(0,count-1))
        self.assertEqual(subject.obligations(0,0,0),[])
        for cap in range(1,5):
            for physical in itertools.product([0,1,1<<63,subject.U64],repeat=cap):
                for head in range(cap):
                    for count in range(cap+1):
                        logical=[physical[(head+i)%cap] for i in range(count)]
                        self.assertEqual(subject.ordered([0x72,0x72],physical,head,count),all(a<b for a,b in zip(logical,logical[1:])))

    def test_real_strictness_and_signedness_counterfactuals_all_five_bodies(self):
        for a,(first,second) in subject.BRANCHES.items():
            baseline=subject.parameters(self.data,a)
            for site,physical,head in [(first,[4,4],0),(second,[4,4],1)]:
                changed=self.mutate(site,0x76);p=subject.parameters(changed,a)
                self.assertFalse(subject.ordered(baseline,physical,head,2));self.assertTrue(subject.ordered(p,physical,head,2))
                with self.assertRaisesRegex(ValueError,'strict unsigned relation changed'):subject.analyze(changed)
            for site,physical,head in [(first,[(1<<63)-1,1<<63],0),(second,[1<<63,(1<<63)-1],1)]:
                changed=self.mutate(site,0x7c);p=subject.parameters(changed,a)
                self.assertTrue(subject.ordered(baseline,physical,head,2));self.assertFalse(subject.ordered(p,physical,head,2))
                with self.assertRaisesRegex(ValueError,'strict unsigned relation changed'):subject.analyze(changed)

    def test_actual_backedges_cross_boundary_loads_and_provider_bindings(self):
        for a,(first,second) in subject.BRANCHES.items():
            for va in [first+1,second+1]:
                with self.assertRaisesRegex(ValueError,'backedge changed'):subject.analyze(self.mutate(va))
            with self.assertRaisesRegex(ValueError,'convergence changed'):subject.analyze(self.mutate(first+3))
            for va in [first-8,first-5,second-12,second-8,second-1]:
                with self.assertRaisesRegex(ValueError,'comparison/load/advance changed'):subject.analyze(self.mutate(va))
        for o in self.spec['owners']:
            for site in o['direct_calls']:
                with self.assertRaisesRegex(ValueError,'direct call changed'):subject.analyze(self.mutate(int(site)+1))
            for site,row in o['rip_bindings'].items():
                with self.assertRaisesRegex(ValueError,'RIP binding changed'):subject.analyze(self.mutate(int(site)+len(bytes.fromhex(row['prefix']))))

    def test_source_diagnostic_relocations_fde_and_raw_metadata_controls(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in self.spec['relocations']:
            changed=bytearray(self.data);changed[offsets[int(slot)]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(changed)
        for va in [0x4424eb,0x6484000]:
            with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(va))
        with self.assertRaisesRegex(ValueError,'diagnostic anchor changed'):subject.analyze(self.mutate(0x7c958c))
        for o in self.report['owners']:
            fde=int(o['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(fde+12))
            with self.assertRaisesRegex(ValueError,'dataflow changed'):subject.analyze(self.mutate(int(o['start'],16)+5))

    def test_public_identity_gate_precedes_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out';p.write_bytes(self.mutate(0x2923d30))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
