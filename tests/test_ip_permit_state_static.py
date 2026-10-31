"""Static constructor/conditional-CAS relation and actual operand controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ip_permit_state_static as subject
from elf_index import sections


class IPPermitStateTests(unittest.TestCase):
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

    def test_native_regeneration_and_retained_records(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(1811,356))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_guard_encoding_and_winning_step_boundary_relations(self):
        maximum=(1<<61)-1
        for n in [0,1,2,maximum-1,maximum]:
            self.assertTrue(subject.guard_passes(self.params,n))
            word=2*n
            self.assertEqual(word&1,0)
            self.assertLess(word,1<<62)
            kind,after=subject.attempt_projection(self.params,word)
            self.assertEqual((kind,after),('eligible',2*(n-1)) if n else ('empty-gate',0))
        for n in [maximum+1,1<<63,subject.U64]:self.assertFalse(subject.guard_passes(self.params,n))
        for word in [1,3,5,(1<<62)-1,subject.U64]:
            self.assertEqual(subject.attempt_projection(self.params,word),('flag-gate',word))
        for word in [2,4,(1<<62)-2,subject.U64-1]:
            kind,after=subject.attempt_projection(self.params,word)
            self.assertEqual(kind,'eligible');self.assertEqual(after&1,0)
            self.assertEqual((word>>1)-(after>>1),1)

    def test_real_shift_mask_threshold_and_step_counterfactuals(self):
        changed=self.mutate(0x4771101,62);p=subject.parameters(changed)
        self.assertFalse(subject.guard_passes(self.params,1<<61))
        self.assertTrue(subject.guard_passes(p,1<<61))
        with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
        changed=self.mutate(0x4770f85,0xfc);p=subject.parameters(changed)
        self.assertEqual(subject.attempt_projection(self.params,4),('eligible',2))
        self.assertEqual(subject.attempt_projection(p,4),('eligible',0))
        with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
        changed=self.mutate(0x4770f71,2);p=subject.parameters(changed)
        self.assertEqual(subject.attempt_projection(p,2)[0],'flag-gate')
        with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
        changed=self.mutate(0x4770f7b,4);p=subject.parameters(changed)
        self.assertEqual(subject.attempt_projection(p,2)[0],'empty-gate')
        with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_actual_guard_retry_init_output_and_followup_operands(self):
        for va in [0x4771103,0x4770f73,0x4770f7d,0x4770f8d]:
            with self.assertRaisesRegex(ValueError,'transfer'):subject.analyze(self.mutate(va))
        for va in [0x4770f65,0x4771148,0x4770f8b]:
            with self.assertRaisesRegex(ValueError,'relation'):subject.analyze(self.mutate(va))
        for va in [0x4771129,0x477112e,0x4771136,0x4770f53,0x4770fff,0x4771000,0x477103b,0x477104b,0x4771064]:
            with self.assertRaisesRegex(ValueError,'opcode|dataflow'):subject.analyze(self.mutate(va))
        for site in subject.DIRECT:
            with self.assertRaisesRegex(ValueError,'call changed'):subject.analyze(self.mutate(site+1))

    def test_real_source_code_relocations_and_fde_extents(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in subject.BINDINGS:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):subject.analyze(changed)
        for va in [0x6496558,0x6496570]:
            with self.assertRaisesRegex(ValueError,'Location'):subject.analyze(self.mutate(va))
        for owner in self.report['owners']:
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):subject.analyze(self.mutate(fde+12))

    def test_public_identity_gate_rejects_modified_truncated_and_other_release(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x4770f85))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
