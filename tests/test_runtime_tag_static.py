"""Target-bound cached-mask relation and actual caller-byte propagation controls."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import runtime_tag_static as subject
from elf_index import sections


class RuntimeTagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:raise ValueError('wrong capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data);cls.spec=subject.specification();cls.params=subject.parameters(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_full_native_regeneration_and_retained_records(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(1080,246))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_stable_cache_all_bit_classes_precedence_and_unrelated_bits(self):
        for a,b,c,d in itertools.product([0,1],repeat=4):
            m=1|(a<<19)|(b<<25)|(c<<15)|(d<<10)
            expected=4 if a and b else 3 if c else 2 if d else 1
            self.assertEqual(subject.stable_tag(self.params,m),expected)
            for bit in set(range(64))-{10,15,19,25}:
                self.assertEqual(subject.stable_tag(self.params,m|(1<<bit)),expected)
        for m in [subject.U64,1<<63,(1<<32)-1,1]:self.assertIn(subject.stable_tag(self.params,m),[1,2,3,4])
        with self.assertRaises(ValueError):subject.stable_tag(self.params,0)

    def test_real_mask_shift_and_word_sign_counterfactuals(self):
        for va,value,m in [(0x160bef3,4,(1<<19)|(1<<25)),(0x160bf06,1,(1<<19)|(1<<25)),
                           (0x160bf22,11,1<<10),(0x160bf16,0x79,1<<15)]:
            changed=self.mutate(va,value);p=subject.parameters(changed)
            self.assertNotEqual(subject.stable_tag(self.params,m),subject.stable_tag(p,m))
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_real_branch_cold_return_and_caller_tag_field_controls(self):
        for site in subject.BRANCHES:
            with self.assertRaisesRegex(ValueError,'branch transfer changed'):subject.analyze(self.mutate(site+1))
        for va in [0x160bf33,0x160bf43,0x160bf55,0x160bf58,0x160bf28,0x160bf5e]:
            with self.assertRaisesRegex(ValueError,'cold/return control changed'):subject.analyze(self.mutate(va))
        for a in subject.CALLERS:
            for off in [0xe9,0xfb,0x10c]:
                with self.assertRaisesRegex(ValueError,'caller tag/context binding changed'):subject.analyze(self.mutate(a+off))
        for o in self.spec['owners']:
            for site in o['direct_calls']:
                with self.assertRaisesRegex(ValueError,'direct call changed'):subject.analyze(self.mutate(int(site)+1))
            for site,row in o['rip_bindings'].items():
                with self.assertRaisesRegex(ValueError,'RIP binding changed'):subject.analyze(self.mutate(int(site)+len(bytes.fromhex(row['prefix']))))

    def test_real_source_relocations_and_three_fde_bounds(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in self.spec['relocations']:
            changed=bytearray(self.data);changed[offsets[int(slot)]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(changed)
        for va in [0x44ada0,0x646e9b0]:
            with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(va))
        for o in self.report['owners']:
            fde=int(o['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(fde+12))
        with self.assertRaisesRegex(ValueError,'opcode changed'):subject.analyze(self.mutate(0x160bf13))

    def test_public_identity_gate_precedes_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out';p.write_bytes(self.mutate(0x160bef3))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
