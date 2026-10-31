"""Actual six-body selector/dispatch and semantic operand corruption controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import snapshot_selection_static as subject
from elf_index import sections


class SnapshotSelectionTests(unittest.TestCase):
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
        self.assertEqual((sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(9438,1922))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_neg_overflow_selector_and_unsigned_count_boundaries(self):
        for a in subject.MAINS:
            p=subject.parameters(self.data,a)
            for word in [0,1,(1<<63)-1,(1<<63)+1,subject.U64]:
                for n in range(102):
                    self.assertEqual(subject.local_route(p,word,n),'explicit-selection-route' if n<=100 else 'diagnostic-route')
                self.assertEqual(subject.local_route(p,word,subject.U64),'diagnostic-route')
            for n in [0,1,100,101,subject.U64]:
                self.assertEqual(subject.local_route(p,1<<63,n),'all-collection-route')
            self.assertEqual(p['all_count_offset']-p['all_buffer_offset'],8)
            self.assertEqual(p['all_stride'],1296)

    def test_real_threshold_overflow_condition_and_mode_counterfactuals(self):
        for a in subject.MAINS:
            baseline=subject.parameters(self.data,a)
            changed=self.mutate(a+0x47b,102);p=subject.parameters(changed,a)
            self.assertEqual(subject.local_route(baseline,0,101),'diagnostic-route')
            self.assertEqual(subject.local_route(p,0,101),'explicit-selection-route')
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
            changed=self.mutate(a+0x23,0x80);p=subject.parameters(changed,a)
            self.assertNotEqual(subject.local_route(baseline,1<<63,101),subject.local_route(p,1<<63,101))
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
            changed=self.mutate(a+0x440,2);p=subject.parameters(changed,a)
            self.assertTrue(1==baseline['mode_equal']);self.assertFalse(1==p['mode_equal'])
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_actual_branch_wrapper_context_and_call_binding_controls(self):
        for a in subject.MAINS:
            for off in [0x24,0x47e,0x448]:
                with self.assertRaisesRegex(ValueError,'transfer changed'):subject.analyze(self.mutate(a+off))
            for off in [0x35,0x3c,0x40,0x5f3]:
                with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(self.mutate(a+off))
        for a in subject.WRAPPERS:
            for off in [0x15,0x1f,0x25,0x2f,0x50,0x8e]:
                with self.assertRaisesRegex(ValueError,'normalization changed'):subject.analyze(self.mutate(a+off))
        for o in self.spec['owners']:
            # Every selected call/LEA is independently native-instruction-bound.
            for site in o['direct_calls']:
                with self.assertRaisesRegex(ValueError,'direct call changed'):subject.analyze(self.mutate(int(site)+1))
            site,row=next(iter(o['rip_bindings'].items()))
            with self.assertRaisesRegex(ValueError,'RIP binding changed'):subject.analyze(self.mutate(int(site)+len(bytes.fromhex(row['prefix']))))

    def test_real_source_relocations_and_six_fde_bounds(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in self.spec['relocations']:
            changed=bytearray(self.data);changed[offsets[int(slot)]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(changed)
        with self.assertRaisesRegex(ValueError,'source path changed'):subject.analyze(self.mutate(0x4318ae))
        for a in [0x642cd18,0x642cd30]:
            with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(a+16))
        for o in self.report['owners']:
            fde=int(o['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(fde+12))

    def test_public_identity_gate_precedes_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out';p.write_bytes(self.mutate(subject.MAINS[0]+0x47b))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(p,out)
            self.assertFalse(out.exists())
