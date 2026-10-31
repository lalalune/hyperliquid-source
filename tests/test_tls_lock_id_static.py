"""Static target-bound TLS key projection and native evidence controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import tls_lock_id_static as subject
from elf_index import sections


class TLSLockIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data)
        cls.report=subject.analyze(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);off=self.offset(va)
        b[off]=b[off]^1 if value is None else value
        return b

    def test_retained_and_native_regeneration(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),814)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_actual_layout_projection_and_uncompared_scalar_bytes(self):
        layout=self.report['probe_layout']
        record=bytearray(56);key=bytearray(33)
        for offset,value in [(8,3),(16,7),(24,9)]:
            struct.pack_into('<I',record,offset,value);struct.pack_into('<I',key,offset,value)
        self.assertTrue(subject.scalar_identity(layout,record,key))
        for offset in [8,16,24]:
            changed=bytearray(record);changed[offset]^=1
            self.assertFalse(subject.scalar_identity(layout,changed,key))
        for offset in [20,21,22,23,32,48,55]:
            changed=bytearray(record);changed[offset]^=1
            self.assertTrue(subject.scalar_identity(layout,changed,key))
        self.assertEqual((layout['stride_multiply'],layout['stride_increment']),(56,56))
        self.assertEqual((layout['tls_offset'],layout['borrow_limit']),(-4480,(1<<63)-1))
        # The equality predicate has a distinct external byte comparison;
        # scalar equality alone is deliberately not claimed sufficient.
        self.assertEqual(self.report['comparison_import']['symbol'],'bcmp')

    def test_real_comparator_displacement_counterfactuals_change_projection(self):
        base=0x154cd10
        record=bytearray(56);key=bytearray(33)
        for offset,value in [(8,3),(16,7),(24,9)]:
            struct.pack_into('<I',record,offset,value);struct.pack_into('<I',key,offset,value)
        for relative,old in [(0xcd,24),(0xd4,16),(0xdb,8)]:
            changed=self.mutate(base+relative,old+1)
            layout=subject.probe_layout(subject.read(changed,base,299)[1])
            self.assertFalse(subject.scalar_identity(layout,record,key))
            with self.assertRaisesRegex(ValueError,'layout'):
                subject.analyze(changed)
        for relative in [0x9d,0xc3,0x10,0x11,0x17,0x74]:
            with self.assertRaisesRegex(ValueError,'layout'):
                subject.analyze(self.mutate(base+relative))

    def test_real_counter_restore_and_caller_outcome_controls(self):
        # Source operand, ready-state check, borrow update/restore, zero/one
        # returns, caller object+0x18, branch polarity and cleanup operands.
        sites=[0x154cd2b,0x154cd85,0x154cd92,0x154cdaa,0x154ce05,0x154ce09,0x154ce1b,
               0x14c2a52,0x14c2a72,0x14c2a9d,0x14c2ac5,0x14c2ad8,
               0x14c2b62,0x14c2b82,0x14c2bad,0x14c2bc0,0x14c2bd3]
        for va in sites:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'dataflow'):
                    subject.analyze(self.mutate(va))

    def test_actual_import_call_relocation_and_fde_controls(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        rels={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in subject.BINDINGS:
            changed=bytearray(self.data);changed[rels[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):
                subject.analyze(changed)
        changed=bytearray(self.data);changed[rels[0x64df9f8]+8]^=1
        with self.assertRaisesRegex(ValueError,'bcmp'):
            subject.analyze(changed)
        for site in [0x154cdfb,0x14c2a69,0x14c2b79]:
            with self.assertRaisesRegex(ValueError,'slot'):
                subject.analyze(self.mutate(site+2))
        for owner in self.report['owners']:
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                subject.analyze(self.mutate(fde+12))

    def test_wrong_modified_truncated_public_inputs_fail_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x154cddd))
            for source in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(source,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())
