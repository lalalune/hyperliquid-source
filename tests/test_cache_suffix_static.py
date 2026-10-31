"""Native target evidence and actual selector-constant counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cache_suffix_static as subject
from elf_index import sections


class CacheSuffixTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),2940)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_actual_literal_equality_has_one_special_ten_byte_key(self):
        c=subject.selector_constants(subject.read(self.data,0x59429e0,350)[1])
        key=b'abci_state'
        self.assertTrue(subject.matches_selector(c,key))
        for index in range(10):
            for bit in range(8):
                bad=bytearray(key);bad[index]^=1<<bit
                self.assertFalse(subject.matches_selector(c,bad))
        for bad in [b'',key[:-1],key+b'\0',b'ABCI_STATE',b'abci_state_extra',b'node_metadata',b'node_artifact_2']:
            self.assertFalse(subject.matches_selector(c,bad))
        self.assertEqual([x['suffix'] for x in self.report['concrete_consumers']],['json','json'])

    def test_actual_key_and_selected_pointer_counterfactuals(self):
        changed=self.mutate(0x5942a09,ord('b'))  # MOVABS first key byte
        c=subject.selector_constants(subject.read(changed,0x59429e0,350)[1])
        self.assertFalse(subject.matches_selector(c,b'abci_state'))
        self.assertTrue(subject.matches_selector(c,b'bbci_state'))
        with self.assertRaisesRegex(ValueError,'key condition'):
            subject.analyze(changed)
        changed=self.mutate(0x5942a27)  # actual RIP displacement to rmp
        layout=subject.suffix_layout(subject.read(changed,0x59429e0,350)[1])
        self.assertNotEqual(layout['special_pointer'],0x9382b9)
        with self.assertRaisesRegex(ValueError,'pointer/length layout'):
            subject.analyze(changed)
        for va in [0x5942a1b,0x5942a3c,0x5942a7b]:
            with self.assertRaisesRegex(ValueError,'key condition|layout|conditional pointer/length'):
                subject.analyze(self.mutate(va))

    def test_real_argument_callbacks_caller_condition_and_descriptor_controls(self):
        sites=[0x5942a34,0x5942a37,0x5942a93,0x5942a9a,0x5942ad0,0x5942ae2,
               0x5616325,0x5616329,0x58621b6,0x58621ba,0x4ec71d5]
        for va in sites:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'dataflow|conditional'):
                    subject.analyze(self.mutate(va))
        for va in [0x9382b9,0x459f60,0x43d026,0x44f619]:
            with self.assertRaisesRegex(ValueError,'descriptor|suffix'):
                subject.analyze(self.mutate(va))
        for va in [0x595b003,0x4ec7247,0x595b010,0x4ec7257]:
            with self.assertRaisesRegex(ValueError,'LEA|selector call'):
                subject.analyze(self.mutate(va))

    def test_real_relocation_location_and_fde_controls(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in list(subject.BINDINGS)+list(subject.KEYS)+[0x64b6778]:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation|fat string|Location'):
                subject.analyze(changed)
        for owner in self.report['owners']:
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x5942a09))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())
