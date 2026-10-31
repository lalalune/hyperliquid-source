"""Target-grounded curl builder material; never invoke curl or captured code."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import curl_options_static as subject
from elf_index import sections


class CurlOptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data);cls.spec=subject.load_spec()

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_and_scoped_denominator(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual((len(self.report['owners']),sum(x['bytes'] for x in self.report['owners']),sum(x['instructions'] for x in self.report['owners'])),(8,4342,910))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_actual_overlapping_literal_and_numeric_counterfactual_all_four(self):
        for start in subject.BUILDERS:
            body=subject.read(self.data,start,1079 if start in [0x15354f0,0x4e4bdb0] else 1053)[1]
            self.assertEqual(subject.default_fragment(body),b' --max-time 300')
            changed=self.mutate(start+0x50,ord('1'))
            body=subject.read(changed,start,len(body))[1]
            self.assertEqual(subject.default_fragment(body),b' --max-time 301')
            with self.assertRaisesRegex(ValueError,'default option literal'):
                subject.analyze(changed)
            with self.assertRaisesRegex(ValueError,'overlapping'):
                subject.analyze(self.mutate(start+0x57+7))
        self.assertIn(b' --connect-timeout ',subject.LITERALS[0x43fecd])
        self.assertNotIn(b'--max-time',subject.LITERALS[0x43fecd])

    def test_real_input_default_sizes_and_presence_gate_controls(self):
        for start in subject.BUILDERS:
            for relative in [0x34,0x67,0x75,0x2e,0x32,0x7b]:
                with self.subTest(start=hex(start),relative=hex(relative)):
                    with self.assertRaisesRegex(ValueError,'length|gate'):
                        subject.analyze(self.mutate(start+relative))

    def test_real_templates_references_callbacks_and_calls(self):
        for address in subject.LITERALS:
            with self.assertRaisesRegex(ValueError,'descriptor'):
                subject.analyze(self.mutate(address+1))
        for owner in self.spec['owners'][:4]:
            # Actual connect descriptor and actual bound source Location LEAs.
            for target in ['0x43fecd','0x63fd790','0x649db18']:
                refs=[r for r in owner['references'] if r['target']==target]
                for r in refs:
                    with self.assertRaisesRegex(ValueError,'operand'):
                        subject.analyze(self.mutate(int(r['site'],16)+3))
        for owner in self.spec['owners'][4:]:
            with self.assertRaisesRegex(ValueError,'dataflow'):
                subject.analyze(self.mutate(int(owner['start'],16)+5))

    def test_real_relocations_formatter_objects_and_fde_extents(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in [0x64df6f0,0x64df6e8,0x64e0a98,0x64df720,0x63fd790,0x649db18,0x63fd778,0x649dab8]:
            changed=bytearray(self.data);changed[offsets[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):
                subject.analyze(changed)
        for va in [0x63fd768,0x649daa8]:
            with self.assertRaisesRegex(ValueError,'formatter object'):
                subject.analyze(self.mutate(va))
        for owner in self.report['owners']:
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            p.write_bytes(self.mutate(subject.BUILDERS[0]+0x50))
            for path in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())
