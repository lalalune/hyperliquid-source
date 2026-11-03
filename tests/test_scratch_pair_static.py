"""Native target evidence and actual accessor-constant counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import scratch_pair_static as subject
from elf_index import sections


class ScratchPairTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),11137)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_result_table_covers_all_names_with_scratch_pair_false(self):
        table=self.report['result_table']
        self.assertEqual(len(table),79)
        self.assertEqual([row['tag'] for row in table],list(range(79)))
        self.assertEqual([row['name'] for row in table],subject.NAMES)
        self.assertTrue(all(row['first']==2 for row in table))
        self.assertEqual([row['tag'] for row in table if not row['flag']],[62,63])
        for tag,name in subject.ANCHORS.items():
            self.assertEqual(table[tag]['name'],name)
        self.assertEqual(self.report['direct_callers'],0)
        self.assertEqual(self.report['relocation_cell'],'0x64f01b0')
        self.assertFalse(self.report['captured_code_executed'])

    def test_mask_algebra_over_full_byte_domain(self):
        # The classifier's producible domain is 0..78; the mask algebra is
        # asserted over the whole byte domain the accessor could read.
        for tag in range(256):
            self.assertEqual(subject.pair_for_tag(tag),(2,(tag & 0x7e)!=62))
        self.assertEqual([t for t in range(256) if not subject.pair_for_tag(t)[1]],[62,63,190,191])
        self.assertEqual([t for t in range(79) if not subject.pair_for_tag(t)[1]],[62,63])

    def test_actual_accessor_immediate_counterfactuals(self):
        # AND mask immediate, CMP immediate, MOV AL,2 immediate, tag +0x48 byte.
        for va in [0x1568d98,0x1568d9a,0x1568d9f,0x1568d96]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'accessor'):
                    subject.analyze(self.mutate(va))

    def test_scratch_name_byte_counterfactual(self):
        by_offset,_=subject.relocations(self.data)
        entries=subject.descriptor_entries(self.data,by_offset)
        pointer=entries[62]['pointer']
        self.assertEqual(entries[62]['name'],'ScratchDummy')
        with self.assertRaisesRegex(ValueError,'descriptor'):
            subject.analyze(self.mutate(pointer))

    def test_relocation_and_fde_controls(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        changed=bytearray(self.data);changed[offsets[0x64f01b0]+16]^=1
        with self.assertRaisesRegex(ValueError,'relocation'):
            subject.analyze(changed)
        changed=bytearray(self.data);changed[offsets[0x64e0918]+16]^=1
        with self.assertRaisesRegex(ValueError,'relocation'):
            subject.analyze(changed)
        fde=int(self.report['owners'][0]['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x1568d98))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
