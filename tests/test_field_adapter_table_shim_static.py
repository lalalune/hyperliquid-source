"""Native target evidence and actual shim counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import field_adapter_table_shim_static as subject
from elf_index import sections


class FieldAdapterTableShimTests(unittest.TestCase):
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

    def rela_addend_offset(self,slot):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        blob=self.data[sec['offset']:sec['offset']+sec['size']]
        for index,(a,i,v) in enumerate(struct.iter_unpack('<QQq',blob)):
            if a==slot:
                return sec['offset']+index*24+16
        raise AssertionError('slot not found')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(self.report['owner']['bytes'],19)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ['frames.txt','records.json','shim.objdump.txt'])
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_owner_identity(self):
        owner=self.report['owner']
        self.assertEqual((owner['start'],owner['end'],owner['sha256']),
                         ('0x168aa10','0x168aa23',subject.OWNER[2]))
        self.assertEqual(owner['file_offset'],'0x1689a10')
        self.assertFalse(self.report['captured_code_executed'])

    def test_table_tail_and_census_facts(self):
        table=self.report['adapter_table']
        self.assertEqual(table['va'],'0x64078f8')
        self.assertEqual(table['header_words'],['0x0','0x18','0x8'])
        self.assertEqual([(s['offset'],s['slot'],s['target']) for s in table['slots']],
                         [(24,'0x6407910','0x1686bd0'),(32,'0x6407918','0x1686b70'),
                          (40,'0x6407920','0x168aa10')])
        self.assertEqual(self.report['tail'],
                         {'jump_site':'0x168aa1d','bytes':'ff25cd4ce504','slot':'0x64df6f0',
                          'target':'0x1680500','relocation_type':8,
                          'note':self.report['tail']['note']})
        self.assertEqual(self.report['census'],
                         {'direct_callers':0,'direct_jumps':0,
                          'relocation_references':['0x6407920'],'raw_va_occurrences':1})
        transformation=self.report['transformation']
        self.assertEqual(transformation['insertion']['value'],'0x64078f8')
        self.assertEqual(transformation['insertion']['register'],'rsi (argument 2)')
        self.assertEqual([m['to'] for m in transformation['moves']],
                         ['rcx (argument 4)','rdx (argument 3)'])

    def test_argument_transformation(self):
        rows=self.report['argument_rows']
        self.assertEqual(rows[0]['inputs'],['a1','a2','a3','a4','a5','a6'])
        self.assertEqual(rows[0]['outputs'],
                         {'rdi':'a1','rsi':'0x64078f8','rdx':'a2','rcx':'a3','r8':'a5','r9':'a6'})
        marks=[0x1111111111111111,0x2222222222222222,0x3333333333333333,
               0x4444444444444444,0x5555555555555555,0x6666666666666666]
        out=subject.transform(*marks)
        self.assertEqual(out,{'rdi':marks[0],'rsi':subject.TABLE,'rdx':marks[1],
                              'rcx':marks[2],'r8':marks[4],'r9':marks[5]})
        self.assertNotIn(marks[3],out.values())
        for values in [(0,0,0,0,0,0),('x','y','z','w','v','u')]:
            out=subject.transform(*values)
            self.assertEqual((out['rdi'],out['rdx'],out['rcx'],out['r8'],out['r9']),
                             (values[0],values[1],values[2],values[4],values[5]))
            self.assertEqual(out['rsi'],subject.TABLE)

    def test_actual_byte_counterfactuals(self):
        cases=[(0x168aa10,'argument 3 to 4 shift'),(0x168aa15,'argument 2 to 3 shift'),
               (0x168aa17,'table insertion'),(0x168aa19,'table insertion reference'),
               (0x168aa1e,'tail jump'),(0x168aa20,'tail jump slot')]
        for va,label in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,label):
                    subject.analyze(self.mutate(va))

    def test_table_tail_and_frame_counterfactuals(self):
        for slot in [0x6407910,0x6407918,0x6407920]:
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);changed[self.rela_addend_offset(slot)]^=1
                with self.assertRaisesRegex(ValueError,'adapter table relocation'):
                    subject.analyze(changed)
        changed=bytearray(self.data);changed[self.rela_addend_offset(0x64df6f0)]^=1
        with self.assertRaisesRegex(ValueError,'tail slot relocation'):
            subject.analyze(changed)
        with self.assertRaisesRegex(ValueError,'adapter table header'):
            subject.analyze(self.mutate(0x6407900))
        fde=int(self.report['owner']['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x168aa19))
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
