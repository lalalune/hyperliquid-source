"""Native target evidence and actual byte-arm counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import field_adapter_byte_arm_static as subject
from elf_index import sections


class FieldAdapterByteArmTests(unittest.TestCase):
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
        self.assertEqual(self.report['owner']['bytes'],95)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ['byte_arm.objdump.txt','frames.txt','records.json'])
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_owner_identity(self):
        owner=self.report['owner']
        self.assertEqual((owner['start'],owner['end'],owner['sha256']),
                         ('0x1686b70','0x1686bcf',subject.OWNER[2]))
        self.assertEqual(owner['file_offset'],'0x1685b70')
        self.assertFalse(self.report['captured_code_executed'])

    def test_table_and_census_facts(self):
        table=self.report['adapter_table']
        self.assertEqual(table['va'],'0x64078f8')
        self.assertEqual(table['header_words'],['0x0','0x18','0x8'])
        self.assertEqual([(s['offset'],s['slot'],s['target']) for s in table['slots']],
                         [(24,'0x6407910','0x1686bd0'),(32,'0x6407918','0x1686b70'),
                          (40,'0x6407920','0x168aa10')])
        self.assertEqual(self.report['census'],
                         {'direct_callers':0,'relocation_references':['0x6407918'],
                          'raw_va_occurrences':1})
        protocol=self.report['protocol']
        self.assertEqual(protocol['state'],{'data_offset':'0x0','table_offset':'0x8',
                                            'flag_pointer_offset':'0x10'})
        self.assertEqual(protocol['indent']['literal'],'    ')
        self.assertEqual(protocol['indent']['length'],4)
        self.assertEqual(protocol['indent']['method_offset'],'0x18')
        self.assertEqual(protocol['byte_tail']['method_offset'],'0x20')
        self.assertEqual(protocol['error_return']['result'],'AL = 1')
        self.assertFalse(protocol['error_return']['flag_written'])

    def test_truth_table_rows(self):
        rows=self.report['truth_table']
        self.assertEqual(len(rows),6)
        by_key={(r['flag_set'],r['indent_al'],r['byte']):r for r in rows}
        for byte in ['0xa','0x61']:
            row=by_key[(False,None,byte)]
            self.assertEqual((row['indent_call'],row['flag_written'],row['flag_value'],row['outcome']),
                             (False,True,byte=='0xa','tail_byte_call'))
            row=by_key[(True,0,byte)]
            self.assertEqual((row['indent_call'],row['flag_written'],row['flag_value'],row['outcome']),
                             (True,True,byte=='0xa','tail_byte_call'))
            row=by_key[(True,1,byte)]
            self.assertEqual((row['indent_call'],row['flag_written'],row['flag_value'],row['outcome']),
                             (True,False,None,'early_return_al_1'))

    def test_model_over_full_byte_domain(self):
        for byte in range(256):
            self.assertEqual(subject.byte_arm(False,0,byte),
                             {'indent_call':False,'flag_written':True,
                              'flag_value':byte==0x0a,'outcome':'tail_byte_call'})
            self.assertEqual(subject.byte_arm(True,0,byte),
                             {'indent_call':True,'flag_written':True,
                              'flag_value':byte==0x0a,'outcome':'tail_byte_call'})
            for al in [1,0x80,0xff]:
                self.assertEqual(subject.byte_arm(True,al,byte),
                                 {'indent_call':True,'flag_written':False,
                                  'flag_value':None,'outcome':'early_return_al_1'})

    def test_actual_byte_counterfactuals(self):
        cases=[(0x1686b70,'prologue'),(0x1686b7e,'state flag field'),
               (0x1686b8b,'flag branch'),(0x1686b8f,'indent literal reference'),
               (0x1686b94,'indent length'),(0x1686ba4,'indent method'),
               (0x1686bab,'indent result branch'),(0x1686bb9,'flag compare'),
               (0x1686bbd,'flag store'),(0x1686bc1,'byte method')]
        for va,label in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,label):
                    subject.analyze(self.mutate(va))

    def test_table_literal_and_frame_counterfactuals(self):
        for slot in [0x6407910,0x6407918,0x6407920]:
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);changed[self.rela_addend_offset(slot)]^=1
                with self.assertRaisesRegex(ValueError,'adapter table relocation'):
                    subject.analyze(changed)
        with self.assertRaisesRegex(ValueError,'adapter table header'):
            subject.analyze(self.mutate(0x6407900))
        with self.assertRaisesRegex(ValueError,'indent literal'):
            subject.analyze(self.mutate(0x45a128))
        fde=int(self.report['owner']['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x1686b94))
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
