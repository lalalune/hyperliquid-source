"""Correct the raw qword/low32 misdescription with original compute points."""
import copy
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-005-reader-budget-tag-width-115'
sys.path.insert(0,str(PACKET));sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('budget_tag_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
import limit_writers_static as producer

class ReaderBudgetTagWidthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.report=json.loads((producer.PACKET/'records.json').read_text())
        cls.proof=json.loads((PACKET/'proof.json').read_text())
        cls.before_after=json.loads((PACKET/'before-after.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_same_actual_counterexample_before_and_after(self):
        observed=n.check_declared_source(self.report)
        self.assertEqual([r['actual'] for r in observed],[10000,10000])
        self.assertEqual([r['declared_prediction'] for r in observed],[10000,10000])
        with self.assertRaisesRegex(ValueError,'declared_prediction.*100000000'):
            n.check_declared_source(self.before_after['old_declared_contract'])
        wrong=copy.deepcopy(self.report)
        for role in ['twin_a','twin_b']:
            condition=wrong['dispatchers'][role]['tag_conditions'][1]
            condition.update(mask='0xffffffffffffffff',operand_bits=64,register='rcx')
        with self.assertRaisesRegex(ValueError,'declared_prediction.*100000000'):n.check_declared_source(wrong)

    def test_actual_widths_and_ordered_conditions(self):
        for alias,role in enumerate(['top_twin_a','top_twin_b']):
            conditions=producer.tag_conditions(self.im.data,role)
            self.assertEqual([c['operand_bits'] for c in conditions],[64,32])
            self.assertEqual([c['register'] for c in conditions],['rcx','ecx'])
            self.assertEqual([c['equal'] for c in conditions],[2,1])
            self.assertEqual(conditions,self.report['dispatchers'][['twin_a','twin_b'][alias]]['tag_conditions'])
            for tag,value in [(2,120),(1,10000),(0x100000001,10000),(0xffffffff00000001,10000),(0x100000002,100000000)]:
                self.assertEqual(n.evaluate(self.im,(alias,tag,0,9))[0],value)

    def test_certificate_changes_with_real_cmp_width_byte(self):
        for alias,role,address in [(0,'top_twin_a',0x2b6a7d9),(1,'top_twin_b',0x5a6b62a)]:
            changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
            try:
                off=changed.view.offset(address);self.assertEqual(changed.data[off],0x48);changed.data[off]=0x40
                conditions=producer.tag_conditions(changed.data,role);self.assertEqual(conditions[0]['operand_bits'],32)
                report=copy.deepcopy(self.report);report['dispatchers'][['twin_a','twin_b'][alias]]['tag_conditions']=conditions
                row=(alias,0x100000002,0,9)
                self.assertEqual(n.evaluate(changed,row)[0],120);self.assertEqual(n.declared_prediction(report,*row),120)
                changed.data[off]=0x49
                with self.assertRaisesRegex(ValueError,'register extension'):producer.tag_conditions(changed.data,role)
            finally:changed.close()

    def test_complete_readonly_corpus_and_alias_agreement(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())),302)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.proof['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.proof['expected_sha256'])
        self.assertEqual(sorted(seen),self.proof['visited_addresses'])
        lines=expected.decode().splitlines();self.assertEqual(lines[:151],lines[151:])
        for row,value in zip(n.stimuli(),lines):self.assertEqual(n.declared_prediction(self.report,*row),int(value))
        with self.assertRaisesRegex(ValueError,'forbidden'):n.Machine(self.im,n.SPECS[0]).call()
        with self.assertRaisesRegex(ValueError,'forbidden'):n.Machine(self.im,n.SPECS[0]).store(n.SOURCE,8,0)

    def test_sixteen_real_compute_corruptions(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),16)
        for c in controls:
            with self.subTest(name=c['name'],alias=c['alias']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    a=int(c['va'],16);off=changed.view.offset(a);self.assertEqual(changed.data[off],int(c['original_byte'],16))
                    changed.data[off]=int(c['changed_byte'],16);row=tuple(c['input'])
                    self.assertEqual(n.evaluate(self.im,row)[0],c['original']);self.assertEqual(n.evaluate(changed,row)[0],c['changed']);self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_full_owners_unwind_and_selected_decode(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);selected=[]
        self.assertEqual(sum(o['bytes'] for o in self.proof['owners']),10985)
        for owner,s in zip(self.proof['owners'],n.SPECS):
            lo,hi=int(owner['start'],16),int(owner['end'],16);self.assertEqual(self.im.view.fde(lo),(lo,hi))
            raw=self.im.view.read(lo,hi-lo);self.assertEqual(hashlib.sha256(raw).hexdigest(),owner['sha256'])
            rows=list(cs.disasm(raw,lo));self.assertEqual(sum(i.size for i in rows),hi-lo);self.assertEqual(len(rows),owner['instructions'])
            selected.extend(i for i in rows if s['start']<=i.address<s['end'])
            for record in owner['unwind'].values():
                raw=bytes.fromhex(record['raw_hex']);self.assertEqual(self.im.view.read(int(record['va'],16),len(raw)),raw)
        self.assertEqual(sum(i.size for i in selected),199);self.assertEqual(len(selected),50)
        self.assertEqual({i.address for i in selected},set(self.proof['visited_addresses']))
        for i in selected:self.assertEqual(self.im.fetch(i.address).size,i.size)

    def test_original_native_exports_remain_identical(self):
        for name,digest in self.before_after['original_native_exports'].items():
            self.assertEqual(hashlib.sha256((producer.PACKET/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(self.before_after['before']['exit'],1)
        self.assertEqual(self.before_after['after']['exit'],0)

if __name__=='__main__':unittest.main()
