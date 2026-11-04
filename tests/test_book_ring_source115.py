"""Correct the cached-word misattribution using actual original ring stores."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-006-book-ring-source-fix-115'
sys.path.insert(0,str(PACKET));sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('book_ring_source_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
import book_ring_append_static as book

class BookRingSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.proof=json.loads((PACKET/'proof.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_attribution_matches_original_and_old_claim_fails(self):
        report=json.loads((book.PACKET/'records.json').read_text())
        observed=n.check_declared_source(report)
        self.assertEqual([x['actual_field0'] for x in observed],[17,17])
        self.assertEqual([x['declared_prediction'] for x in observed],[17,17])
        report['trace']['append']['element_fields'][0]['source']='the qword cached at level +0x28'
        with self.assertRaisesRegex(ValueError,'declared_prediction.*900'):
            n.check_declared_source(report)

    def test_five_real_source_flow_sites_in_both_twins(self):
        for base in n.BASES:
            body=self.im.view.read(base,663);origin=book.element0_origin(body,base)
            self.assertEqual(origin['object'],'order');self.assertEqual(origin['offset'],'0xf0')
            self.assertEqual(origin['saved_stack_offset'],'0x30');self.assertEqual(origin['carrier'],'r15')
            self.assertEqual(len(origin['sites']),5)
            for offset in [0x17,0x41,0xf0,0x1c3,0x232]:
                changed=bytearray(body);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'Element0 source flow'):
                    book.element0_origin(changed,base)

    def test_shared_argument_pointer_is_only_fixed_on_zero_arm(self):
        report=json.loads((book.PACKET/'records.json').read_text())
        sources=report['trace']['append_arm']['shared_word_sources']
        self.assertEqual(sources['zero_derivation'],{'base':'level','offset':'0x28'})
        self.assertEqual(sources['nonzero_derivation']['pointee_identity'],'unclosed')
        for name,spec in book.OWNERS.items():
            base=spec['range'][0];body=self.im.view.read(base,663)
            book.owner_trace(body,base,spec)
            self.assertEqual(body[0x16f:0x173],bytes.fromhex('498d5628'))
            self.assertEqual(body[0x173:0x176],bytes.fromhex('4c8b3a'))
            self.assertEqual(body[0x106:0x108],bytes.fromhex('eb6b'))

    def test_complete_snapshot_stream_and_alias_agreement(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())),self.proof['rows'])
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.proof['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.proof['expected_sha256'])
        self.assertEqual(sorted(seen),self.proof['visited_addresses'])
        rows=n.stimuli();values=expected.decode().splitlines();half=len(rows)//2
        self.assertEqual(values[:half],values[half:])

    def test_twelve_actual_instruction_corruptions(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),12)
        for c in controls:
            with self.subTest(name=c['name'],alias=c['alias']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    a=int(c['va'],16);offset=changed.view.offset(a)
                    self.assertEqual(bytes([changed.data[offset]]).hex(),c['original_byte'])
                    changed.data[offset]=int(c['changed_byte'],16)
                    self.assertEqual(n.evaluate(self.im,c['input'])[0],c['original'])
                    self.assertEqual(n.evaluate(changed,c['input'])[0],c['changed'])
                    self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_actual_slot_padding_and_grow_boundaries(self):
        for alias in [0,1]:
            self.assertEqual(n.evaluate(self.im,(alias,0,0,0,17,900))[0],'G')
            self.assertEqual(n.evaluate(self.im,(alias,2,1,2,17,900))[0],'G')
            value,_=n.evaluate(self.im,(alias,2,1,0,17,900));buffer=bytes.fromhex(value.split(':')[2])
            for slot in range(2):
                start=slot*32+28
                self.assertEqual(buffer[start:start+4],bytes((165+17*i)&255 for i in range(start,start+4)))
        m=n.Machine(self.im,2)
        with self.assertRaisesRegex(ValueError,'forbidden'):m.call()

    def test_selected_decode_and_containing_identities(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);starts=set()
        for owner in self.proof['owners']:
            base=int(owner['start'],16)
            self.assertEqual(self.im.view.fde(base),(base,base+663))
            self.assertEqual(hashlib.sha256(self.im.view.read(base,663)).hexdigest(),owner['sha256'])
            for lo,hi in [(0x1f0,0x204),(0x212,0x259)]:
                rows=list(cs.disasm(self.im.view.read(base+lo,hi-lo),base+lo))
                self.assertEqual(sum(x.size for x in rows),hi-lo)
                for x in rows:self.assertEqual(self.im.fetch(x.address).size,x.size);starts.add(x.address)
        self.assertEqual(starts,set(self.proof['visited_addresses']))

if __name__=='__main__':unittest.main()
