"""Actual selected-row point replay, native RETs and corruption controls."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-007-margin-row-115'
sys.path.insert(0,str(PACKET))
spec=importlib.util.spec_from_file_location('margin_row_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class MarginRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.record=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_frozen_independent_point_stream(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.record['expected_sha256'])
        self.assertEqual(len(set(inputs.splitlines())),5647)
        self.assertEqual(sorted(seen),self.record['visited_addresses'])

    def test_fifteen_actual_byte_controls(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),15)
        for c in controls:
            with self.subTest(name=c['name']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    address=int(c['va'],16);offset=changed.view.offset(address)
                    self.assertEqual(bytes([changed.data[offset]]).hex(),c['original_byte'])
                    changed.data[offset]=int(c['changed_byte'],16)
                    self.assertEqual(n.evaluate(self.im,c['input'])[0],c['original'])
                    self.assertEqual(n.evaluate(changed,c['input'])[0],c['changed'])
                    self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_selected_and_full_context_extents(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seen=set()
        for a,b in n.RANGES:
            rows=list(cs.disasm(self.im.view.read(a,b-a),a));self.assertEqual(sum(x.size for x in rows),b-a)
            for x in rows:self.assertEqual(self.im.fetch(x.address).size,x.size);seen.add(x.address)
        self.assertEqual(len(seen),56);self.assertEqual(sum(b-a for a,b in n.RANGES),179)
        self.assertEqual(seen,set(self.record['visited_addresses']))
        self.assertEqual(self.im.view.fde(n.ENTRIES[0]),(0x38b54b0,0x38b55f3))
        self.assertEqual(self.im.view.fde(n.ENTRIES[1]),(0x38b5300,0x38b54a9))
        self.assertEqual(sum(x['bytes'] for x in self.record['owners']),748)
        self.assertEqual(sum(x['instructions'] for x in self.record['owners']),187)
        for owner in self.record['owners']:
            self.assertEqual(hashlib.sha256(self.im.view.read(int(owner['start'],16),owner['bytes'])).hexdigest(),owner['sha256'])

    def test_sealed_boundaries_and_fresh_point_distinction(self):
        cases=[((0,5,1,2),'V:0'),((0,5,1,3),'B'),((1,5,1,1),'V:1'),
               ((1,0,1,1<<62),'B'),((2,0,1,1<<62),'V:0'),
               ((2,0,1,0),'V:3074457345618258602'),((1,1<<63,1,0),'H')]
        for row,expected in cases:self.assertEqual(n.evaluate(self.im,row)[0],expected)

    def test_no_callback_writes_or_invalid_point_premises(self):
        m=n.Machine(self.im)
        for method in [m.store,m.spill]:
            with self.assertRaisesRegex(ValueError,'write forbidden'):method()
        with self.assertRaisesRegex(ValueError,'opaque call'):m.call()
        for address,size in [(n.ROW-17,1),(n.ROW,1),(n.cpu.STACK+0x70,1)]:
            with self.assertRaisesRegex(ValueError,'footprint'):m.load(address,size)
        for address in [*n.FRONTIERS,0x38b54b0,0x38b5300]:
            with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(address)
        for row in [(0,1,0,0),(2,1,1,0),(3,0,1,0)]:
            with self.assertRaisesRegex(ValueError,'canonical'):n.evaluate(self.im,row)
        self.assertIsNone(m.get(n.cpu.RBX,64))

    def test_wrong_digest_rejected_without_assertions(self):
        r=subprocess.run([sys.executable,'-O','-c',"import native; native.SHA='0'*64; native.verify()"],cwd=PACKET,capture_output=True)
        self.assertNotEqual(r.returncode,0);self.assertIn(b'wrong115target',r.stderr)

if __name__=='__main__':unittest.main()
