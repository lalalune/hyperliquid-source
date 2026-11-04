"""Original instruction, reciprocal-proof and independent-point controls."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-014-raw-threshold-115'
sys.path.insert(0,str(PACKET))
spec=importlib.util.spec_from_file_location('raw_threshold_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
fspec=importlib.util.spec_from_file_location('raw_threshold_freeze115',PACKET/'freeze.py')
f=importlib.util.module_from_spec(fspec);fspec.loader.exec_module(f)

class RawThresholdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.record=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_frozen_independent_point_results(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.record['expected_sha256'])
        self.assertEqual(len(set(inputs.splitlines())),self.record['rows'])
        self.assertEqual(sorted(seen),self.record['visited_addresses'])

    def test_eleven_actual_cow_controls(self):
        rows=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(rows),11)
        for c in rows:
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

    def test_all_u64_proof_is_bound_to_original_literal(self):
        proof=f.reciprocal_proof(self.im)
        self.assertEqual(proof,self.record['proof'])
        self.assertEqual(proof['reduced_divisor']*256,proof['divisor'])
        self.assertGreater(proof['delta'],0)
        self.assertLess(proof['max_error_numerator'],proof['bound'])
        changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
        try:
            changed.data[changed.view.offset(0x2a824f1)]=0x52
            with self.assertRaisesRegex(ValueError,'literal/proof'):f.reciprocal_proof(changed)
        finally:changed.close()

    def test_decoder_selected_denominator_and_owner(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seen=set()
        for a,b in n.RANGES:
            rows=list(cs.disasm(self.im.view.read(a,b-a),a));self.assertEqual(sum(x.size for x in rows),b-a)
            for x in rows:
                self.assertEqual(self.im.fetch(x.address).size,x.size);seen.add(x.address)
        self.assertEqual(len(seen),24)
        self.assertEqual(seen,set(self.record['visited_addresses']))
        self.assertEqual(sum(b-a for a,b in n.RANGES),112)
        self.assertEqual(self.im.view.fde(n.ENTRIES[0]),(0x2a82220,0x2a825b2))

    def test_frontiers_order_and_no_opaque_effects(self):
        U=n.cpu.U64
        self.assertEqual(n.evaluate(self.im,(0,U,1,1,0,1000))[0],'A')
        self.assertEqual(n.evaluate(self.im,(1,U,1,1,0,1000))[0],'B')
        self.assertEqual(n.evaluate(self.im,(1,U,1,0,0,1000))[0],'V:36893488147:5000:9223372036854775835')
        self.assertEqual(n.evaluate(self.im,(2,1<<32,0,0,0,1001))[0],'V:8:1008:9223372036854775835')
        m=n.Machine(self.im)
        for a,size in [(n.SLOT-1,1),(n.SLOT+8,1),(n.SLOT+7,2)]:
            with self.assertRaisesRegex(ValueError,'footprint'):m.load(a,size)
        for method in [m.store,m.spill]:
            with self.assertRaisesRegex(ValueError,'write forbidden'):method()
        with self.assertRaisesRegex(ValueError,'handler forbidden'):m.call()
        for a in [n.END,n.SUM_DIAG,n.SECOND_DIAG]:
            with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(a)
        with self.assertRaisesRegex(ValueError,'canonical'):n.evaluate(self.im,(2,1,1,0,0,1000))

    def test_digest_rejection_without_assertions(self):
        r=subprocess.run([sys.executable,'-O','-c',"import native; native.SHA='0'*64; native.verify()"],cwd=PACKET,capture_output=True)
        self.assertNotEqual(r.returncode,0);self.assertIn(b'wrong115target',r.stderr)

if __name__=='__main__':unittest.main()
