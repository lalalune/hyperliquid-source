"""Target-pinned integer-prefix replay and real corruption controls."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-012-position-integer-115'
spec=importlib.util.spec_from_file_location('position_integer_native115',PACKET/'native.py')
sys.path.insert(0,str(PACKET))
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class PositionIntegerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.record=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_original_frozen_stream(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.record['expected_sha256'])
        self.assertEqual(len(set(inputs.splitlines())),3328)
        self.assertEqual(sorted(seen),self.record['visited_addresses'])

    def test_eleven_actual_byte_controls(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),11)
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

    def test_decode_extent_and_all_selected_starts(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seen=set()
        for a,b in n.RANGES:
            rows=list(cs.disasm(self.im.view.read(a,b-a),a))
            self.assertEqual(sum(x.size for x in rows),b-a)
            for x in rows:
                self.assertEqual(self.im.fetch(x.address).size,x.size);seen.add(x.address)
        self.assertEqual(len(seen),45);self.assertEqual(seen,set(self.record['visited_addresses']))
        self.assertEqual(sum(b-a for a,b in n.RANGES),188)
        self.assertEqual(self.im.view.fde(n.ENTRY),(0x2c7fd80,0x2c80666))

    def test_boundaries_and_actual_original_special_cases(self):
        # These raw observations predate Rust in the sealed corpus.
        self.assertEqual(n.evaluate(self.im,(1,7,0))[0],'V:7:0:N')
        self.assertEqual(n.evaluate(self.im,(3,7,7))[0],'V:21:14:32:2:1')
        self.assertEqual(n.evaluate(self.im,(n.cpu.U64-2,7,7))[0],'V:18446744073709551595:18446744073709551602:32:2:1')
        self.assertEqual(n.evaluate(self.im,(1<<63,1,0))[0],'V:9223372036854775808:0:N')
        self.assertEqual(n.evaluate(self.im,(1<<63,1,(1<<63)-1))[0],'V:9223372036854775808:18446744073709551615:N')
        self.assertEqual(n.evaluate(self.im,(2,(1<<63)-1,n.cpu.U64))[0],'M')
        self.assertEqual(n.evaluate(self.im,(1,0,n.cpu.U64))[0],'E')

    def test_no_opaque_calls_or_outside_slots(self):
        m=n.Machine(self.im)
        self.assertIsNone(m.get(n.cpu.RBX,64))
        for a,size in [(n.cpu.STACK,8),(n.cpu.STACK+0x3f,2),(n.cpu.STACK+0x111,8)]:
            with self.assertRaisesRegex(ValueError,'footprint'):m.load(a,size)
            with self.assertRaisesRegex(ValueError,'footprint'):m.store(a,size,0)
        with self.assertRaisesRegex(ValueError,'opaque call'):m.call()
        for a in [*n.NORMAL,*n.FRONTIERS]:
            with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(a)
        with self.assertRaisesRegex(ValueError,'nonzero'):n.evaluate(self.im,(0,0,0))

    def test_digest_rejection_without_assertions(self):
        r=subprocess.run([sys.executable,'-O','-c',"import native; native.SHA='0'*64; native.verify()"],cwd=PACKET,capture_output=True)
        self.assertNotEqual(r.returncode,0);self.assertIn(b'wrong115target',r.stderr)

if __name__=='__main__':unittest.main()
