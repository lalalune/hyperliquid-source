"""Actual ordinary RET, memory footprint and captured-byte corruption checks."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-004-spot-decimal-115'
sys.path.insert(0,str(PACKET))
spec=importlib.util.spec_from_file_location('spot_decimal_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class SpotDecimalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.record=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_frozen_full_memory_stream(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.record['expected_sha256'])
        self.assertEqual(len(set(inputs.splitlines())),4048)
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

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone required for independent disassembly; skip is not a decoder pass")
    def test_owner_and_all_ordinary_instruction_starts(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        rows=list(cs.disasm(self.im.view.read(n.ENTRY,207),n.ENTRY))
        self.assertEqual(sum(x.size for x in rows),207);self.assertEqual(len(rows),66)
        for x in rows:self.assertEqual(self.im.fetch(x.address).size,x.size)
        self.assertEqual({x.address for x in rows},set(self.record['visited_addresses']))
        self.assertEqual(self.im.view.fde(n.ENTRY),(n.ENTRY,n.END))
        full=list(cs.disasm(self.im.view.read(n.ENTRY,242),n.ENTRY));self.assertEqual(len(full),73)

    def test_sealed_quotient_rejection_and_inactive_bytes(self):
        # These complete raw snapshots occur in the pre-Rust stream.
        self.assertEqual(n.evaluate(self.im,(0,0,[0],[0],165))[0],'O:a201c7d8e9fa0b1c0000000000000000')
        self.assertEqual(n.evaluate(self.im,(100000000,0,[0],[0],165))[0],'O:a201c7d8e9fa0b1c0100000000000000')
        self.assertEqual(n.evaluate(self.im,(100000001,0,[0],[0],165))[0],'O:6a00c7d8e9fa0b1c2d3e4f60718293a4')
        self.assertEqual(n.evaluate(self.im,(0,0,[0],[9],165))[0],'O:6a00c7d8e9fa0b1c2d3e4f60718293a4')
        self.assertEqual(n.evaluate(self.im,(1,0,[0],[8],165))[0],'O:a201c7d8e9fa0b1c0100000000000000')
        self.assertEqual(n.evaluate(self.im,(0,0,[],[],165))[0],'A')
        self.assertEqual(n.evaluate(self.im,(0,0,[0],[],165))[0],'B')

    def test_no_opaque_calls_or_input_writes(self):
        m=n.Machine(self.im,1,1)
        for address in [n.DESC,n.FIRST,n.SECOND]:
            with self.assertRaisesRegex(ValueError,'footprint'):m.store(address,1,0)
        for address in [n.FIRST+32,n.SECOND+344,n.OUTPUT+16]:
            with self.assertRaisesRegex(ValueError,'footprint'):m.load(address,1)
        with self.assertRaisesRegex(ValueError,'opaque call'):m.call()
        for address in n.FRONTIERS:
            with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(address)
        self.assertIsNone(m.get(n.cpu.RAX,64))

    def test_wrong_target_rejected_under_optimization(self):
        r=subprocess.run([sys.executable,'-O','-c',"import native; native.SHA='0'*64; native.verify()"],cwd=PACKET,capture_output=True)
        self.assertNotEqual(r.returncode,0);self.assertIn(b'wrong115target',r.stderr)

if __name__=='__main__':unittest.main()
