"""Original whole-leaf state/operand/footprint controls, no captured process."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-limb-add-family-115'
sys.path.insert(0, str(PACKET))
spec = importlib.util.spec_from_file_location('limb_family_native115', PACKET/'native.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)

class LimbAddFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im = n.Image()
        if hashlib.sha256(cls.im.data).hexdigest() != n.SHA:
            cls.im.close()
            raise ValueError('wrong115target')
        cls.record = json.loads((PACKET/'FREEZE.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.im.close()

    def test_frozen_complete_observations(self):
        inputs, expected, seen = n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())), self.record['rows'])
        self.assertEqual(hashlib.sha256(inputs).hexdigest(), self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(), self.record['expected_sha256'])
        self.assertEqual(sorted(seen), self.record['visited_addresses'])

    def test_fifteen_actual_cow_controls(self):
        controls = json.loads((PACKET/'native-controls.json').read_text())
        self.assertEqual(len(controls), 15)
        for c in controls:
            with self.subTest(name=c['name']):
                changed = n.Image()
                changed.data = mmap.mmap(changed.view.file.fileno(), 0, access=mmap.ACCESS_COPY)
                try:
                    address = int(c['va'], 16)
                    offset = changed.view.offset(address)
                    self.assertEqual(bytes([changed.data[offset]]).hex(), c['original_byte'])
                    changed.data[offset] = int(c['changed_byte'], 16)
                    v = c['input']
                    self.assertEqual(n.evaluate(self.im,v[0],v[1],v[2:6],v[6:10])[0],c['original'])
                    self.assertEqual(n.evaluate(changed,v[0],v[1],v[2:6],v[6:10])[0],c['changed'])
                    self.assertNotEqual(c['original'],c['changed'])
                finally:
                    changed.close()

    def test_full_fdes_decoder_and_duplicate_aliases(self):
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        addresses = set()
        for start, end in n.RANGES:
            self.assertEqual(self.im.view.fde(start), (start,end))
            rows = list(cs.disasm(self.im.view.read(start,end-start),start))
            self.assertEqual(sum(i.size for i in rows),end-start)
            for i in rows:
                self.assertEqual(self.im.fetch(i.address).size,i.size)
                addresses.add(i.address)
        self.assertEqual(addresses,set(self.record['visited_addresses']))
        self.assertEqual(len(addresses),48)
        self.assertEqual(self.im.view.read(*[n.RANGES[1][0],49]), self.im.view.read(*[n.RANGES[2][0],49]))
        a,b = (n.cpu.U64,)*4, (1,0,0,0)
        self.assertEqual(n.evaluate(self.im,1,2,a,b)[0], n.evaluate(self.im,2,2,a,b)[0])

    def test_footprint_calls_and_domain(self):
        machine=n.Machine(self.im)
        for method in [machine.load,machine.store]:
            with self.assertRaisesRegex(ValueError,'footprint'):
                method(n.DESC-1,1,*([0] if method==machine.store else []))
        with self.assertRaisesRegex(ValueError,'unclosed'):
            machine.call()
        for _,end in n.RANGES:
            with self.assertRaisesRegex(ValueError,'CFG escape'):
                self.im.fetch(end)
        for mode,count in [(3,2),(0,-1),(0,9)]:
            with self.assertRaisesRegex(ValueError,'mode/count'):
                n.evaluate(self.im,mode,count,(0,)*4,(0,)*4)

    def test_short_guarded_raw_status_and_unchanged_state(self):
        for count in [0,1]:
            result,_ = n.evaluate(self.im,0,count,(n.cpu.U64,)*4,(1,0,0,0))
            self.assertTrue(result.startswith('44:'))
            raw=bytes.fromhex(result.split(':',1)[1])
            self.assertEqual(len(raw),424)
            self.assertEqual(int.from_bytes(raw[0x30:0x38],'little'),count)
            self.assertEqual(raw[64:96],n.cpu.U64.to_bytes(8,'little')*4)
            self.assertEqual(raw[352:416],bytes([0xa5])*64)

    def test_optimized_python_digest_refusal(self):
        code="import native; native.SHA='0'*64; native.verify()"
        r=subprocess.run([sys.executable,'-O','-c',code],cwd=PACKET,capture_output=True)
        self.assertNotEqual(r.returncode,0)
        self.assertIn(b'wrong115target',r.stderr)

if __name__=='__main__':
    unittest.main()
