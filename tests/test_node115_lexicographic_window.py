import json
import mmap
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from tools import node115_lexicographic_window as b

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-001-node115-lexicographic-window'

class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = b.TARGET.open('rb')
        cls.image = mmap.mmap(cls.file.fileno(),0,access=mmap.ACCESS_COPY)
        cls.records = b.analyze(b.TARGET)

    @classmethod
    def tearDownClass(cls):
        cls.image.close()
        cls.file.close()

    def test_regeneration_and_counts(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_text()), self.records)
        readme = (PACKET/'README.md').read_text()
        for label,number in [('Window bytes',self.records['window']['size']),
                             ('Instructions',len(self.records['instructions'])),
                             ('Callees',len(self.records['callees'])),
                             ('Relative direct-transfer candidates',len(self.records['direct_transfer_candidates'])),
                             ('Call-shaped candidates',sum(x['kind']=='call' for x in self.records['direct_transfer_candidates'])),
                             ('Jump-shaped candidates',sum(x['kind']=='jmp' for x in self.records['direct_transfer_candidates'])),
                             ('Padding bytes',len(bytes.fromhex(self.records['window']['padding_hex'])))]:
            match = re.search(r'^- '+re.escape(label)+r': \*\*(\d+)\*\*$',readme,re.M)
            self.assertIsNotNone(match,label)
            self.assertEqual(int(match.group(1)),number)
        self.assertEqual(self.records['scan']['candidate_count'],len(self.records['direct_transfer_candidates']))

    def test_lexicographic_boundaries(self):
        m=b.model
        # First limb signed, others unsigned. Less ignores D; greater/equal permits code 2.
        self.assertEqual(m(0x80000000,0,0,0,0,0,0,0,0),0)
        self.assertEqual(m(0,0,0,0x80000000,0,0,0,0,0),2)
        self.assertEqual(m(0,0xffffffff,0,0,0,0,0,0,0),2)
        self.assertEqual(m(0,0,0xffffffff,0,0,0,0,0,0),2)
        self.assertEqual(m(0,0,0,0,0,1,5000,0,0),1)
        self.assertEqual(m(1,0,0,1,0,0,4999,5000,0),0)
        self.assertEqual(m(1,0,0,1,0,0,5000,5001,0),1)
        self.assertEqual(m(1,0,0,1,0,0,5000,5000,0),2)

    def test_saturation_boundaries(self):
        m=b.model
        top=2**64-1
        for base in (0,1,top-5000,top-4999,top-1,top):
            threshold=min(top,base+5000)
            for current in (threshold-1,threshold):
                self.assertEqual(m(0,0,0,1,0,0,current,0,base),int(current>=threshold))

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            wrong=Path(d)/'wrong'
            wrong.write_bytes(b'not node 115')
            with self.assertRaisesRegex(ValueError,'digest/size'):
                b.analyze(wrong)
            out=Path(d)/'output'
            result=subprocess.run([sys.executable,str(ROOT/'tools/node115_lexicographic_window.py'),'--binary',str(wrong),'--out',str(out)],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(out.exists())

    def corrupt(self,offset):
        old=self.image[offset]
        self.image[offset]=old ^ 1
        try:
            with self.assertRaisesRegex(ValueError,'digest/size'):
                b.authenticate(self.image)
            with self.assertRaises(ValueError):
                b.derive(self.image)
        finally:
            self.image[offset]=old

    def test_window_instruction_corruption(self):
        self.corrupt(0x55fe970)

    def test_branch_target_corruption(self):
        self.corrupt(0x55fe981)

    def test_shifted_fde_corruption(self):
        self.corrupt(0xf86fac)

    def test_source_location_relocation_corruption(self):
        self.corrupt(0xa29d8+16)

    def test_wrong_caller_target(self):
        self.corrupt(0x517beb5-0x1000+1)

if __name__ == '__main__':
    unittest.main()
