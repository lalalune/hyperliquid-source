"""Static controls for the #115 ring-span evidence; never execute the artifact."""
import hashlib
import json
import mmap
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools import node115_ring_spans as subject

ROOT = Path(__file__).resolve().parents[1]
PACKET = subject.PACKET


class RingSpansTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET/'records.json').read_text())
        cls.body = bytes.fromhex(''.join(row['bytes'] for row in cls.record['instructions']))

    def test_model_boundaries(self):
        m=(1<<64)-1
        vectors = [
            ((10,100,8,0),(100,100,100,100)),
            ((10,100,8,2),(548,660,100,100)),
            ((10,100,8,5),(548,660,100,268)),
            ((10,100,12,5),(212,492,100,100)),
            ((0,m,m,1),(m-56,m,m,m)),
            ((0,m,m,2),(m-56,m,m,55)),
            ((m,0,m,1),(0,56,0,0)),
        ]
        for args, expected in vectors:
            with self.subTest(args=args): self.assertEqual(subject.model(*args),expected)
        for args in ((-1,0,0,0),(0,0,0,1<<64)):
            with self.assertRaises(ValueError): subject.model(*args)

    def test_full_instruction_walk(self):
        self.assertEqual(subject.decode(self.body),self.record['instructions'])
        self.assertEqual(hashlib.sha256(self.body).hexdigest(),self.record['body']['sha256'])
        self.assertEqual(len(self.body),self.record['body']['size'])

    def test_changed_window_byte_rejected(self):
        bad=bytearray(self.body);bad[-1] ^= 1
        with self.assertRaises(ValueError): subject.decode(bytes(bad))

    def test_changed_branch_target_rejected(self):
        bad=bytearray(self.body);bad[11] ^= 1
        with self.assertRaises(ValueError): subject.decode(bytes(bad))

    def test_shifted_fde_and_cie_rejected(self):
        f=self.record['body']['frame']; raw=bytearray.fromhex(f['fde_hex']);cie=bytes.fromhex(f['cie_hex'])
        self.assertEqual(subject.frame(bytes(raw),cie),f)
        raw[8] ^= 1
        with self.assertRaises(ValueError): subject.frame(bytes(raw),cie)
        bad=bytearray(cie);bad[16] ^= 1
        with self.assertRaises(ValueError): subject.frame(bytes.fromhex(f['fde_hex']),bytes(bad))

    def test_wrong_caller_target_rejected(self):
        row=self.record['direct_rel32_scan']['candidates'][0]
        raw=bytearray.fromhex(row['bytes']);raw[1] ^= 1
        with self.assertRaises(ValueError): subject.decode_call(bytes(raw),row['site'],subject.START)
        self.assertEqual(self.record['callees'],[])

    def test_digest_rejects_modified_and_short_input(self):
        # mmap keeps one copy on disk; mutate the actual captured body byte on the copy.
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'target'; shutil.copyfile(subject.TARGET,path)
            with path.open('r+b') as f:
                f.seek(subject.START-0x1000); b=f.read(1); f.seek(-1,1); f.write(bytes([b[0]^1])); f.flush()
                with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
                    with self.assertRaisesRegex(ValueError,'SHA-256'): subject.collect(image)
            with self.assertRaisesRegex(ValueError,'SHA-256'): subject.collect(b'wrong release')

    def test_readme_counts_match_records(self):
        text=(PACKET/'README.md').read_text()
        checks = [(r'\*\*(\d+) bytes\*\*',self.record['body']['size']),
                  (r'following \*\*(\d+) bytes\*\*',len(bytes.fromhex(self.record['body']['padding_hex']))),
                  (r'walk of \*\*(\d+) instructions\*\*',len(self.record['instructions'])),
                  (r'yields \*\*(\d+) candidate\*\*',len(self.record['direct_rel32_scan']['candidates']))]
        for pattern, expected in checks:
            match=re.search(pattern,text); self.assertIsNotNone(match,pattern); self.assertEqual(int(match[1]),expected)
        stride = int(re.search(r'stride-(\d+)', text)[1])
        factors = [int(row['instruction'].split(',')[-1]) for row in self.record['instructions']
                   if row['instruction'].startswith('imul ')]
        self.assertEqual(factors, [stride] * len(factors))
        self.assertTrue(factors)
        self.assertIn('no callees', text)
        self.assertEqual(len(self.record['callees']),0)
        self.assertEqual(self.record['body']['end']-self.record['body']['start'],self.record['body']['size'])

    def test_regeneration_and_manifest_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'packet'
            subprocess.run([sys.executable,str(ROOT/'tools/node115_ring_spans.py'),'--out',str(out)],check=True)
            for p in PACKET.iterdir():
                self.assertEqual(p.read_bytes(),(out/p.name).read_bytes(),p.name)
            subprocess.run([sys.executable,str(out/'verify.py')],check=True,capture_output=True)
            with (out/'records.json').open('ab') as f: f.write(b' ')
            self.assertNotEqual(subprocess.run([sys.executable,str(out/'verify.py')],capture_output=True).returncode,0)
            (out/'extra').write_text('x')
            self.assertNotEqual(subprocess.run([sys.executable,str(out/'verify.py')],capture_output=True).returncode,0)

    def test_wrong_digest_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out'; wrong=Path(d)/'wrong';wrong.write_bytes(b'wrong')
            result=subprocess.run([sys.executable,str(ROOT/'tools/node115_ring_spans.py'),'--binary',str(wrong),'--out',str(out)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertFalse(out.exists())

if __name__ == '__main__': unittest.main()
