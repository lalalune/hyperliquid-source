"""Compile and compare the bounded u32 reader reconstruction."""
import os
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u32_reader115_rust as reader


class U32ReaderRustTests(unittest.TestCase):
    def test_compiled_reader(self):
        rustc = os.environ.get('RUSTC') or shutil.which('rustc')
        if not rustc:
            self.skipTest('Rust compiler with the Linux x86-64 target required')
        result = reader.verify(ROOT / 'artifacts/node/115/hl-node', rustc)
        self.assertEqual(result['cases'], 18600)
        self.assertEqual(result['evaluations'], 148800)
        self.assertEqual(result['mismatches'], 0)
        self.assertEqual(result['transcript_sha256'],
                         '99303a883c2ac9fecd38312cfd952cb5745958d94fcb0394e8bcb9a0f3390ed2')


if __name__ == '__main__':
    unittest.main()
