import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DRIFT = Path(__file__).resolve().parents[1] / 'tools' / 'legacy' / 'drift.py'

SOURCE = '''pub const A: &str = "delta  epsilon";
pub const B: &str = "red  green blue";
pub const C: &str = "purple monkey dishwasher";
pub const D: &str = "verbatim string here";
'''
BIN_A = b'PAD delta epsilon PAD red green blue PAD verbatim string here PAD'
BIN_B = b'PAD verbatim string here PAD'


def classify():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        crate = root / 'src' / 'crate1'
        crate.mkdir(parents=True)
        (crate / 'a.rs').write_text(SOURCE, encoding='utf-8')
        (root / 'binA').write_bytes(BIN_A)
        (root / 'binB').write_bytes(BIN_B)
        out = root / 'out.json'
        r = subprocess.run(
            [sys.executable, '-I', str(DRIFT), str(root / 'src'),
             str(root / 'binA'), str(root / 'binB'), str(out)],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(f'drift.py failed: {r.stderr}')
        items = json.loads(out.read_text(encoding='utf-8'))['items']
        return {i['literal']: i['class'] for i in items}


class DriftWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classes = classify()

    def test_two_word_literal_is_not_partial(self):
        # 'delta  epsilon' has only two words, so no 3-word window exists
        # for it; 'partial' requires a real 3-word window in the source
        # binary. Its normalized two-word form occurs in BIN_A, which must
        # not be enough.
        self.assertEqual(self.classes['delta  epsilon'], 'unanchored')

    def test_three_word_window_is_partial(self):
        self.assertEqual(self.classes['red  green blue'], 'partial')

    def test_verbatim_in_both_binaries_is_grounded(self):
        self.assertEqual(self.classes['verbatim string here'], 'grounded')

    def test_no_window_anywhere_is_unanchored(self):
        self.assertEqual(self.classes['purple monkey dishwasher'], 'unanchored')


if __name__ == '__main__':
    unittest.main()
