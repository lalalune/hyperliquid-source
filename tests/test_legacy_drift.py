import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRIFT = ROOT / 'tools' / 'legacy' / 'drift.py'


class DriftHexEscapeTests(unittest.TestCase):
    def classify(self, literal, needle):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src = d / 'src' / 'crate'
            src.mkdir(parents=True)
            (src / 'lib.rs').write_text(f'pub const S: &str = "{literal}";\n')
            bin_a = d / 'a.bin'
            bin_a.write_bytes(b'xx' + needle + b'yy')
            bin_b = d / 'b.bin'
            bin_b.write_bytes(b'xx' + needle + b'yy')
            out = d / 'out.json'
            subprocess.run([sys.executable, '-I', str(DRIFT), str(d / 'src'),
                            str(bin_a), str(bin_b), str(out)],
                           check=True, capture_output=True)
            return json.loads(out.read_text())['items']

    def test_hex_escape_literal_is_grounded(self):
        items = self.classify(r'prefix\x41suffix99', b'prefixAsuffix99')
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['literal'], 'prefixAsuffix99')
        self.assertEqual(items[0]['class'], 'grounded')

    def test_plain_literal_still_grounded(self):
        items = self.classify('plainliteral99', b'plainliteral99')
        self.assertEqual(items[0]['class'], 'grounded')


if __name__ == '__main__':
    unittest.main()
