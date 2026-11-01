"""Independent authority regeneration and complete raw-comparator controls."""
import gzip
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import hex_pair_iterator_rust as protocol


class HexIteratorAuthorityTests(unittest.TestCase):
    def test_full_authority_and_comparator_corruptions(self):
        inputs, raw, expected = protocol.fixtures()
        self.assertEqual(len(inputs.splitlines()), 39850)
        self.assertEqual(len(expected), 185490)
        self.assertEqual(protocol.compare(raw, expected), [])
        changed = expected.copy()
        fields = changed[0].split(b'|')
        fields[2] = b'00' * 16
        changed[0] = b'|'.join(fields)
        self.assertEqual(protocol.compare(b'\n'.join(changed) + b'\n', expected), ['h000000|1'])
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            protocol.compare(b'\n'.join(expected[:-1]), expected)

    def test_high_level_unicode_oracle_regenerates_exact_frozen_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('generate_hex_iterator.py', 'hex-iterator-proof.md'):
                shutil.copyfile(protocol.PACKET / 'oracle' / name, root / name)
            process = subprocess.run([sys.executable, '-B', str(root / 'generate_hex_iterator.py')],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            for name in ('hex-iterator-authority.json', 'hex-iterator-input.txt', 'hex-iterator-expected.txt'):
                self.assertEqual((root / name).read_bytes(), gzip.decompress((protocol.PACKET / 'oracle' / (name + '.gz')).read_bytes()))
            self.assertEqual((root / 'hex-iterator-freeze.json').read_bytes(), (protocol.PACKET / 'oracle/hex-iterator-freeze.json').read_bytes())

    def test_actual_frozen_input_container_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(protocol.PACKET / 'oracle', root / 'oracle')
            path = root / 'oracle/hex-iterator-input.txt.gz'
            raw = bytearray(gzip.decompress(path.read_bytes()))
            raw[0] ^= 1
            path.write_bytes(gzip.compress(raw, mtime=0))
            with patch.object(protocol, 'PACKET', root):
                with self.assertRaisesRegex(ValueError, 'oracle identity mismatch'):
                    protocol.fixtures()


if __name__ == '__main__':
    unittest.main()
