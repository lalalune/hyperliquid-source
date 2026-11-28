"""Focused controls using real signed packages and a second ELF inspection tool."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import verify


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads((verify.HERE / 'result.json').read_text())

    def test_two_release_tables_agree_with_objdump(self):
        # objdump uses BFD. GNU readelf in the collector uses its own ELF reader.
        def table(path, undefined):
            rows = set()
            for line in verify.run([ARGS.objdump, '-T', str(path)]).decode().splitlines():
                fields = line.split()
                if len(fields) < 6 or ('*UND*' in fields) != undefined:
                    continue
                version = fields[-2].strip('()')
                if version.startswith(('GLIBCXX_', 'CXXABI_')):
                    rows.add((fields[-1], version))
            return rows

        imports = self.receipt['imports']
        self.assertEqual(table(verify.TARGET, True), {(r['symbol'], r['version']) for r in imports})
        with tempfile.TemporaryDirectory() as temp:
            for suite in verify.RELEASES:
                _, data = verify.package(suite, ARGS.cache / suite, ARGS.keyring.resolve(), False)
                path = Path(temp) / 'provider'
                path.write_bytes(data)
                offered = table(path, False)
                for row in imports:
                    with self.subTest(suite=suite, symbol=row['symbol']):
                        self.assertEqual((row['symbol'], row['version']) in offered,
                                         row[suite]['match'])

    def test_same_symbol_old_version_and_two_absent_symbols(self):
        missing = [r for r in self.receipt['imports'] if not r['focal']['match']]
        self.assertEqual(len(missing), 3)
        wait, = [r for r in missing if 'condition_variable4wait' in r['symbol']]
        self.assertEqual((wait['version'], wait['focal']['available']),
                         ('GLIBCXX_3.4.30', ['GLIBCXX_3.4.11']))
        self.assertEqual(sum(not r['focal']['available'] for r in missing), 2)
        self.assertTrue(all(r['noble']['match'] for r in missing))

    def test_altered_package_bytes_rejected(self):
        path = ARGS.cache / 'focal/provider.deb'
        with tempfile.TemporaryDirectory() as temp:
            changed = Path(temp) / 'altered.deb'
            blob = bytearray(path.read_bytes())
            blob[-1] ^= 1
            changed.write_bytes(blob)
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                verify.resource(changed, '', self.receipt['packages'][0]['deb_sha256'], False)

    def test_untrusted_archive_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            empty = Path(temp) / 'empty.gpg'
            empty.touch()
            with self.assertRaises(subprocess.CalledProcessError):
                verify.package('noble', ARGS.cache / 'noble', empty, False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cache', type=Path)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump')
    ARGS = parser.parse_args()
    unittest.main(argv=['test_provider.py'], verbosity=2)
