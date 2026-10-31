"""Actual target table controls; altered copies are parsed below the hash gate."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from node94_version_requirements import TARGET, analyze, generate


class VersionRequirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = ROOT / TARGET
        if not binary.is_file() or binary.read_bytes()[:4] != b'\x7fELF':
            raise unittest.SkipTest('SKIPPED (not a PASS): captured node94 ELF unavailable')
        cls.result = generate(ROOT)  # authenticates exactly the snapshot analyzed
        cls.data = binary.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != cls.result['sha256']:
            raise ValueError('Target changed during test preparation')
        cls.facts = cls.result['facts']

    def test_actual_tables_and_version_maxima(self):
        f = self.facts
        self.assertEqual((len(f['providers']), len(f['requirements']), f['dynsym_count']), (7, 53, 509))
        self.assertEqual(sum(len(r['symbols']) for r in f['requirements']), 497)
        self.assertEqual((len(f['unversioned_undefined_symbols']), f['defined_symbol_count'],
                          f['reserved_null_symbol_count']), (10, 1, 1))
        maxima = {ns: rows[0]['name'].split('_', 1)[1] for ns, rows in f['maxima'].items()}
        legacy = json.loads((ROOT / 'research/work-items/RE-002-build-provenance/provenance-94.json').read_text())
        self.assertEqual(maxima, next(r['value'] for r in legacy['facts']
                                     if r['key'] == 'dynamic.max_symbol_versions'))
        self.assertEqual([(r['provider'], len(r['symbols'])) for r in f['maxima']['OPENSSL']],
                         [('libssl.so.3', 30), ('libcrypto.so.3', 28)])
        glibc, = f['maxima']['GLIBC']
        self.assertEqual((glibc['provider'], glibc['index'], glibc['version_flags']), ('libc.so.6', 26, 0))
        self.assertEqual([(s['index'], s['name'], s['binding']) for s in glibc['symbols']],
                         [(173, 'pidfd_getpid', 2), (182, 'pidfd_spawnp', 2)])
        self.assertEqual((glibc['vernaux_file_offset'], glibc['symbols'][0]['symbol_file_offset'],
                          glibc['symbols'][0]['versym_file_offset']), (0x3a94, 0x1378, 0x3452))

    def test_binding_and_requirement_flags_are_independent(self):
        base, = self.facts['maxima']['GLIBC']
        changed = bytearray(self.data)
        struct.pack_into('<H', changed, base['vernaux_file_offset'] + 4, 2)
        row, = analyze(changed)['maxima']['GLIBC']
        self.assertEqual(row['version_flags'], 2)
        self.assertEqual([s['binding'] for s in row['symbols']], [2, 2])
        changed = bytearray(self.data)
        changed[base['symbols'][0]['symbol_file_offset'] + 4] = 0x12
        row, = analyze(changed)['maxima']['GLIBC']
        self.assertEqual(row['version_flags'], 0)
        self.assertEqual([s['binding'] for s in row['symbols']], [1, 2])

    def test_symbol_version_and_provider_are_read_from_their_rows(self):
        base, = self.facts['maxima']['GLIBC']
        changed = bytearray(self.data)
        struct.pack_into('<H', changed, base['symbols'][0]['versym_file_offset'], 2)
        f = analyze(changed)
        moved = next(r for r in f['requirements'] if any(s['index'] == 173 for s in r['symbols']))
        self.assertEqual((moved['index'], moved['name']), (2, 'GLIBC_2.34'))
        self.assertEqual([s['index'] for s in f['maxima']['GLIBC'][0]['symbols']], [182])
        changed = bytearray(self.data)
        libm = next(p for p in self.facts['providers'] if p['name'] == 'libm.so.6')
        offset = libm['name_file_offset'] - self.facts['sections']['.dynstr']['offset']
        struct.pack_into('<I', changed, base['verneed_file_offset'] + 4, offset)
        row, = analyze(changed)['maxima']['GLIBC']
        self.assertEqual(row['provider'], 'libm.so.6')
        self.assertEqual(row['symbols'], base['symbols'])

    def test_section_dynamic_and_chain_corruptions_are_rejected(self):
        secs = self.facts['sections']
        first = self.facts['requirements'][0]
        tag = next(r for r in self.facts['dynamic_entries'] if r['tag'] == 0x6ffffffe)
        controls = [
            (secs['.gnu.version']['header_file_offset'] + 40, '<I', secs['.dynstr']['index'], 'linked section'),
            (tag['file_offset'] + 8, '<Q', tag['value'] + 1, 'Dynamic tag'),
            (secs['.gnu.version_r']['offset'] + 8, '<I', secs['.gnu.version_r']['size'], 'outside'),
            (secs['.gnu.version_r']['offset'] + 12, '<I', 0, 'Incomplete Verneed'),
            (first['vernaux_file_offset'] + 12, '<I', 0, 'Incomplete Vernaux'),
            (first['vernaux_file_offset'], '<I', first['name_hash'] ^ 1, 'name hash'),
            (0x3452, '<H', 0x7ffe, 'absent version requirement'),
        ]
        for offset, fmt, value, message in controls:
            with self.subTest(offset=hex(offset), message=message):
                changed = bytearray(self.data)
                struct.pack_into(fmt, changed, offset, value)
                with self.assertRaisesRegex(ValueError, message):
                    analyze(changed)

    def test_gnu_readelf_agrees_on_all_versioned_imports(self):
        tool = shutil.which('readelf')
        if not tool or 'GNU' not in subprocess.check_output([tool, '--version'], text=True):
            self.skipTest('SKIPPED (not a PASS): GNU readelf unavailable')
        # readelf only reads the captured input; it never executes it.
        output = subprocess.check_output([tool, '--dyn-syms', '--wide', str(ROOT / TARGET)], text=True)
        parsed = {}
        for line in output.splitlines():
            match = re.fullmatch(r'\s*(\d+):\s+[0-9a-f]+\s+\d+\s+\S+\s+(\S+)\s+\S+\s+UND\s+(\S+)@([^\s]+)\s+\((\d+)\)', line)
            if match:
                index, binding, name, version, vi = match.groups()
                parsed[int(index)] = (binding, name, version, int(vi))
        expected = {s['index']: ({1: 'GLOBAL', 2: 'WEAK'}[s['binding']], s['name'], r['name'], r['index'])
                    for r in self.facts['requirements'] for s in r['symbols']}
        self.assertEqual(len(parsed), 497)
        self.assertEqual(parsed, expected)

    def test_gnu_readelf_agrees_on_requirement_providers_and_flags(self):
        tool = shutil.which('readelf')
        if not tool or 'GNU' not in subprocess.check_output([tool, '--version'], text=True):
            self.skipTest('SKIPPED (not a PASS): GNU readelf unavailable')
        output = subprocess.check_output([tool, '--version-info', '--wide', str(ROOT / TARGET)], text=True)
        provider, parsed = None, {}
        for line in output.splitlines():
            header = re.search(r'Version: 1\s+File: (\S+)\s+Cnt: (\d+)', line)
            if header:
                provider = header.group(1)
            entry = re.search(r'Name: (\S+)\s+Flags: (\S+)\s+Version: (\d+)', line)
            if entry:
                name, flags, index = entry.groups()
                parsed[int(index)] = (provider, name, flags)
        self.assertEqual(len(parsed), 53)
        self.assertEqual(parsed, {r['index']: (r['provider'], r['name'], 'none')
                                  for r in self.facts['requirements']})
        self.assertTrue(all(r['version_flags'] == 0 for r in self.facts['requirements']))

    def test_retained_packet_regenerates_exactly(self):
        packet = ROOT / 'research/work-items/RE-002-version-requirements-94/observed.json'
        expected = (json.dumps(self.result, indent=2, sort_keys=True) + '\n').encode()
        self.assertEqual(packet.read_bytes(), expected)

    def test_cli_preserves_existing_output_and_creates_fresh_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'observed.json'
            sentinel = b'preserve this existing evidence\n'
            output.write_bytes(sentinel)
            cmd = [sys.executable, '-B', str(ROOT / 'tools/node94_version_requirements.py'),
                   '--output', str(output)]
            result = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'FileExistsError', result.stderr)
            self.assertEqual(output.read_bytes(), sentinel)
            fresh = Path(tmp) / 'fresh.json'
            result = subprocess.run(cmd[:-1] + [str(fresh)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(fresh.read_bytes(),
                             (json.dumps(self.result, indent=2, sort_keys=True) + '\n').encode())


class AuthenticationTests(unittest.TestCase):
    def test_substituted_target_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'provenance').mkdir()
            (root / 'provenance/artifacts.json').write_bytes((ROOT / 'provenance/artifacts.json').read_bytes())
            target = root / TARGET
            target.parent.mkdir(parents=True)
            target.write_bytes(b'not the captured node')
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                generate(root)


if __name__ == '__main__':
    unittest.main()
