import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import lt_hashes_format as m  # noqa: E402
import bincode_varint as bv  # noqa: E402

PKT = ROOT / 'research/work-items/RE-009B-lt-hashes-format'
BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA = '007928510442778665a87e3bb086cd96be5c41f3c83f2ed69350f9b87aed6cfb'
DATA = bv.TARGET.read_bytes() if bv.TARGET.exists() else None
requires_bin = unittest.skipIf(DATA is None, 'node #94 binary absent')
RE009_MERGED = {
    'research/work-items/RE-009-storage-state-roots/hashers.json':
        '6411981c8f0953dc152e432a3c9abeb8512f703599e36df675d39dfb9f6a77f0',
    'research/work-items/RE-009-storage-state-roots/state-roots.json':
        '1ac3af0abe3b12e44819f117d3288a2e7e7ae336934cb6927d566142bc8387a8',
    'research/work-items/RE-009-storage-state-roots/fixture-schema.json':
        'ae0c6815914486fefb7092a697f3748c39caaad6131a6f93de339814c45429e4',
}


def _gnu_objdump():
    exe = shutil.which('objdump')
    if not exe:
        return None
    out = subprocess.run([exe, '--version'], capture_output=True, text=True).stdout
    return exe if out.startswith('GNU objdump') else None


requires_gnu = unittest.skipIf(_gnu_objdump() is None, 'GNU objdump required')


def _run(*args, env=None):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=ROOT, env=env)


@requires_bin
class Pins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = m.scan(DATA)

    def test_binary_sha(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), BIN_SHA)

    def test_json_bytes(self):
        got = m.render(self.r)
        self.assertEqual(hashlib.sha256(got).hexdigest(), JSON_SHA)
        self.assertEqual(got, (PKT / 'lt-hashes-format.json').read_bytes())

    def test_exact_counts(self):
        self.assertEqual(len(self.r['anchors']), 56)
        self.assertEqual(len(self.r['functions']), 11)
        self.assertEqual(self.r['rel32_callers'], {'0x32699c0': ['0x326a2e0', '0x326aff3', '0x32fc267'],
                                                   '0x3c16810': ['0x3269a7b']})

    def test_fields(self):
        self.assertEqual([(f['name'], f['value_offset']) for f in self.r['fields']],
                         [('accounts_hash', '0x0'), ('contracts_hash', '0x810'), ('storage_hash', '0x1020')])
        self.assertEqual(self.r['value']['total_len'], 0x1830)

    def test_locations(self):
        self.assertEqual(self.r['locations']['0x37e21c0'], ['serde_json-1.0.120/src/ser.rs:660',
                         'serde_json-1.0.120/src/ser.rs:2004', 'serde_json-1.0.120/src/ser.rs:2014'])
        self.assertEqual(self.r['locations']['0x32699c0'], ['l1/src/evm/hash.rs:69'])

    def test_wrong_sha_rejected(self):
        with self.assertRaises(bv.EvidenceError):
            m.scan(DATA, expected_sha256='0' * 64)

    def test_tamper_rejected(self):
        secs = bv.sections(DATA)
        bad = bytearray(DATA)
        bad[bv.va_to_off(secs, 0x37e2215) + 3] ^= 1
        with self.assertRaises(bv.EvidenceError):
            m.scan(bytes(bad), expected_sha256=hashlib.sha256(bad).hexdigest(), check_callers=False)


@requires_bin
class Scripts(unittest.TestCase):
    def test_verify_isolated_and_optimized(self):
        for flag in ('-I', '-O'):
            p = _run(flag, '-B', str(PKT / 'verify.py'))
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(p.stdout, f'PASS lt-hashes-format.json sha256 {JSON_SHA}\n')

    def test_independent_pass(self):
        p = _run('-I', '-B', str(PKT / 'independent_verify.py'))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertTrue(p.stdout.endswith('PASS\n'))
        self.assertNotIn('tools', (PKT / 'independent_verify.py').read_text().split('"""')[2])

    def test_hashseeds(self):
        outs = set()
        for seed in ('0', '7', '99'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = _run('-B', 'tools/lt_hashes_format.py', env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            outs.add(hashlib.sha256(p.stdout.encode()).hexdigest())
        self.assertEqual(outs, {JSON_SHA})

    def test_manifest(self):
        for line in (PKT / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ')
            self.assertEqual(hashlib.sha256((PKT / name).read_bytes()).hexdigest(), h, name)

    def test_re009_merged_untouched(self):
        for rel, h in RE009_MERGED.items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), h, rel)

def _load_iv():
    import importlib.util
    spec = importlib.util.spec_from_file_location('re009b_iv', PKT / 'independent_verify.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _quiet(fn, *a, **k):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


@requires_bin
class KeyVaTamper(unittest.TestCase):
    def _run(self, mutate):
        import tempfile
        iv = _load_iv()
        j = json.loads((PKT / 'lt-hashes-format.json').read_text())
        mutate(j)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'lt-hashes-format.json'
            p.write_text(json.dumps(j))
            return _quiet(iv.main, json_path=p)

    def test_untampered_passes(self):
        self.assertEqual(self._run(lambda j: None), 0)

    def test_every_key_va_mutation_fails(self):
        for i in range(3):
            def mut(j, i=i):
                f = j['fields'][i]
                f['key_va'] = hex(int(f['key_va'], 16) + 1)
            self.assertEqual(self._run(mut), 1, i)

    def test_key_pool_va_mutation_fails(self):
        def mut(j):
            j['key_pool']['va'] = hex(int(j['key_pool']['va'], 16) + 1)
        self.assertEqual(self._run(mut), 1)

    def test_pinned_key_constant_mutation_fails(self):
        iv = _load_iv()
        iv.KEYS = [(0x59b249, b'accounts_hash'), (0x59b257, b'contracts_hash'), (0x59b264, b'storage_hash')]
        self.assertEqual(_quiet(iv.main), 1)



@requires_bin
@requires_gnu
class GnuObjdump(unittest.TestCase):
    def test_key_leas_and_json_markers(self):
        out = subprocess.run([_gnu_objdump(), '-d', '-M', 'intel', '--start-address=0x37e21c0',
                              '--stop-address=0x37e2330', str(bv.TARGET)], capture_output=True, text=True).stdout
        self.assertIn('BYTE PTR [rcx+rax*1],0x7b', out)
        self.assertIn('WORD PTR [rax+rsi*1],0x203a', out)
        for va in ('59b249', '59b256', '59b264'):
            self.assertIn(va, out)


if __name__ == '__main__':
    unittest.main()
