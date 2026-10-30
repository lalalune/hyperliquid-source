import hashlib
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_db_blake3 as m  # noqa: E402
import bincode_varint as bv  # noqa: E402

PKT = ROOT / 'research/work-items/RE-009-evm-db-blake3'
BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA = 'd0047969a9226409e8d74480d57df9cd76bd4c8d91fcbbb38792c9a85fbead4e'
DATA = bv.TARGET.read_bytes() if bv.TARGET.exists() else None
requires_bin = unittest.skipIf(DATA is None, 'node #94 binary absent')


def _gnu_objdump():
    exe = shutil.which('objdump')
    if not exe:
        return None
    out = subprocess.run([exe, '--version'], capture_output=True, text=True).stdout
    return exe if out.startswith('GNU objdump') else None


requires_gnu = unittest.skipIf(_gnu_objdump() is None, 'GNU objdump required')


@requires_bin
class Pins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = m.scan(DATA)

    def test_binary_sha(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), BIN_SHA)

    def test_json_bytes(self):
        out = m.render(self.r)
        self.assertEqual(hashlib.sha256(out).hexdigest(), JSON_SHA)
        self.assertEqual(out, (PKT / 'evm-db-blake3.json').read_bytes())

    def test_rounds_exact(self):
        rs = self.r['rounds']
        self.assertEqual(len(rs), 3)
        self.assertEqual([x['producer'] for x in rs], ['0x37d3070', '0x37d3bd0', '0x37d2550'])
        self.assertEqual([x['update_args']['rdx'] for x in rs], [0x800, 0x800, 0x800])
        self.assertEqual([x['finalize_out'] for x in rs], ['rsp+0x2e90', 'rsp+0x2580', 'rsp+0x150'])
        self.assertEqual([x['db_wrapper_esi'] for x in rs], ['0x18', '0x19', '0x1a'])

    def test_slots_and_callers_exact(self):
        s = self.r['blake3_slots']
        self.assertEqual(s['0x57700c0']['call_sites'], ['0x3269cd1', '0x3269eec', '0x326a0f8'])
        self.assertEqual(s['0x57700c8']['call_sites'], ['0x3269d96', '0x3269fb1', '0x326a1bd'])
        self.assertEqual(s['0x57700d0']['call_sites'], ['0x3269dac', '0x3269fc7', '0x326a1d3'])
        self.assertEqual(self.r['function']['rel32_callers'], ['0x326e4bb', '0x32fc41f'])
        self.assertEqual(len(self.r['anchors']), 68)

    def test_tamper_anchor(self):
        d = bytearray(DATA)
        d[bv.va_to_off(bv.sections(DATA), 0x3269d91) + 2] ^= 1
        with self.assertRaises(bv.EvidenceError):
            m.scan(bytes(d), expected_sha256=hashlib.sha256(d).hexdigest(), check_callers=False)

    def test_wrong_sha(self):
        with self.assertRaises(bv.EvidenceError):
            m.scan(DATA + b'\0')

    def test_negative_control_untouched(self):
        d = ROOT / 'research/work-items/RE-009-storage-state-roots'
        for f, h in (('hashers.json', '6411981c'), ('state-roots.json', '1ac3af0a'),
                     ('fixture-schema.json', 'ae0c6815')):
            self.assertEqual(hashlib.sha256((d / f).read_bytes()).hexdigest()[:8], h, f)


@requires_bin
class Scripts(unittest.TestCase):
    def _run(self, *args, env=None):
        return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env)

    def test_independent_pass(self):
        p = self._run('-I', '-B', str(PKT / 'independent_verify.py'))
        self.assertEqual((p.returncode, p.stdout.splitlines()[-1]), (0, 'PASS'), p.stdout + p.stderr)

    def test_verify_I_and_O(self):
        for flag in ('-I', '-O'):
            p = self._run(flag, '-B', str(PKT / 'verify.py'))
            self.assertEqual(p.returncode, 0, flag + p.stdout + p.stderr)
            self.assertEqual(p.stdout, f'PASS evm-db-blake3.json sha256 {JSON_SHA}\n')

    def test_hashseeds(self):
        import os
        outs = set()
        for seed in ('0', '7', '99'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = self._run('-B', str(ROOT / 'tools/evm_db_blake3.py'), env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            outs.add(hashlib.sha256(p.stdout.encode()).hexdigest())
        self.assertEqual(outs, {JSON_SHA})


@requires_bin
@requires_gnu
class GnuObjdump(unittest.TestCase):
    def test_update_round1(self):
        out = subprocess.run([_gnu_objdump(), '-d', '-M', 'intel', '--no-show-raw-insn',
                              '--start-address=0x3269d91', '--stop-address=0x3269d9c', str(bv.TARGET)],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.count('mov    edx,0x800'), 1)
        self.assertEqual(out.count('# 57700c8'), 1)


if __name__ == '__main__':
    unittest.main()
