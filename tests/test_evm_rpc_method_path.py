import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('evm_rpc_method_path', ROOT / 'tools/evm_rpc_method_path.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PACKET = ROOT / 'research/work-items/RE-011-evm-rpc-method-path'


class MethodPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary94 = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.binary115 = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.inputs = {k: (ROOT / k).read_bytes() for k in mod.INPUTS}
        cls.result = mod.build(cls.binary94, cls.binary115, cls.inputs)
        cls.elf = mod.common.Elf(cls.binary94)

    def test_reproduces_packet_with_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([sys.executable, str(ROOT / 'tools/evm_rpc_method_path.py'), '--out', directory], check=True)
            self.assertEqual((Path(directory) / 'evm-rpc-method-path.json').read_bytes(),
                             (PACKET / 'evm-rpc-method-path.json').read_bytes())
        self.assertEqual(mod.render(self.result), (PACKET / 'evm-rpc-method-path.json').read_bytes())

    def test_inventory_and_locations(self):
        r = self.result
        self.assertEqual(r['method_count'], 26)
        self.assertEqual(len(r['methods']), 26)
        self.assertEqual(r['fde_count'], 121299)
        self.assertEqual(sum(r['scoped_location_counts'].values()), 42)
        self.assertEqual(r['scoped_location_counts']['evm_rpc/src/method_router.rs'], 7)
        self.assertEqual(r['scoped_location_counts']['evm_rpc/src/evm_rpc.rs'], 15)
        self.assertEqual(len(r['location_functions']), 38)
        for m in r['methods']:
            self.assertTrue(any(s['fde'] and s['fde']['start'] == '0x27ab650'
                                for a in m['anchors'] for s in a['lea_sites']), m['method'])
            use = m['table_use']
            self.assertEqual(use['length'], len(m['method'].encode()))
            self.assertEqual(bytes.fromhex(use['length_bytes']), b'\xb9' + struct.pack('<I', use['length']))
            call = bytes.fromhex(use['call_bytes'])
            self.assertEqual(call[0], 0xe8)
            self.assertEqual(int(use['call_site'], 16) + 5 + struct.unpack('<i', call[1:])[0], int(use['call_target'], 16))
            self.assertEqual(use['target_fde']['start'], use['call_target'])
        functions = {x['start']: x for x in r['location_functions']}
        self.assertEqual(functions['0x20266a0']['locations']['evm_rpc/src/method_router.rs'], [37, 39, 42])
        self.assertEqual(functions['0x202ec80']['locations']['evm_rpc/src/method_router.rs'], [51, 97, 116])
        self.assertEqual(functions['0x2027610']['locations']['evm_rpc/src/method_router.rs'], [151])

    def test_call_bytes_and_exclusive_fde_end(self):
        for edge in self.result['pinned_calls'].values():
            site = int(edge['site'], 16)
            raw = self.elf.read(site, 5)
            self.assertEqual(raw.hex(), edge['bytes'])
            self.assertEqual(site + 5 + struct.unpack('<i', raw[1:])[0], int(edge['target'], 16))
        starts, ends = mod.common.fde_index(self.elf)
        self.assertEqual(mod.common.containing(starts, ends, 0x27abc17), (0x27ab650, 0x27abc18))
        self.assertNotEqual(mod.common.containing(starts, ends, 0x27abc18), (0x27ab650, 0x27abc18))

    def test_rejects_corrupted_binaries_and_input(self):
        corrupt94 = self.binary94[:-1] + bytes([self.binary94[-1] ^ 1])
        corrupt115 = self.binary115[:-1] + bytes([self.binary115[-1] ^ 1])
        with self.assertRaises(mod.common.EvidenceError):
            mod.build(corrupt94, self.binary115, self.inputs)
        with self.assertRaises(mod.common.EvidenceError):
            mod.build(self.binary94, corrupt115, self.inputs)
        bad = dict(self.inputs)
        name = 'references/can1357-hl/evm_rpc/method_router.rs'
        bad[name] += b'\n'
        with self.assertRaises(mod.common.EvidenceError):
            mod.build(self.binary94, self.binary115, bad)
        bad = dict(self.inputs)
        name = 'research/imported/hl-node-115.inventory.json'
        bad[name] += b'\n'
        with self.assertRaises(mod.common.EvidenceError):
            mod.build(self.binary94, self.binary115, bad)

    def test_cli_wrong_binary_fails_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad'
            path.write_bytes(b'not the authenticated ELF')
            out = Path(directory) / 'out'
            p = subprocess.run([sys.executable, str(ROOT / 'tools/evm_rpc_method_path.py'),
                                '--binary', str(path), '--out', str(out)], capture_output=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b'SHA-256 mismatch', p.stderr)
            self.assertFalse(out.exists())

    def test_absent_string_does_not_anchor(self):
        rel = mod.common.relative_relocs(self.elf)
        leas = mod.common.lea_targets(self.elf)
        self.assertEqual(mod.common.tag_anchor(self.elf, 'eth_nonexistentRe011Control', leas, rel), [])

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_objdump_linear_table_and_calls(self):
        out = subprocess.run(['objdump', '-d', '--start-address=0x27ab650', '--stop-address=0x27abc18',
                              str(ROOT / 'artifacts/node/94/hl-node')], capture_output=True, text=True, check=True).stdout
        for method in self.result['methods']:
            for anchor in method['anchors']:
                for site in anchor['lea_sites']:
                    if site['fde'] and site['fde']['start'] == '0x27ab650':
                        address = site['va'][2:]
                        self.assertRegex(out, rf'(?m)^\s*{address}:\s+.*\blea\s+.*#\s*{anchor["anchor"][2:]}\b')
            use = method['table_use']
            self.assertRegex(out, rf'(?m)^\s*{use["length_site"][2:]}:\s+.*\bmov\s+\$0x{use["length"]:x},%ecx')
            self.assertRegex(out, rf'(?m)^\s*{use["call_site"][2:]}:\s+.*\bcall\s+{use["call_target"][2:]}\b')
        for edge in self.result['pinned_calls'].values():
            site = int(edge['site'], 16)
            text = subprocess.run(['objdump', '-d', f'--start-address={site:#x}', f'--stop-address={site+5:#x}',
                                   str(ROOT / 'artifacts/node/94/hl-node')], capture_output=True, text=True, check=True).stdout
            self.assertIn('call', text)
            self.assertIn(edge['target'][2:], text)

    def test_fork_matrix_is_release_bound(self):
        matrix = self.result['fork_matrix']
        self.assertEqual(matrix['94']['binary_sha256'], mod.SHA94)
        self.assertEqual(matrix['115']['binary_sha256'], mod.SHA115)
        self.assertEqual(matrix['94']['inventory_registry_crates']['revm'], ['19.2.0'])
        self.assertEqual(matrix['115']['inventory_forked_crates']['revm-precompile'], 12)
        self.assertNotIn('expensive_call_limiter.rs', matrix['94']['first_party_evm_rpc_files'])
        self.assertIn('expensive_call_limiter.rs', matrix['115']['first_party_evm_rpc_files'])


if __name__ == '__main__':
    unittest.main()
