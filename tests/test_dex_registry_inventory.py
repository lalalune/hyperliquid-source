import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import dex_registry_inventory as inv

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/dex-registry-inventory-94'


class RegistryInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = inv.TARGET.read_bytes()
        cls.reference = inv.REF.read_bytes()
        cls.result = inv.build(cls.data, cls.reference)
        cls.elf = inv.elfutil.Elf(cls.data)

    def test_regeneration_byte_identical(self):
        self.assertEqual(inv.render(self.result), (PACKET / 'inventory.json').read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(ROOT / 'tools/dex_registry_inventory.py'), '--out', tmp], check=True)
            self.assertEqual((Path(tmp) / 'inventory.json').read_bytes(), inv.render(self.result))

    def test_digest_mismatch_and_no_output(self):
        corrupt = bytearray(self.data)
        corrupt[0x333140f] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            inv.build(bytes(corrupt), self.reference)
        with self.assertRaisesRegex(ValueError, 'node #94 SHA-256 mismatch'):
            inv.build(self.data[:-1], self.reference)
        with self.assertRaisesRegex(ValueError, 'node #94 SHA-256 mismatch'):
            inv.build((ROOT / 'artifacts/node/115/hl-node').read_bytes(), self.reference)
        with self.assertRaisesRegex(ValueError, 'reference file SHA-256 mismatch'):
            inv.build(self.data, self.reference + b' ')
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'bad-node'
            binary.write_bytes(corrupt)
            out = Path(tmp) / 'out'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/dex_registry_inventory.py'), '--binary', str(binary), '--out', str(out)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())

    def test_reference_inventory(self):
        text = self.reference.decode()
        arr = re.search(r'const RESERVED_DEX_NAMES:.*?= &\[(.*?)\];', text, re.S)
        self.assertEqual(re.findall(r'"([a-z]+)"', arr.group(1)), list(inv.NAMES))
        for group, expected in [('DexStatus', inv.STATUS), ('RegistryError', inv.ERRORS)]:
            body = re.search(r'pub enum ' + group + r'\s*\{([^}]*)\}', text).group(1)
            self.assertEqual(re.findall(r'^\s*(\w+)\s*,', body, re.M), list(expected))
        for name, value in [('ASSETS_PER_DEX', '10_000'), ('MAX_DEX_COUNT', '2_000'), ('MAX_FULL_NAME_BYTES', '50'), ('SUCCESS_RESULT_TAG', '390')]:
            self.assertRegex(text, rf'const {name}:\s*\w+\s*=\s*{value};')

    def test_locations_and_bounds(self):
        self.assertEqual(self.result['location_counts'], {'l1/src/dex_registry/clearinghouses.rs': 2, 'l1/src/dex_registry/dex_registry.rs': 1, 'l1/src/dex_registry/perp_dex.rs': 2})
        self.assertEqual(len(self.result['location_fde_owners']), 390)
        starts, ends = inv.elfutil.fde_index(self.elf)
        self.assertEqual(inv.bounds(starts, ends, 0x3330f30)['start'], '0x3330f30')
        self.assertEqual(inv.bounds(starts, ends, 0x3331d55)['end_exclusive'], '0x3331d56')
        self.assertNotEqual(inv.bounds(starts, ends, 0x3331d56), {'start': '0x3330f30', 'end_exclusive': '0x3331d56'})
        for row in self.result['locations']:
            slot = int(row['slot_va'], 16)
            self.assertEqual(self.elf.read(slot, 24).hex(), row['record_bytes'])

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_objdump_all_reserved_name_leas_and_threshold(self):
        output = subprocess.run(['objdump', '-d', '--start-address=0x3330f30', '--stop-address=0x33315cd', str(inv.TARGET)], check=True, capture_output=True, text=True).stdout
        for name in self.result['reserved_names']:
            site, target = int(name['comparison_lea_va'], 16), int(name['anchor_va'], 16)
            self.assertRegex(output, rf'(?m)^\s*{site:x}:.*\blea\s+.*# {target:x}\b')
        self.assertRegex(output, r'(?m)^\s*3330f4f:.*cmpq\s+\$0x7cf,')
        self.assertRegex(output, r'(?m)^\s*3330f57:.*jbe\s+')

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_objdump_10000_candidate(self):
        output = subprocess.run(['objdump', '-d', '--start-address=0x2744b2f', '--stop-address=0x2744b39', str(inv.TARGET)], check=True, capture_output=True, text=True).stdout
        self.assertRegex(output, r'(?m)^\s*2744b2f:.*cmpq\s+\$0x2710,')


if __name__ == '__main__':
    unittest.main()
