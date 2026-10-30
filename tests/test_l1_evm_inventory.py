import hashlib
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import l1_evm_inventory as inventory

PACKET = ROOT / 'research/work-items/l1-evm-inventory-94'
BIN = ROOT / 'artifacts/node/94/hl-node'


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()
        cls.result = inventory.build(cls.data)
        cls.elf = inventory.Elf(cls.data)

    def mutate(self, address, replacement):
        data = bytearray(self.data)
        off = self.elf.off(address)
        data[off:off + len(replacement)] = replacement
        return bytes(data)

    def structurally_build(self, data):
        # Model an authenticated but changed input to exercise structural controls;
        # the production API never accepts a caller-supplied digest.
        with patch.object(inventory, 'SHA256', hashlib.sha256(data).hexdigest()):
            return inventory.build(data)

    def test_counts_locations_and_edge(self):
        self.assertEqual(self.result['counts_by_file'], inventory.COUNTS)
        self.assertEqual((self.result['location_count'], self.result['reference_site_count'],
                          self.result['fde_count']), (10, 18, 11))
        self.assertEqual(self.result['call_edge']['bytes'], 'e854d7f6ff')
        self.assertEqual(self.result['call_edge']['to_fde'], '0x32699c0')
        self.assertTrue(all(x['status'] == 'unresolved' for x in self.result['reference_constants'].values()))
        self.assertEqual(inventory.render(self.result), (PACKET / 'l1-evm-inventory.json').read_bytes())
        self.assertEqual(inventory.excerpts(self.result), (PACKET / 'excerpts.txt').read_bytes())

    def test_digest_mismatch_rejected_before_writes(self):
        changed = self.data[:-1] + bytes([self.data[-1] ^ 1])
        with self.assertRaises(inventory.EvidenceError):
            inventory.build(changed)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad'; path.write_bytes(changed)
            out = Path(tmp) / 'output'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/l1_evm_inventory.py'),
                                   '--binary', str(path), '--out', str(out)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())

    def test_location_length_corruption_fails_closed(self):
        changed = self.mutate(0x56dfb28 + 8, struct.pack('<Q', 0))
        with self.assertRaises(inventory.EvidenceError):
            self.structurally_build(changed)

    def test_reference_retarget_fails_closed(self):
        changed = self.mutate(0x3269a6e + 3, b'\0\0\0\0')
        with self.assertRaises(inventory.EvidenceError):
            self.structurally_build(changed)

    def test_call_retarget_and_opcode_fail_closed(self):
        for addr, replacement in ((0x32fc267, b'\x90'),
                                  (0x32fc268, struct.pack('<i', 0x3269ae0 - (0x32fc267 + 5)))):
            with self.subTest(address=addr), self.assertRaises(inventory.EvidenceError):
                self.structurally_build(self.mutate(addr, replacement))

    def test_location_line_corruption_changes_regeneration(self):
        changed = self.mutate(0x56dfb28 + 16, struct.pack('<I', 70))
        self.assertNotEqual(inventory.render(self.structurally_build(changed)), inventory.render(self.result))

    def test_fde_end_exclusive(self):
        starts, ends = inventory.fde_index(self.elf)
        self.assertEqual(inventory.containing(starts, ends, 0x3269ad0), (0x32699c0, 0x3269ad1))
        self.assertNotEqual(inventory.containing(starts, ends, 0x3269ad1), (0x32699c0, 0x3269ad1))

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_objdump_instruction_boundaries_and_targets(self):
        for fde in self.result['fdes']:
            start, end = int(fde['start'], 16), int(fde['end_exclusive'], 16)
            output = subprocess.run(['objdump', '-d', f'--start-address={start}',
                                     f'--stop-address={end}', str(BIN)],
                                    capture_output=True, text=True, check=True).stdout
            for loc in self.result['locations']:
                for ref in loc['references']:
                    if int(ref['fde_start'], 16) == start:
                        site, slot = int(ref['site'], 16), int(loc['slot'], 16)
                        self.assertRegex(output, rf'(?m)^\s*{site:x}:\s+.*\blea\s+.*# {slot:x}\b')
            if start == inventory.EDGE_FROM:
                self.assertRegex(output, r'(?m)^\s*32fc267:\s+e8 54 d7 f6 ff\s+call\s+32699c0\b')

    def test_hashseed_and_cli_regeneration(self):
        for seed in ('0', '7'):
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run([sys.executable, str(ROOT / 'tools/l1_evm_inventory.py'), '--out', tmp],
                               env=dict(os.environ, PYTHONHASHSEED=seed), check=True)
                for name in ('l1-evm-inventory.json', 'excerpts.txt'):
                    self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes())

    def test_manifest_whitelist_and_tampering(self):
        spec = importlib.util.spec_from_file_location('evm_verify', PACKET / 'verify.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            for name in verifier.MANIFEST | {'MANIFEST.sha256'}:
                shutil.copyfile(PACKET / name, dest / name)
            verifier.check_packet(dest)
            manifest = (dest / 'MANIFEST.sha256').read_text()
            (dest / 'MANIFEST.sha256').write_text('\n'.join(x for x in manifest.splitlines() if not x.endswith('  RESULT.md')) + '\n')
            with self.assertRaises(ValueError):
                verifier.check_packet(dest)
            (dest / 'MANIFEST.sha256').write_text(manifest)
            (dest / 'RESULT.md').write_text('altered\n')
            with self.assertRaises(ValueError):
                verifier.check_packet(dest)


if __name__ == '__main__':
    unittest.main()
