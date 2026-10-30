import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import clearinghouse_oracle_inventory as inv

PACKET = ROOT / 'research/work-items/clearinghouse-oracle-inventory-94'
spec = importlib.util.spec_from_file_location('oracle_verify', PACKET / 'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
DATA = inv.TARGET.read_bytes() if inv.TARGET.exists() else None


@unittest.skipIf(DATA is None, 'pinned node #94 absent')
class OracleInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = inv.build(DATA)
        cls.elf = inv.Elf(DATA)
        cls.expected = inv.render(cls.result)

    def mutate(self, va, replacement):
        data = bytearray(DATA)
        offset = self.elf.off(va)
        self.assertIsNotNone(offset)
        data[offset:offset + len(replacement)] = replacement
        return bytes(data)

    def adversarial_build(self, data):
        # Test semantic checks after bypassing only the identity check; production
        # has no switch for replacing the expected digest.
        with patch.object(inv, 'SHA256', hashlib.sha256(data).hexdigest()):
            return inv.build(data)

    def test_census(self):
        r = self.result
        self.assertEqual((r['location_count'], r['lea_count'], r['owning_fde_count']), (21, 72, 67))
        self.assertEqual(r['location_counts_by_basename'], {'oracle.rs': 21})
        self.assertEqual(r['fde_table_count'], 121299)
        self.assertEqual(r['first_party_location_count'], 1186)
        self.assertTrue(all('/oracle/' in x['path'] and 'margin_table' not in x['path'] for x in r['locations']))

    def test_anchors_and_edge(self):
        r = self.result
        self.assertEqual([x['length'] for x in r['diagnostics'] if x['status'] == 'bound'], [24, 41])
        self.assertEqual(sum(x['status'] == 'unresolved' for x in r['diagnostics']), 7)
        self.assertTrue(all(x['status'] == 'unresolved' for x in r['constants']))
        self.assertEqual(r['call_edge']['bytes'], 'e89244ffff')
        self.assertEqual(r['call_edge']['destination_fde'], '0x26ebdc0')

    def test_regeneration(self):
        self.assertEqual(self.expected, (PACKET / 'oracle-inventory.json').read_bytes())
        self.assertEqual(inv.excerpts(DATA, self.result), (PACKET / 'byte-excerpts.txt').read_bytes())
        verify.verify_manifest(PACKET)

    def test_wrong_digest_rejected(self):
        data = bytearray(DATA)
        data[-1] ^= 1
        with self.assertRaises(inv.EvidenceError):
            inv.build(bytes(data))

    def test_cli_bad_target_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'bad'
            source.write_bytes(b'not the target')
            out = Path(tmp) / 'out'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/clearinghouse_oracle_inventory.py'),
                                   '--binary', str(source), '--out', str(out)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())

    def test_corrupt_literal_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x584655, b'X'))

    def test_corrupt_length_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x326149e, b'\x17'))

    def test_corrupt_literal_lea_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x32614a5, b'\x00\x00\x00\x00'))

    def test_corrupt_call_opcode_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x26f7929, b'\x90'))

    def test_retarget_call_to_other_fde_rejected(self):
        disp = 0x26f4cd0 - (0x26f7929 + 5)
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x26f792a, struct.pack('<i', disp)))

    def test_location_length_corruption_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x56df7b8, struct.pack('<Q', 0)))

    def test_location_xref_corruption_rejected(self):
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(0x3261349, b'\0\0\0\0'))

    def test_location_line_corruption_changes_evidence(self):
        altered = self.adversarial_build(self.mutate(0x56df7c0, struct.pack('<I', 628)))
        self.assertNotEqual(inv.render(altered), self.expected)
        row = next(x for x in altered['locations'] if x['slot'] == '0x56df7b0')
        self.assertEqual(row['line'], 628)

    def test_location_path_corruption_rejected(self):
        path_va = int(next(x['path_pointer'] for x in self.result['locations']
                           if x['slot'] == '0x56df7b0'), 16)
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(path_va, b'X'))

    def test_location_relocation_corruption_rejected(self):
        _, off, size = self.elf.sections['.rela.dyn']
        pos = next(i for i in range(off, off + size, 24)
                   if struct.unpack_from('<Q', DATA, i)[0] == 0x56df7b0)
        data = bytearray(DATA)
        struct.pack_into('<q', data, pos + 16, 0)
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(bytes(data))

    def test_fde_range_corruption_rejected(self):
        va, off, _ = self.elf.sections['.eh_frame_hdr']
        count = struct.unpack_from('<I', DATA, off + 8)[0]
        fde = None
        for i in range(count):
            entry = off + 12 + 8 * i
            if va + struct.unpack_from('<i', DATA, entry)[0] == 0x3261290:
                fde = va + struct.unpack_from('<i', DATA, entry + 4)[0]
                break
        self.assertIsNotNone(fde)
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(fde + 12, struct.pack('<I', 0)))

    def test_relocated_scope_path(self):
        self.assertTrue(inv.in_scope('l1/relocated/clearinghouse/oracle/nested/oracle.rs'))
        self.assertFalse(inv.in_scope('l1/src/clearinghouse/margin_table.rs'))
        self.assertFalse(inv.in_scope('other/clearinghouse/oracle/oracle.rs'))

    def test_fde_header_corruption_rejected(self):
        va = self.elf.sections['.eh_frame_hdr'][0]
        with self.assertRaises(inv.EvidenceError):
            self.adversarial_build(self.mutate(va, b'\x00'))

    def test_hashseed_independence(self):
        for seed in ('0', '7'):
            with tempfile.TemporaryDirectory() as tmp:
                env = dict(os.environ, PYTHONHASHSEED=seed)
                subprocess.run([sys.executable, str(ROOT / 'tools/clearinghouse_oracle_inventory.py'),
                                '--out', tmp], env=env, check=True, capture_output=True)
                self.assertEqual((Path(tmp) / 'oracle-inventory.json').read_bytes(), self.expected)
                self.assertEqual((Path(tmp) / 'byte-excerpts.txt').read_bytes(),
                                 (PACKET / 'byte-excerpts.txt').read_bytes())


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.packet = Path(self.tmp.name)
        for name in verify.MANIFEST | {'MANIFEST.sha256'}:
            shutil.copyfile(PACKET / name, self.packet / name)

    def test_manifest_control(self):
        verify.verify_manifest(self.packet)

    def test_manifest_missing_entry_rejected(self):
        p = self.packet / 'MANIFEST.sha256'
        p.write_text('\n'.join(p.read_text().splitlines()[1:]) + '\n')
        with self.assertRaises(ValueError):
            verify.verify_manifest(self.packet)

    def test_manifest_duplicate_rejected(self):
        p = self.packet / 'MANIFEST.sha256'
        p.write_text(p.read_text() + p.read_text().splitlines()[0] + '\n')
        with self.assertRaises(ValueError):
            verify.verify_manifest(self.packet)

    def test_manifest_traversal_rejected(self):
        p = self.packet / 'MANIFEST.sha256'
        p.write_text(p.read_text() + '0' * 64 + '  ../outside\n')
        with self.assertRaises(ValueError):
            verify.verify_manifest(self.packet)

    def test_packet_corruption_rejected(self):
        p = self.packet / 'RESULT.md'
        p.write_bytes(p.read_bytes() + b'\ncorrupt')
        with self.assertRaises(ValueError):
            verify.verify_manifest(self.packet)


if __name__ == '__main__':
    unittest.main()
