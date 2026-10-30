import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_delayer_inventory as inv

PACKET = ROOT / 'research/work-items/action-delayer-inventory-94'
spec = importlib.util.spec_from_file_location('packet_verify', PACKET / 'verify.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ActionDelayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = inv.TARGET.read_bytes()
        cls.elf = inv.irp.Elf(cls.binary)
        cls.result = inv.build(cls.binary)

    def corrupted(self, va):
        b = bytearray(self.binary)
        b[self.elf.off(va)] ^= 1
        return bytes(b)

    def test_expected_census_and_thresholds(self):
        r = self.result
        self.assertEqual(r['fde_count'], 121299)
        loc = r['locations'][0]
        self.assertEqual((loc['path'], loc['line'], loc['column']), (inv.PATH, 246, 73))
        self.assertEqual(loc['references'][0]['fde'], ['0x392fcc0', '0x393033a'])
        self.assertEqual([x['reference_value'] for x in r['constants']], [0.76, 2.0, 10000, 110000, 100000000, 10000.0])
        self.assertEqual([x['status'] for x in r['constants']], ['co-located comparison'] * 2 + ['unresolved'] * 4)
        self.assertEqual(r['rodata_lea_anchors'][0]['target'], '0x5a802f')

    def test_scoped_fde_exclusive_boundaries(self):
        starts, ends = inv.irp.fde_index(self.elf)
        self.assertEqual(inv.irp.containing(starts, ends, inv.START), (inv.START, inv.END))
        self.assertEqual(inv.irp.containing(starts, ends, inv.END - 1), (inv.START, inv.END))
        self.assertNotEqual(inv.irp.containing(starts, ends, inv.START - 1), (inv.START, inv.END))
        self.assertNotEqual(inv.irp.containing(starts, ends, inv.END), (inv.START, inv.END))

    def test_regeneration_matches_packet_across_hash_seeds(self):
        self.assertEqual(inv.render(self.result), (PACKET / 'inventory.json').read_bytes())
        self.assertEqual(inv.excerpts(self.binary), (PACKET / 'excerpts.txt').read_bytes())
        with tempfile.TemporaryDirectory() as td:
            for seed in ('0', '7'):
                out = Path(td) / seed
                env = dict(os.environ, PYTHONHASHSEED=seed)
                p = subprocess.run([sys.executable, str(ROOT / 'tools/action_delayer_inventory.py'), '--out', str(out)], env=env, capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                for name in ('inventory.json', 'excerpts.txt'):
                    self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes())

    def test_digest_mismatch_never_writes(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / 'bad'; fake.write_bytes(self.corrupted(0x20a250))
            out = Path(td) / 'out'
            p = subprocess.run([sys.executable, str(ROOT / 'tools/action_delayer_inventory.py'), '--binary', str(fake), '--out', str(out)], capture_output=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b'sha256', p.stderr)
            self.assertFalse(out.exists())

    def test_pinned_semantics_fail_even_if_digest_is_recomputed(self):
        for va in (0x20a250, 0x3930034, 0x5a802f, 0x393023d, 0x570d838, 0x392ff24):
            with self.subTest(va=hex(va)):
                b = self.corrupted(va)
                with self.assertRaises(ValueError):
                    inv.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def test_verifier_rejects_packet_corruption_and_manifest_changes(self):
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'packet'; shutil.copytree(PACKET, copy, ignore=shutil.ignore_patterns('__pycache__'))
            for name in ('inventory.json', 'excerpts.txt', 'RESULT.md'):
                original = (copy / name).read_bytes()
                (copy / name).write_bytes(original + b'corrupt')
                with self.assertRaises(ValueError):
                    verifier.verify_packet(copy, ROOT)
                (copy / name).write_bytes(original)
            manifest = (copy / 'MANIFEST.sha256').read_text()
            original_json = (copy / 'inventory.json').read_bytes()
            tampered = original_json + b' '
            (copy / 'inventory.json').write_bytes(tampered)
            old_hash = hashlib.sha256(original_json).hexdigest()
            new_hash = hashlib.sha256(tampered).hexdigest()
            (copy / 'MANIFEST.sha256').write_text(manifest.replace(old_hash, new_hash))
            with self.assertRaisesRegex(ValueError, 'regeneration mismatch'):
                verifier.verify_packet(copy, ROOT)
            (copy / 'inventory.json').write_bytes(original_json)
            for altered in (manifest.replace('RESULT.md', 'OTHER.md'), manifest + manifest.splitlines()[0] + '\n',
                            manifest + '0' * 64 + '  ../outside\n'):
                (copy / 'MANIFEST.sha256').write_text(altered)
                with self.assertRaises(ValueError):
                    verifier.verify_packet(copy, ROOT)

    def test_malformed_target_rejected(self):
        with self.assertRaises(ValueError):
            inv.build(b'not elf')


if __name__ == '__main__':
    unittest.main()
