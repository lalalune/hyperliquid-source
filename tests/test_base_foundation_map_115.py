"""Tests for RE-001-node115-base-foundation-map."""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-base-foundation-map'
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(PACKET))

from artifacts import manifest_item
from elf_index import sections
import verify as base_verify


class BaseFoundationMap115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rec = json.loads((PACKET / 'records.json').read_text(encoding='utf-8'))
        rel = cls.rec['target']['path']
        item = manifest_item(ROOT, rel)
        cls.elf = (ROOT / rel).read_bytes()
        assert len(cls.elf) == item['size']
        assert hashlib.sha256(cls.elf).hexdigest() == item['sha256']
        cls.secs = sections(cls.elf)

    def test_positive_elf_verification(self):
        summary = base_verify.verify_records(self.rec, self.elf, self.secs)
        self.assertEqual(summary['files'], 33)
        self.assertEqual(summary['locations'], 247)
        self.assertEqual(summary['rodata_anchors'], 12)
        self.assertEqual(summary['time_fde_size'], 273)

    def test_manifest_sha256_complete(self):
        manifest = (PACKET / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
        entries = {}
        for line in manifest:
            if not line.strip():
                continue
            digest, rel = line.split('  ', 1)
            entries[rel] = digest
        self.assertEqual(set(entries), {'README.md', 'records.json', 'verify.py'})
        for rel, digest in entries.items():
            actual = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f'Digest mismatch for {rel}')

    def test_negative_controls_detect_corruption(self):
        bad = copy.deepcopy(self.rec)
        bad['target']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'Target digest'):
            base_verify.verify_records(bad, self.elf, self.secs)

        bad = copy.deepcopy(self.rec)
        bad['rodata_anchors'][0]['ascii'] = bad['rodata_anchors'][0]['ascii'][:-1] + '0'
        with self.assertRaisesRegex(ValueError, 'bytes mismatch'):
            base_verify.verify_records(bad, self.elf, self.secs)

        bad = copy.deepcopy(self.rec)
        bad['time_unix_day_fde']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA-256 or size mismatch'):
            base_verify.verify_records(bad, self.elf, self.secs)

        bad = copy.deepcopy(self.rec)
        bad['files']['cid.rs']['locations'][0]['line'] += 1
        with self.assertRaisesRegex(ValueError, 'fields mismatch'):
            base_verify.verify_records(bad, self.elf, self.secs)

        bad = copy.deepcopy(self.rec)
        bad['files']['time.rs']['locations'][0]['first_xref_site'] = '0x15027d0'
        with self.assertRaisesRegex(ValueError, 'not RIP-relative LEA|does not target'):
            base_verify.verify_records(bad, self.elf, self.secs)


if __name__ == '__main__':
    unittest.main()
