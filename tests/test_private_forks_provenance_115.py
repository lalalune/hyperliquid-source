"""Tests for RE-002-node115-private-forks-provenance."""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-private-forks-provenance'
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(PACKET))

from artifacts import manifest_item
from elf_index import sections
import verify as fork_verify


class PrivateForksProvenance115Tests(unittest.TestCase):
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
        summary = fork_verify.verify_records(self.rec, self.elf, self.secs)
        self.assertEqual(summary['forks'], 8)
        self.assertEqual(summary['overflow_sites'], 50151)
        self.assertEqual(summary['locations'], 712)
        self.assertGreater(summary['xrefs'], 1000)

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
        # 1. Corrupt target digest
        bad = copy.deepcopy(self.rec)
        bad['target']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Target digest'):
            fork_verify.verify_records(bad, self.elf, self.secs)

        # 2. Corrupt GOT overflow slot target
        bad = copy.deepcopy(self.rec)
        bad['overflow_checks_observation']['got_slots'][0]['target_va'] = '0x1681da1'
        with self.assertRaisesRegex(ValueError, 'does not relocate'):
            fork_verify.verify_records(bad, self.elf, self.secs)

        # 3. Corrupt overflow site count
        bad = copy.deepcopy(self.rec)
        bad['overflow_checks_observation']['total_text_call_jmp_sites'] += 1
        with self.assertRaisesRegex(ValueError, 'Overflow site count mismatch'):
            fork_verify.verify_records(bad, self.elf, self.secs)

        # 4. Corrupt bincode-fork Location line number
        bad = copy.deepcopy(self.rec)
        bad['forks']['bincode-fork']['locations'][0]['line'] += 1
        with self.assertRaisesRegex(ValueError, 'fields mismatch'):
            fork_verify.verify_records(bad, self.elf, self.secs)

        # 5. Corrupt xref site VA
        bad = copy.deepcopy(self.rec)
        bad['forks']['reth-chainspec']['locations'][0]['xref_sites'][0]['site_va'] = '0x5bccf90'
        with self.assertRaisesRegex(ValueError, 'not RIP-relative LEA|does not target'):
            fork_verify.verify_records(bad, self.elf, self.secs)


if __name__ == '__main__':
    unittest.main()
