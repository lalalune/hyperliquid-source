"""Native corruption controls for node94's initial reply policy."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-greeting-policy-94'
spec = importlib.util.spec_from_file_location('greeting_policy_evidence', PACKET / 'verify.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class PolicyEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.layout = subject.Image(cls.data)

    def test_authenticated_record(self):
        self.assertEqual(subject.analyze(self.data), json.loads((PACKET / 'records.json').read_text()))

    def test_each_instruction_corruption_is_rejected(self):
        for row in subject.ANCHORS['facts']:
            with self.subTest(address=row['address']):
                changed = bytearray(self.data)
                changed[self.layout.offset(row['address'])] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    subject.inspect(changed, self.layout)

    def test_tables_strings_relocations_and_import_are_bound(self):
        offsets = [self.layout.offset(int(r['address'], 16)) for r in subject.ANCHORS['tables'].values()]
        offsets += [self.layout.offset(int(r['address'], 16)) for r in subject.ANCHORS['strings']]
        offsets += [r['file_offset'] + 8 for r in subject.ANCHORS['relocations']]
        offsets += [r['file_offset'] for r in subject.ANCHORS['imports'].values()]
        for off in offsets:
            changed = bytearray(self.data); changed[off] ^= 1
            with self.assertRaises(ValueError):
                subject.inspect(changed, self.layout)

    def test_full_bodies_and_instruction_starts(self):
        for row in subject.ANCHORS['ranges'].values():
            changed = bytearray(self.data); changed[self.layout.offset(row['end'] - 1)] ^= 1
            with self.assertRaises(ValueError):
                subject.inspect(changed, self.layout)
        for provider in ['gnu', 'llvm']:
            starts = set()
            for name in subject.ANCHORS['ranges']:
                text = (PACKET / f'{name}.{provider}.txt').read_text()
                starts |= {int(m[1], 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', text, re.M)}
            self.assertTrue(all(r['address'] in starts for r in subject.ANCHORS['facts']))

    def test_structural_seam_does_not_authenticate(self):
        self.assertEqual(subject.inspect(self.data, self.layout)['origin'], 'unqualified structural inspection')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
