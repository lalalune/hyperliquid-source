"""Authenticated native bindings and immutable peer-fixture controls."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-greeting-reply-94'
spec = importlib.util.spec_from_file_location('greeting_reply_evidence', PACKET / 'verify.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class ReplyEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.layout = subject.Layout(cls.data)

    def test_current_authenticated_record(self):
        self.assertEqual(subject.analyze(self.data), json.loads((PACKET / 'records.json').read_text()))

    def test_every_selected_instruction_corruption_is_rejected(self):
        for row in subject.ANCHORS['facts']:
            with self.subTest(address=row['address']):
                changed = bytearray(self.data)
                changed[self.layout.image.offset(row['address'])] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    subject.inspect(changed, self.layout)

    def test_each_body_is_bound_even_outside_selected_anchors(self):
        for row in subject.ANCHORS['ranges'].values():
            changed = bytearray(self.data)
            changed[self.layout.image.offset(row['start'])] ^= 1
            with self.assertRaises(ValueError):
                subject.inspect(changed, self.layout)

    def test_dispatch_relocations_and_compiler_path_are_bound(self):
        offsets = [self.layout.image.offset(int(a, 16)) for a in subject.ANCHORS['tables']]
        offsets += [off + 8 for off in self.layout.relocations.values()]
        offsets.append(subject.ANCHORS['compiler_path']['file_offset'])
        offsets += [row['file_offset'] for row in subject.ANCHORS['imports'].values()]
        for off in offsets:
            changed = bytearray(self.data)
            changed[off] ^= 1
            with self.assertRaises(ValueError):
                subject.inspect(changed, self.layout)

    def test_native_instruction_starts_agree(self):
        for provider in ['gnu', 'llvm']:
            starts = set()
            for name in subject.ANCHORS['ranges']:
                text = (PACKET / f'{name}.{provider}.txt').read_text()
                starts |= {int(m[1], 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', text, re.M)}
            self.assertTrue(all(r['address'] in starts for r in subject.ANCHORS['facts']))

    def test_frozen_fixtures_reject_one_byte_changes(self):
        for name in subject.FIXTURES:
            raw = bytearray((PACKET / 'fixtures' / f'{name}.jsonl.gz').read_bytes())
            subject.fixture_bytes(name, raw)
            raw[-1] ^= 1
            with self.assertRaisesRegex(ValueError, 'fixture identity changed'):
                subject.fixture_bytes(name, raw)

    def test_authentication_cannot_be_replaced_by_structural_checks(self):
        self.assertEqual(subject.inspect(self.data, self.layout)['origin'], 'unqualified structural inspection')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
