"""Static controls for the greeting request and selected reply reader arguments."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-greeting-frame-exchange-94'
spec = importlib.util.spec_from_file_location('greeting_exchange_evidence', PACKET / 'verify.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class GreetingExchangeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.image = subject.Image(cls.data)

    def test_current_record_is_authenticated_and_matches(self):
        self.assertEqual(subject.analyze(self.data), json.loads((PACKET / 'records.json').read_text()))

    def test_all_selected_instruction_corruptions_are_rejected_below_digest(self):
        for row in subject.ANCHORS['facts']:
            with self.subTest(address=row['address']):
                changed = bytearray(self.data)
                changed[self.image.offset(int(row['address'], 16))] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    subject.inspect(changed)

    def test_native_tools_agree_on_all_selected_instruction_starts(self):
        for tool in ['gnu', 'llvm']:
            starts = set()
            for name in subject.ANCHORS['ranges']:
                text = (PACKET / f'{name}.{tool}.txt').read_text()
                starts |= {int(m[1], 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', text, re.M)}
            self.assertTrue(all(int(row['address'], 16) in starts for row in subject.ANCHORS['facts']))

    def test_authentication_is_required_for_origin(self):
        self.assertEqual(subject.inspect(self.data)['origin'], 'unqualified structural inspection')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
