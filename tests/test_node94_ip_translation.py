"""Target-backed static checks for the bounded IP translation packet."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node94-ip-translation'
spec = importlib.util.spec_from_file_location('ip_translation_evidence', PACKET / 'verify.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class IpTranslationEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()

    def test_published_evidence_regenerates(self):
        report = evidence.build(self.data)
        report['retained_instructions'] = evidence.verify_exports(self.data)
        self.assertEqual(report, json.loads((PACKET / 'records.json').read_text()))

    def test_structural_corruptions_without_digest_guards(self):
        controls = evidence.controls(self.data)
        self.assertEqual(len(controls), 14)
        self.assertTrue(all('digest' not in row['rejection'] and 'SHA-256' not in row['rejection'] for row in controls))

    def test_rust_table_is_the_eight_initializer_immediates(self):
        source = (ROOT / 'src/node94-ip-translation/lib.rs').read_text()
        import re
        rows = re.findall(r'^    \[([0-9, ]+)\],$', source, re.M)
        expected = [list(bytes.fromhex(raw)) for _, raw, _ in evidence.TABLE]
        self.assertEqual([[int(n.strip()) for n in row.split(',')] for row in rows], expected)
        self.assertEqual(len({tuple(r[:4]) for r in expected}), 8)
        self.assertEqual(len({tuple(r[4:]) for r in expected}), 8)

    def test_wrong_image_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'wrong node94 SHA-256'):
            evidence.build(b'\x7fELF' + bytes(4096))


if __name__ == '__main__':
    unittest.main()
