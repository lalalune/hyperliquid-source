"""Node94 bloom-prefilter evidence, independent of running the captured image."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-evm-bloom-prefilter-94'
spec = importlib.util.spec_from_file_location('bloom_evidence', PACKET / 'verify.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class BloomEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / evidence.BINARY).read_bytes()

    def test_authenticated_evidence_regenerates(self):
        self.assertEqual(evidence.build(self.data), json.loads((PACKET / 'records.json').read_text()))

    def test_control_flow_vector_and_relocation_corruption(self):
        results = evidence.controls(self.data)
        self.assertEqual(len(results), 9)
        # The first eight reject at structural checks, not only the outer digest.
        self.assertTrue(all('SHA-256' not in row['rejection'] for row in results[:8]))

    def test_other_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'wrong node94 SHA-256'):
            evidence.build(b'\x7fELF' + bytes(4096))


if __name__ == '__main__':
    unittest.main()
