import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-global-selector-got-initializers'
SPEC = importlib.util.spec_from_file_location('global_selector_collect', PACKET / 'collect.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GlobalSelectorEvidence(unittest.TestCase):
    def test_target_identity_is_checked_before_analysis(self):
        wrong = bytearray((ROOT / 'artifacts/node/115/hl-node').read_bytes())
        wrong[0] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'out'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                MODULE.collect(bytes(wrong), output)
            self.assertFalse(output.exists())

    def test_committed_packet_reproduces(self):
        with tempfile.TemporaryDirectory() as tmp:
            actual = MODULE.collect((ROOT / 'artifacts/node/115/hl-node').read_bytes(), Path(tmp) / 'out')
        expected = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(actual, expected)
        self.assertEqual(hashlib.sha256((ROOT / 'artifacts/node/115/hl-node').read_bytes()).hexdigest(), MODULE.SHA)


if __name__ == '__main__':
    unittest.main()
