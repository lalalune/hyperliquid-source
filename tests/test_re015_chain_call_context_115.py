import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'chain_call_context', ROOT / 'tools/re015_chain_call_context_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestChainCallContext(unittest.TestCase):
    def test_call_key_literal_and_fde(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(report['caller']['direct_call_site'], 0x24062c7)
        self.assertEqual(report['caller']['codec_entry'], 0x2674b80)
        self.assertEqual(report['map_key']['text'], 'hyperliquidChain')
        self.assertEqual(report['map_key']['marker'], 0xb0)
        self.assertEqual(report['caller']['fde'], {'start': 0x2406120, 'end': 0x24064e4})

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
