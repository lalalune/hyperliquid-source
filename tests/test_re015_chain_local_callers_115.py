import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'chain_callers', ROOT / 'tools/re015_chain_local_callers_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestChainSerializerCallers(unittest.TestCase):
    def test_exact_direct_call_census_and_fde_ownership(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(report['total_direct_calls'], 52)
        self.assertEqual([row['direct_call_count'] for row in report['direct_callers']],
                         [17, 17, 18])
        for group in report['direct_callers']:
            for row in group['sites']:
                self.assertEqual(row['call_bytes'][:2], 'e8')
                self.assertLessEqual(row['fde_start'], row['call_site'])
                self.assertLess(row['call_site'], row['fde_end'])

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
