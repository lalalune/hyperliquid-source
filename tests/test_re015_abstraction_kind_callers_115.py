import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'abstraction_callers', ROOT / 'tools/re015_abstraction_kind_callers_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestAbstractionKindCallers(unittest.TestCase):
    def test_exact_five_visitor_seven_call_census(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(report['total_direct_calls'], 7)
        self.assertEqual([row['direct_call_count'] for row in report['callers']],
                         [1, 1, 1, 2, 2])
        for group in report['callers']:
            for row in group['sites']:
                self.assertLessEqual(row['fde_start'], row['call_site'])
                self.assertLess(row['call_site'], row['fde_end'])

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
