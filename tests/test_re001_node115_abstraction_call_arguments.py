import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'abstraction_call_abi', ROOT / 'research/work-items/RE-001-node115-abstraction-call-arguments/collect.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestAbstractionKindCallABI(unittest.TestCase):
    def test_seven_calls_have_three_verified_register_producers(self):
        report = module.extract()
        self.assertEqual(len(report['calls']), 7)
        self.assertEqual(len({row['visitor_entry'] for row in report['calls']}), 5)
        self.assertTrue(all([arg['register'] for arg in row['arguments']] == ['rdi', 'rsi', 'rdx']
                            for row in report['calls']))

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(binary=ROOT / 'README.md')


if __name__ == '__main__':
    unittest.main()
