import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'byte_prefix_caller', ROOT / 'tools/re001_byte_prefix_caller_output_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestBytePrefixCallerOutput(unittest.TestCase):
    def test_four_direct_calls_and_distinct_tag_nine_values(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual([row['call_site'] for row in report['calls']],
                         [0x534f9b1, 0x534fb6b, 0x534ff57, 0x5350475])
        self.assertEqual([row['tag_9_action']['u64_value'] for row in report['calls']],
                         [99, 133, 60, 38])
        self.assertEqual(report['non_9_output_copy']['effect'],
                         'copy 32 local-output bytes at rsp+0 to rbx+8')

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
