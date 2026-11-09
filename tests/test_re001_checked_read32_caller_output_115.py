import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'checked_read32_caller', ROOT / 'tools/re001_checked_read32_caller_output_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestCheckedRead32CallerOutput(unittest.TestCase):
    def test_tag_branch_wraps_distinct_helper_byte_ranges(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(report['tag_1_result']['payload_source'], 'helper output bytes [8,40)')
        self.assertEqual(report['other_result']['payload_source'], 'helper output bytes [1,33)')
        self.assertEqual(report['caller_fde'], {'start': 0x4e182e0, 'end': 0x4e18353})

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
