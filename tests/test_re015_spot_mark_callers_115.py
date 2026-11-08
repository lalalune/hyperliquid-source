import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'spot_mark_callers', ROOT / 'tools/re015_spot_mark_callers_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestSpotMarkCodecCallers(unittest.TestCase):
    def test_three_callers_emit_same_map_key_prefix(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(len(report['callers']), 3)
        self.assertEqual(report['msgpack_prefix']['bytes'],
                         ['0x81', '0xa1', '0x70', '0x92'])
        for row in report['callers']:
            self.assertLess(row['containing_fde']['start'], row['call_site'])
            self.assertLess(row['call_site'], row['containing_fde']['end'])
            self.assertEqual([entry['stored_byte'] for entry in row['prefix_stores']],
                             [0x81, 0xa1, 0x70, 0x92])

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
