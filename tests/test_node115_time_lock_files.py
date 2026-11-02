"""Target-bound evidence for time-lock filename collection; no capture execution."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-time-lock-files'


def load(name):
    spec = importlib.util.spec_from_file_location('time_lock_files_' + name, PACKET / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TimeLockFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load('verify')
        cls.data = cls.v.TARGET.read_bytes()
        if cls.data.startswith(b'version https://git-lfs'):
            raise unittest.SkipTest('pinned node115 LFS input not materialized')

    def test_complete_exports_and_call_data_bindings(self):
        result = self.v.build(self.data)
        self.assertEqual(result, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(result['measured_bytes'], 3614)
        self.assertEqual([(r['role'],r['instructions']) for r in result['bodies']],
                         [('collector',244),('caller',459),('directory',124)])
        self.assertEqual(result['dynamic_imports'][0]['symbol']['name'], 'bcmp')

    def test_semantic_corruptions_below_integrity_guards(self):
        result = self.v.controls(self.data)
        self.assertEqual(result, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(result['rejected']), 73)
        self.assertFalse(result['survived'])

    def test_independent_integrity_guards(self):
        v = self.v
        changed = bytearray(self.data)
        changed[v.Image(changed).off(0x5961a30)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            v.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            v.observe(changed)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            v.observe(changed, body_hashes=False)
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            v.build(self.data[:-1])

    def test_ascii_overflow_and_in_place_geometry(self):
        result = load('algebra').verify(self.data)
        self.assertEqual(result, json.loads((PACKET / 'algebra.json').read_text()))
        self.assertEqual(len(result['decimal_boundary_steps']), 70)
        self.assertEqual(result['in_place_geometry_cases'], 8256)
        self.assertEqual(len(result['counterfacts']), 5)


if __name__ == '__main__':
    unittest.main()
