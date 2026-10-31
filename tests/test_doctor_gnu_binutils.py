import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from doctor import probe_gnu, report


GNU = {'objdump': 'GNU objdump (GNU Binutils) 2.44', 'readelf': 'GNU readelf (GNU Binutils) 2.44'}
LLVM = {'objdump': 'Apple LLVM version 21.0.0', 'readelf': 'LLVM (http://llvm.org/):'}


class GnuBinutilsProbe(unittest.TestCase):
    def path_with(self, versions):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name, line in versions.items():
            tool = Path(directory.name) / name
            tool.write_text(f'#!/bin/sh\necho "{line}"\n')
            tool.chmod(0o755)
        return mock.patch.dict(os.environ, {'PATH': directory.name})

    def test_gnu_tools_are_available(self):
        with self.path_with(GNU):
            for name in GNU:
                result = probe_gnu(name)
                self.assertTrue(result['available'])
                self.assertEqual(result['version'], GNU[name])
                self.assertNotIn('hint', result)

    def test_llvm_tools_under_gnu_names_are_rejected(self):
        with self.path_with(LLVM):
            for name in LLVM:
                result = probe_gnu(name)
                self.assertFalse(result['available'])
                self.assertEqual(result['version'], LLVM[name])
                self.assertIn('binutils', result['hint'])

    def test_missing_tools_are_rejected(self):
        with self.path_with({}):
            for name in GNU:
                result = probe_gnu(name)
                self.assertFalse(result['available'])
                self.assertIn('hint', result)

    def test_report_requires_both_gnu_tools(self):
        def required(versions):
            with mock.patch('doctor.probe', side_effect=lambda name, command: {'name': name, 'available': True, 'version': versions.get(name, 'ok')}):
                return report()

        self.assertTrue(required(GNU)['analysis_ready'])
        self.assertFalse(required({**GNU, 'readelf': LLVM['readelf']})['analysis_ready'])
        self.assertFalse(required({**GNU, 'objdump': LLVM['objdump']})['analysis_ready'])
        names = [tool['name'] for tool in required(GNU)['required_tools']]
        self.assertIn('objdump', names)
        self.assertIn('readelf', names)


if __name__ == '__main__':
    unittest.main()
