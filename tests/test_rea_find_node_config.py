import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class FindNodeConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)
        self._env = os.environ.pop('REA_NODE', None)

    def tearDown(self):
        rea.CONFIG = self._config
        if self._env is not None:
            os.environ['REA_NODE'] = self._env
        else:
            os.environ.pop('REA_NODE', None)

    def test_missing_preferred_node_fails_closed(self):
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'preferred_node'}
        with self.assertRaisesRegex(ValueError, 'missing preferred_node'):
            rea.find_node()

    def test_explicit_node_ignores_missing_preferred_node(self):
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'preferred_node'}
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / 'node'
            stub.write_text('#!/bin/sh\necho v24.22.1\n')
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            os.environ['REA_NODE'] = str(stub)
            self.assertEqual(rea.find_node(), stub.resolve())

    def test_present_preferred_node_still_fails_closed_without_node(self):
        with mock.patch('shutil.which', return_value=None), \
                mock.patch.object(Path, 'glob', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'needs Node'):
                rea.find_node()


if __name__ == '__main__':
    unittest.main()
