import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea

GARBAGE = "#!/bin/sh\nprintf '\\377\\376 2.44\\n'\n"
VALID = "#!/bin/sh\necho v24.22.1\n"
UNSUPPORTED = "#!/bin/sh\necho v24.15.0\n"


def write_stub(directory, body):
    stub = Path(directory) / 'node'
    stub.write_text(body)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub


@unittest.skipUnless(os.name == 'posix', 'POSIX shell stub executables')
class FindNodeUndecodableVersionTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop('REA_NODE', None)

    def tearDown(self):
        if self._env is not None:
            os.environ['REA_NODE'] = self._env
        else:
            os.environ.pop('REA_NODE', None)

    def select_from_path(self, bodies):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        home = root / 'home'
        home.mkdir()
        directories = []
        stubs = {}
        for name, body in bodies:
            directory = root / name
            directory.mkdir()
            stubs[name] = write_stub(directory, body)
            directories.append(str(directory))
        with mock.patch.dict(os.environ, {'PATH': os.pathsep.join(directories)}), \
                mock.patch.object(rea.Path, 'home', return_value=home):
            return rea.find_node(), stubs

    def test_explicit_undecodable_version_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = write_stub(tmp, GARBAGE)
            os.environ['REA_NODE'] = str(stub)
            with self.assertRaisesRegex(ValueError, 'needs Node'):
                rea.find_node()

    def test_undecodable_path_candidate_does_not_block_supported_node(self):
        selected, stubs = self.select_from_path([('garbage', GARBAGE), ('valid', VALID)])
        self.assertEqual(selected, stubs['valid'].resolve())

    def test_undecodable_candidate_after_unsupported_still_reaches_supported(self):
        selected, stubs = self.select_from_path(
            [('unsupported', UNSUPPORTED), ('garbage', GARBAGE), ('valid', VALID)])
        self.assertEqual(selected, stubs['valid'].resolve())

    def test_explicit_supported_control_is_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = write_stub(tmp, VALID)
            os.environ['REA_NODE'] = str(stub)
            self.assertEqual(rea.find_node(), stub.resolve())


if __name__ == '__main__':
    unittest.main()
