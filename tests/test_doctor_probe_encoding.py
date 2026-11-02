import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from doctor import probe, probe_gnu


class UndecodableVersionOutput(unittest.TestCase):
    """A probed tool whose --version bytes are not valid UTF-8 is an
    unavailable tool with an error, not a crash of the whole preflight."""

    def path_with_raw(self, name, payload):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tool = Path(directory.name) / name
        # /bin/sh printf octal escapes emit the exact non-UTF-8 bytes.
        tool.write_text("#!/bin/sh\nprintf '" + payload + "'\n")
        tool.chmod(0o755)
        return directory.name

    def test_probe_reports_undecodable_output_as_unavailable(self):
        directory = self.path_with_raw('objdump', 'GNU objdump \\377\\376 2.44\\n')
        result = probe('objdump', [str(Path(directory) / 'objdump'), '--version'])
        self.assertFalse(result['available'])
        self.assertIn('error', result)
        self.assertIn('utf-8', result['error'])

    def test_probe_gnu_reports_undecodable_output_with_hint(self):
        directory = self.path_with_raw('objdump', 'GNU objdump \\377\\376 2.44\\n')
        with mock.patch.dict(os.environ, {'PATH': directory}):
            result = probe_gnu('objdump')
        self.assertFalse(result['available'])
        self.assertIn('error', result)
        self.assertIn('binutils', result['hint'])

    def test_decodable_gnu_output_still_available(self):
        directory = self.path_with_raw('objdump', 'GNU objdump (GNU Binutils) 2.44\\n')
        with mock.patch.dict(os.environ, {'PATH': directory}):
            result = probe_gnu('objdump')
        self.assertTrue(result['available'])
        self.assertEqual(result['version'], 'GNU objdump (GNU Binutils) 2.44')
        self.assertNotIn('hint', result)


if __name__ == '__main__':
    unittest.main()
