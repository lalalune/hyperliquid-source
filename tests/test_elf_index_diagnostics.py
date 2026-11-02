"""elf_index must report a missing/wrong artifact as one line, not a traceback."""
import contextlib
import io
import runpy
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import artifacts  # noqa: E402
import elf_index  # noqa: E402


class MissingArtifactDiagnostics(unittest.TestCase):
    def test_missing_artifact_is_one_line(self):
        stderr = io.StringIO()
        # Other discovered tests may load a fresh artifacts module. Patch the
        # exact object imported by the CLI at invocation, not an earlier alias.
        with mock.patch.object(sys.modules['artifacts'], 'check', side_effect=ValueError('Missing artifact: x')), \
                mock.patch.object(sys, 'argv', ['elf_index.py', '--release', '115']), \
                contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(ROOT / "tools/elf_index.py"), run_name="__main__")
        self.assertEqual(caught.exception.code, 1)
        lines = [line for line in stderr.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith('elf_index: Missing artifact:'), lines[0])


if __name__ == '__main__':
    unittest.main()
