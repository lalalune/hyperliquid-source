"""foundation_duration_guards main must report a missing artifact as one line, not a traceback."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MissingArtifactDiagnostics(unittest.TestCase):
    def test_missing_binary_is_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / 'no-such-hl-node'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'tools' / 'foundation_duration_guards.py'),
                 '--binary', str(missing)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn('Traceback (most recent call last)', result.stderr)
            lines = [line for line in result.stderr.splitlines() if line.strip()]
            self.assertEqual(len(lines), 1, result.stderr)
            self.assertTrue(lines[0].startswith('foundation_duration_guards:'), lines[0])


if __name__ == '__main__':
    unittest.main()
