import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ghidra_plan import render_import_plan


class GhidraPlanShellTests(unittest.TestCase):
    def test_native_plan_executes_only_the_marker_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory(prefix="Ghidra tools' fixture ") as temp:
            root = Path(temp)
            support = root / 'support'
            support.mkdir()
            marker = root / 'record arguments.py'
            marker.write_text('import json,sys\nprint(json.dumps(sys.argv[1:]))\n', encoding='utf-8')
            if os.name == 'nt':
                launcher = support / 'analyzeHeadless.bat'
                launcher.write_bytes(f'@echo off\r\n@"{sys.executable}" "{marker}" %*\r\n'.encode())
                shell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
                script = root / 'import plan.ps1'
                prefix = [shell, '-NoProfile', '-NonInteractive', '-File']
            else:
                launcher = support / 'analyzeHeadless'
                launcher.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, str(marker)]) + ' "$@"\n', encoding='utf-8')
                launcher.chmod(0o755)
                script = root / 'import plan.sh'
                prefix = ['/bin/sh']
            project = root / "project's data"
            binary = root / 'capture only, never executed'
            log = root / "log's output.txt"
            script.write_text(render_import_plan(root, project, 'digest-project', binary, log,
                                                  windows=os.name == 'nt'), encoding='utf-8')
            result = subprocess.run([*prefix, str(script)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(project.is_dir())
            self.assertEqual(json.loads(result.stdout), [str(project), 'digest-project',
                             '-import', str(binary), '-processor', 'x86:LE:64:default',
                             '-analysisTimeoutPerFile', '1800', '-max-cpu', '4', '-log', str(log)])
            self.assertFalse(binary.exists())

    def test_posix_output_round_trips_and_keeps_the_existing_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'support').mkdir()
            (root / 'support/analyzeHeadless').touch()
            project = root / "space and quote' directory"
            text = render_import_plan(root, project, 'name', root / 'node', root / 'log', windows=False)
            lines = text.splitlines()
            self.assertEqual(lines[0], '# Static import plan only. Creates a separate analysis project; no node execution.')
            self.assertEqual(shlex.split(lines[1]), ['mkdir', '-p', str(project)])
            self.assertEqual(shlex.split(lines[2]), [str(root / 'support/analyzeHeadless'), str(project), 'name',
                             '-import', str(root / 'node'), '-processor', 'x86:LE:64:default',
                             '-analysisTimeoutPerFile', '1800', '-max-cpu', '4', '-log', str(root / 'log')])

    def test_windows_plan_selects_batch_and_escapes_powershell_literals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'support').mkdir()
            (root / 'support/analyzeHeadless.bat').touch()
            text = render_import_plan(root, root / "project's path", 'name', root / 'node', root / 'log', windows=True)
            self.assertIn('PowerShell', text.splitlines()[0])
            self.assertTrue(text.splitlines()[2].startswith('& '))
            self.assertIn('analyzeHeadless.bat', text)
            self.assertIn("project''s path", text)

    def test_missing_native_launcher_is_not_printed_as_a_verified_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'support').mkdir()
            (root / 'support/analyzeHeadless').touch()
            with self.assertRaisesRegex(ValueError, 'native headless launcher'):
                render_import_plan(root, root / 'p', 'name', root / 'node', root / 'log', windows=True)


if __name__ == '__main__':
    unittest.main()
