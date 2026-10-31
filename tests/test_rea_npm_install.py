import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('hl_rea_npm_install', ROOT / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


class NpmShimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.node = Path(self.temp.name) / 'node'

    def touch(self, name):
        path = self.node.parent / name
        path.write_text('')
        return path

    def test_posix_selects_extensionless_npm(self):
        npm = self.touch('npm')
        self.touch('npm.cmd')
        self.assertEqual(rea.npm_shim(self.node, 'posix'), npm)

    def test_windows_selects_cmd_shim_first(self):
        self.touch('npm')
        cmd = self.touch('npm.cmd')
        self.assertEqual(rea.npm_shim(self.node, 'nt'), cmd)

    def test_windows_accepts_batch_shim_when_cmd_is_absent(self):
        bat = self.touch('npm.bat')
        self.assertEqual(rea.npm_shim(self.node, 'nt'), bat)

    def test_windows_rejects_a_posix_only_runtime(self):
        self.touch('npm')
        with self.assertRaisesRegex(ValueError, 'npm missing beside'):
            rea.npm_shim(self.node, 'nt')

    def test_posix_does_not_execute_a_windows_shim(self):
        self.touch('npm.cmd')
        with self.assertRaisesRegex(ValueError, 'npm missing beside'):
            rea.npm_shim(self.node, 'posix')


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.node = Path(self.temp.name) / 'node'
        self.npm = Path(self.temp.name) / 'npm'
        self.npm.write_text('#!/bin/sh\nexit 0\n')
        self.npm_cmd = Path(self.temp.name) / 'npm.cmd'
        self.npm_cmd.write_text('@exit /b 0\r\n')
        self.env = {'PATH': str(self.temp.name)}

    def test_windows_runs_the_shim_and_returns_its_status(self):
        completed = subprocess.CompletedProcess([], 7)
        with patch.object(rea.subprocess, 'run', return_value=completed) as run:
            status = rea.run_install(self.node, self.env, windows=True)
        self.assertEqual(status, 7)
        run.assert_called_once_with(
            [str(self.npm_cmd), 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
            env=self.env)

    def test_posix_replaces_the_launcher_process(self):
        with patch.object(rea.os, 'execvpe') as execvpe:
            status = rea.run_install(self.node, self.env, windows=False)
        self.assertIsNone(status)
        execvpe.assert_called_once_with(
            str(self.npm), [str(self.npm), 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
            self.env)


if __name__ == '__main__':
    unittest.main()
