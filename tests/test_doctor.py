"""Tests for research-tool preflight diagnostics (tools/doctor.py)."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import doctor  # noqa: E402


class DoctorProbeTests(unittest.TestCase):
    def test_probe_empty_or_none_command(self):
        self.assertEqual(doctor.probe('tool', None), {'name': 'tool', 'available': False})
        self.assertEqual(doctor.probe('tool', []), {'name': 'tool', 'available': False})
        self.assertEqual(doctor.probe('tool', [None]), {'name': 'tool', 'available': False})

    def test_probe_successful_command(self):
        res = doctor.probe('python', [sys.executable, '--version'])
        self.assertTrue(res['available'])
        self.assertIn('Python', res['version'])
        self.assertEqual(res['executable'], sys.executable)

    def test_probe_nonexistent_command(self):
        res = doctor.probe('nonexistent', ['/nonexistent_binary_xyz_123', '--version'])
        self.assertFalse(res['available'])

    def test_probe_git_lfs_fallback_to_git_lfs(self):
        with patch('shutil.which') as mock_which:
            def side_effect(cmd):
                if cmd == 'git-lfs':
                    return None
                if cmd == 'git':
                    return '/usr/bin/git'
                return None
            mock_which.side_effect = side_effect
            with patch('doctor.probe') as mock_probe:
                mock_probe.return_value = {'name': 'git-lfs', 'available': True, 'version': 'git-lfs/3.4.0'}
                res = doctor.probe_git_lfs()
                self.assertTrue(res['available'])
                mock_probe.assert_called_with('git-lfs', ['/usr/bin/git', 'lfs', 'version'])


class DoctorLocatorTests(unittest.TestCase):
    def test_locate_ghidra_unix_and_windows_batch(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            unix_ghidra = base / 'ghidra_unix'
            (unix_ghidra / 'support').mkdir(parents=True)
            (unix_ghidra / 'support/analyzeHeadless').write_text('#!/bin/sh\n')

            win_ghidra = base / 'ghidra_win'
            (win_ghidra / 'support').mkdir(parents=True)
            (win_ghidra / 'support/analyzeHeadless.bat').write_text('@echo off\n')

            with patch.dict(os.environ, {'GHIDRA_HOME': str(unix_ghidra)}):
                self.assertEqual(doctor.locate_ghidra(), unix_ghidra)

            with patch.dict(os.environ, {'GHIDRA_HOME': str(win_ghidra)}):
                self.assertEqual(doctor.locate_ghidra(), win_ghidra)

    def test_locate_llvm_env_override(self):
        with tempfile.TemporaryDirectory() as td:
            fake_llvm = Path(td) / 'fake-llvm-objdump'
            fake_llvm.write_text('')
            with patch.dict(os.environ, {'LLVM_OBJDUMP': str(fake_llvm)}):
                self.assertEqual(doctor.locate_llvm(), str(fake_llvm))


class DoctorReportTests(unittest.TestCase):
    def test_report_schema_and_keys(self):
        rep = doctor.report()
        self.assertIn('analysis_ready', rep)
        self.assertIn('exact_rebuild_ready', rep)
        self.assertIn('missing_rebuild_evidence', rep)
        self.assertIn('required_tools', rep)
        self.assertIn('optional_tools', rep)
        self.assertIn('ghidra', rep)
        self.assertIn('captured_binaries_executed', rep)
        self.assertFalse(rep['captured_binaries_executed'])

        required_names = {t['name'] for t in rep['required_tools']}
        self.assertTrue({'python', 'git', 'git-lfs', 'gpg', 'rg'} <= required_names)
        optional_names = {t['name'] for t in rep['optional_tools']}
        self.assertTrue({'llvm-objdump', 'java', 'rust-1.94.1', 'rust-1.95.0'} <= optional_names)


if __name__ == '__main__':
    unittest.main()
