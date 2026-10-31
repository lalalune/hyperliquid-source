import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
spec = importlib.util.spec_from_file_location('hl_rea_launcher', Path(__file__).resolve().parents[1] / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


class RuntimeSelectionTests(unittest.TestCase):
    def test_windows_launcher_preserves_command_exit_status(self):
        for exit_status in (0, 23):
            with self.subTest(exit_status=exit_status), \
                 patch.object(rea.sys, 'platform', 'win32'), \
                 patch.object(rea, 'find_node', return_value=Path('/chosen/node/bin/node')), \
                 patch.object(rea, 'environment', return_value={'PATH': 'fixture'}), \
                 patch.object(Path, 'is_file', return_value=True), \
                 patch.object(Path, 'read_text', return_value=json.dumps({'version': rea.CONFIG['version']})), \
                 patch.object(rea.os, 'chdir'), \
                 patch.object(rea.os, 'execvpe', side_effect=SystemExit(0)), \
                 patch.object(rea.os, 'spawnve', return_value=exit_status) as run:
                with self.assertRaises(SystemExit) as exited:
                    rea.main(['--version'])
                self.assertEqual(exited.exception.code, exit_status)
                if run.called:
                    self.assertEqual(run.call_args.args[2][-1], '--version')
                    self.assertEqual(run.call_args.args[3], {'PATH': 'fixture'})

    def test_exact_supported_version_boundaries(self):
        for version in ['22.23.4', '24.22.1', '26.12.1', '27.0.0']:
            with self.subTest(version=version): self.assertTrue(rea.supported_node(version))
        for version in ['22.23.3', '24.15.0', '24.22.0', '25.99.0', '26.12.0', 'nightly']:
            with self.subTest(version=version): self.assertFalse(rea.supported_node(version))

    def test_explicit_incompatible_runtime_not_silently_replaced(self):
        with patch.dict(os.environ, {'REA_NODE': '/explicit/node'}), patch.object(rea.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'v24.15.0\n', '')) as run:
            with self.assertRaises(ValueError): rea.find_node()
            self.assertEqual(run.call_count, 1)

    def test_explicit_provider_environment_preserved(self):
        with patch.dict(os.environ, {'GHIDRA_INSTALL_DIR': '/chosen/ghidra', 'JAVA_HOME': '/chosen/java'}):
            env = rea.environment(Path('/chosen/node/bin/node'))
            self.assertEqual(env['GHIDRA_INSTALL_DIR'], '/chosen/ghidra')
            self.assertEqual(env['JAVA_HOME'], '/chosen/java')
            self.assertEqual(env['PATH'].split(os.pathsep)[0], '/chosen/node/bin')

    def test_target_bound_to_artifact_manifest(self):
        row = rea.target('94')
        self.assertEqual(row['sha256'], '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual(row['provider_id'], 'ghidra')

    def test_project_dependency_and_runtime_pins_agree(self):
        package = json.loads((rea.ROOT / 'package.json').read_text())
        lock = json.loads((rea.ROOT / 'package-lock.json').read_text())
        self.assertEqual(package['devDependencies']['rea-agents'], rea.CONFIG['version'])
        self.assertEqual(lock['packages']['node_modules/rea-agents']['version'], rea.CONFIG['version'])
        preferred = (rea.ROOT / '.nvmrc').read_text().strip()
        self.assertEqual(preferred, rea.CONFIG['preferred_node'])
        self.assertTrue(rea.supported_node(preferred))
