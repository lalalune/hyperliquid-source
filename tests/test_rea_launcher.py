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


class TargetSelectionTests(unittest.TestCase):
    def run_target(self, *args):
        return subprocess.run(
            [sys.executable, str(rea.ROOT / 'tools/rea.py'), 'target', *args],
            capture_output=True, text=True, check=False,
        )

    def test_cli_preserves_default_and_explicit_artifact_identities(self):
        manifest = json.loads((rea.ROOT / 'provenance/artifacts.json').read_text())
        for args, relative in [
            ((), 'artifacts/node/94/hl-node'),
            (('94',), 'artifacts/node/94/hl-node'),
            (('115',), 'artifacts/node/115/hl-node'),
            (('visor',), 'artifacts/visor/captured/hl-visor'),
        ]:
            with self.subTest(args=args):
                result = self.run_target(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                item = next(row for row in manifest['files'] if row['path'] == relative)
                self.assertEqual(json.loads(result.stdout), {
                    'path': str(rea.ROOT / relative),
                    'sha256': item['sha256'],
                    'provider_id': 'ghidra',
                })

    def test_cli_rejects_surplus_arguments_without_emitting_a_target(self):
        for args in [
            ('115', '--format', 'json'),
            ('visor', 'extra'),
            ('94', '115'),
            ('unknown', 'extra'),
            ('--format', 'json'),
        ]:
            with self.subTest(args=args):
                result = self.run_target(*args)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(result.stdout, '')
                self.assertIn('Usage: rea.py target [94|115|visor]', result.stderr)
                self.assertNotIn('Traceback', result.stderr)


class RuntimeSelectionTests(unittest.TestCase):
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
