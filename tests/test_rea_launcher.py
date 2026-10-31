import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
spec = importlib.util.spec_from_file_location('hl_rea_launcher', Path(__file__).resolve().parents[1] / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


class PathRuntimeSelectionTests(unittest.TestCase):
    def select(self, versions):
        with tempfile.TemporaryDirectory(prefix='rea-path-') as temporary:
            root = Path(temporary)
            candidates = []
            for index, version in enumerate(versions):
                directory = root / str(index)
                directory.mkdir()
                candidate = directory / ('node.cmd' if os.name == 'nt' else 'node')
                # These are version-protocol fixtures; the native CLI probe
                # separately uses real supported and unsupported Node binaries.
                candidate.write_text(
                    '@echo off\necho v' + version + '\n' if os.name == 'nt'
                    else '#!/bin/sh\nprintf "v' + version + '\\n"\n',
                    encoding='utf-8',
                )
                candidate.chmod(0o755)
                candidates.append(candidate)
            with patch.dict(os.environ, {'PATH': os.pathsep.join(str(p.parent) for p in candidates)}), \
                    patch.object(rea.Path, 'home', return_value=root):
                os.environ.pop('REA_NODE', None)
                selected = rea.find_node()
                version = subprocess.check_output([str(selected), '--version'], text=True).strip()
            return selected.name, version

    def test_later_supported_path_runtime_is_selected(self):
        _name, version = self.select(['24.12.0', '24.22.1'])
        self.assertEqual(version, 'v24.22.1')

    def test_first_supported_path_runtime_keeps_priority(self):
        _name, version = self.select(['24.22.1', '26.12.1'])
        self.assertEqual(version, 'v24.22.1')


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
