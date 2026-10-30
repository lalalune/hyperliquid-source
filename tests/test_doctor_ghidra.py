"""Exercise documented Ghidra selection through the real read-only doctor CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DOCTOR = Path(__file__).resolve().parents[1] / 'tools/doctor.py'


class DoctorGhidraSelectionTests(unittest.TestCase):
    def installation(self, directory, version):
        (directory / 'support').mkdir(parents=True)
        (directory / 'Ghidra').mkdir()
        # Discovery-only fixture: this is not a Ghidra installation or launcher.
        (directory / 'support/analyzeHeadless').write_text('fixture; never execute\n')
        (directory / 'Ghidra/application.properties').write_text(
            'application.version=' + version + '\n')
        return directory

    def invoke(self, home, **configuration):
        environment = dict(os.environ, HOME=str(home), USERPROFILE=str(home), PATH='')
        for key in ('GHIDRA_INSTALL_DIR', 'GHIDRA_HOME'):
            environment.pop(key, None)
        environment.update({key: str(value) for key, value in configuration.items()})
        completed = subprocess.run([sys.executable, str(DOCTOR)], env=environment,
                                   capture_output=True, text=True, timeout=30)
        # PATH intentionally excludes optional/prerequisite native tools. The
        # JSON's Ghidra result is independent of analysis_ready and exit status.
        self.assertIn(completed.returncode, (0, 1), completed.stderr)
        result = json.loads(completed.stdout)
        self.assertFalse(result['captured_binaries_executed'])
        self.assertFalse(result['ghidra']['started'])
        return result['ghidra']

    def test_documented_install_directory_is_selected_over_legacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = self.installation(root / 'selected', 'fixture-selected')
            legacy = self.installation(root / 'legacy', 'fixture-legacy')
            for options in ({'GHIDRA_INSTALL_DIR': selected},
                            {'GHIDRA_INSTALL_DIR': selected, 'GHIDRA_HOME': legacy}):
                with self.subTest(options=list(options)):
                    result = self.invoke(root, **options)
                    self.assertTrue(result['available'])
                    self.assertEqual(result['home'], str(selected))
                    self.assertEqual(result['version'], 'fixture-selected')

    def test_invalid_explicit_install_is_not_replaced_by_another_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = self.installation(root / 'legacy', 'fixture-legacy')
            self.installation(root / '.local/share/rea-tools/ghidra_99_PUBLIC', 'fixture-auto')
            result = self.invoke(root, GHIDRA_INSTALL_DIR=root / 'missing', GHIDRA_HOME=legacy)
            self.assertFalse(result['available'])
            self.assertIsNone(result['home'])

    def test_legacy_and_automatic_discovery_remain_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = self.installation(root / 'legacy', 'fixture-legacy')
            automatic = self.installation(root / '.local/share/rea-tools/ghidra_99_PUBLIC', 'fixture-auto')
            self.assertEqual(self.invoke(root, GHIDRA_HOME=legacy)['home'], str(legacy))
            self.assertEqual(self.invoke(root)['home'], str(automatic))


if __name__ == '__main__':
    unittest.main()
