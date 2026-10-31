"""REA JDK-root discovery, including the real macOS system Java launcher."""
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
spec = importlib.util.spec_from_file_location('rea_java_home', ROOT / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


@unittest.skipUnless(sys.platform == 'darwin' and Path('/usr/libexec/java_home').is_file(), 'native macOS resolver required')
class NativeJavaHomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(['/usr/libexec/java_home'], capture_output=True, text=True, timeout=5)
        if result.returncode:
            raise unittest.SkipTest('no native JDK registered')
        cls.home = Path(result.stdout.strip()).resolve()
        if not (cls.home / 'bin/javac').is_file():
            raise unittest.SkipTest('registered runtime is not a full JDK')

    def test_system_launcher_uses_registered_jdk_root(self):
        with patch.dict(os.environ, {'JAVA_HOME': '', 'PATH': '/usr/bin:/bin', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}):
            env = rea.environment(Path('/usr/bin/node'))
        self.assertEqual(Path(env['JAVA_HOME']).resolve(), self.home)
        self.assertNotEqual(env['JAVA_HOME'], '/usr')

    def test_real_nested_jre_uses_enclosing_jdk(self):
        java = self.home / 'jre/bin/java'
        if not java.is_file():
            self.skipTest('native JDK has no separate nested JRE')
        with patch.dict(os.environ, {'JAVA_HOME': '', 'PATH': str(java.parent) + ':/usr/bin:/bin', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}):
            env = rea.environment(Path('/chosen/node/bin/node'))
        self.assertEqual(Path(env['JAVA_HOME']).resolve(), self.home)


class JavaHomeDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / 'jdk with spaces'
        (self.home / 'bin').mkdir(parents=True)
        # Filesystem-shape controls only; native tests above use installed Java.
        (self.home / 'bin/java').touch()
        (self.home / 'bin/javac').touch()

    def test_direct_selected_jdk_and_nested_jre_do_not_query_default(self):
        (self.home / 'jre/bin').mkdir(parents=True)
        (self.home / 'jre/bin/java').touch()
        with patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', side_effect=AssertionError('must preserve selected JDK')):
            self.assertEqual(rea.find_java_home(self.home / 'bin/java'), self.home)
            self.assertEqual(rea.find_java_home(self.home / 'jre/bin/java'), self.home)

    def test_system_stub_uses_macos_resolver(self):
        result = subprocess.CompletedProcess([], 0, str(self.home) + '\n', '')
        with patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', return_value=result) as run:
            self.assertEqual(rea.find_java_home(Path('/usr/bin/java')), self.home)
        self.assertEqual(run.call_args.args[0], ['/usr/libexec/java_home'])
        self.assertEqual(run.call_args.kwargs['timeout'], 5)

    def test_failed_resolver_does_not_advertise_usr(self):
        outcomes = [subprocess.CompletedProcess([], 1, '', 'unavailable'), FileNotFoundError(), subprocess.TimeoutExpired('java_home', 5)]
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__):
                kwargs = {'side_effect': outcome} if isinstance(outcome, Exception) else {'return_value': outcome}
                with patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', **kwargs):
                    self.assertIsNone(rea.find_java_home(Path('/usr/bin/java')))

    def test_reported_home_must_be_absolute_and_have_full_jdk(self):
        (self.home / 'bin/javac').unlink()
        for value in ['', 'relative/jdk', str(self.home)]:
            result = subprocess.CompletedProcess([], 0, value, '')
            with self.subTest(value=value), patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', return_value=result):
                self.assertIsNone(rea.find_java_home(Path('/usr/bin/java')))

    def test_explicit_home_preserved_without_discovery(self):
        with patch.dict(os.environ, {'JAVA_HOME': '/chosen/jdk', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}), patch.object(rea, 'find_java_home', side_effect=AssertionError('explicit home wins')):
            self.assertEqual(rea.environment(Path('/chosen/node/bin/node'))['JAVA_HOME'], '/chosen/jdk')

    def test_no_java_leaves_home_unset(self):
        with patch.dict(os.environ, {'JAVA_HOME': '', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}), patch.object(rea.shutil, 'which', return_value=None):
            self.assertFalse(rea.environment(Path('/chosen/node/bin/node')).get('JAVA_HOME'))


if __name__ == '__main__':
    unittest.main()
