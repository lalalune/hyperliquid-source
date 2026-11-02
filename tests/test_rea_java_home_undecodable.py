"""REA JDK discovery: an undecodable macOS resolver output is no JDK found."""
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
spec = importlib.util.spec_from_file_location('rea_java_home_undecodable', ROOT / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)

DECODE_ERROR = UnicodeDecodeError('utf-8', b'\xff\xfe', 0, 1, 'invalid start byte')


class UndecodableJavaHomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / 'jdk with spaces'
        (self.home / 'bin').mkdir(parents=True)
        (self.home / 'bin/java').touch()
        (self.home / 'bin/javac').touch()

    def test_undecodable_resolver_output_returns_none(self):
        # A text-mode subprocess.run raises UnicodeDecodeError from inside the
        # call when /usr/libexec/java_home prints non-UTF-8 bytes.
        with patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', side_effect=DECODE_ERROR):
            self.assertIsNone(rea.find_java_home(Path('/usr/bin/java')))

    def test_undecodable_resolver_leaves_java_home_unset(self):
        with patch.dict(os.environ, {'JAVA_HOME': '', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}), \
             patch.object(rea.sys, 'platform', 'darwin'), \
             patch.object(rea.shutil, 'which', return_value='/usr/bin/java'), \
             patch.object(rea.subprocess, 'run', side_effect=DECODE_ERROR):
            env = rea.environment(Path('/usr/bin/node'))
        self.assertFalse(env.get('JAVA_HOME'))

    def test_valid_resolver_output_still_resolves(self):
        result = subprocess.CompletedProcess([], 0, str(self.home) + '\n', '')
        with patch.object(rea.sys, 'platform', 'darwin'), patch.object(rea.subprocess, 'run', return_value=result):
            self.assertEqual(rea.find_java_home(Path('/usr/bin/java')), self.home)

    def test_valid_resolver_output_sets_java_home(self):
        result = subprocess.CompletedProcess([], 0, str(self.home) + '\n', '')
        with patch.dict(os.environ, {'JAVA_HOME': '', 'GHIDRA_INSTALL_DIR': '/chosen/ghidra'}), \
             patch.object(rea.sys, 'platform', 'darwin'), \
             patch.object(rea.shutil, 'which', return_value='/usr/bin/java'), \
             patch.object(rea.subprocess, 'run', return_value=result):
            env = rea.environment(Path('/usr/bin/node'))
        self.assertEqual(env['JAVA_HOME'], str(self.home))


if __name__ == '__main__':
    unittest.main()
