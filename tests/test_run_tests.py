"""Real-process integration controls for complete per-file unittest discovery."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'tools/run_tests.py'


class ProcessIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.tests = self.folder / 'tests'
        self.tests.mkdir()

    def write(self, name, source):
        path = self.tests / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source))

    def invoke(self, *flags, directory=None):
        return subprocess.run([sys.executable, *flags, '-B', str(RUNNER),
                               str(directory or self.tests)], cwd=self.folder,
                              capture_output=True, text=True, timeout=20)

    def test_real_children_isolate_import_globals_and_run_every_valid_file(self):
        self.write('shared.py', 'seen = []\n')
        for name in ('test_a.py', 'test_b.py'):
            self.write(name, '''
                import json, os, unittest
                from pathlib import Path
                import shared
                shared.seen.append(__name__)
                RETAINED = bytearray(8 * 1024 * 1024)
                class Probe(unittest.TestCase):
                    def test_fresh_process(self):
                        self.assertEqual(shared.seen, [__name__])
                        self.assertEqual(len(RETAINED), 8 * 1024 * 1024)
                        with (Path(__file__).parent / 'events.jsonl').open('a') as f:
                            f.write(json.dumps([__name__, os.getpid()]) + '\\n')
            ''')
        for name in ('test[ab].py', 'test-with-dash.py', 'helper.py'):
            self.write(name, 'raise RuntimeError("must not be discovered")\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(s) for s in (self.tests / 'events.jsonl').read_text().splitlines()]
        self.assertEqual([r[0] for r in rows], ['test_a', 'test_b'])
        self.assertEqual(len({r[1] for r in rows}), 2)
        self.assertIn('test_a.Probe.test_fresh_process', result.stderr)
        self.assertIn('test_b.Probe.test_fresh_process', result.stderr)
        self.assertNotIn('must not be discovered', result.stderr)
        self.assertIn('2 files attempted; 0 failed', result.stderr)

    def test_failures_import_errors_skips_and_output_are_not_hidden(self):
        self.write('test_a.py', '''
            import unittest
            class Broken(unittest.TestCase):
                def test_assertion(self): self.fail('deliberate assertion')
        ''')
        self.write('test_b.py', 'raise RuntimeError("deliberate import error")\n')
        self.write('test_c.py', '''
            import sys, unittest
            class Later(unittest.TestCase):
                @unittest.skip('deliberate skip')
                def test_skip(self): pass
                def test_output(self):
                    print('later stdout')
                    print('later stderr', file=sys.stderr)
        ''')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        for text in ['deliberate assertion', 'deliberate import error',
                     'skipped \'deliberate skip\'', 'later stderr',
                     'test_c.Later.test_output', '3 files attempted; 2 failed']:
            self.assertIn(text, result.stderr)
        self.assertIn('later stdout', result.stdout)

    @unittest.skipUnless(os.name == 'posix', 'POSIX child-signal behavior')
    def test_signaled_child_does_not_hide_failure_or_stop_later_files(self):
        self.write('test_a.py', 'import os, signal\nos.kill(os.getpid(), signal.SIGTERM)\n')
        self.write('test_b.py', '''
            import unittest
            class Later(unittest.TestCase):
                def test_later(self): print('after signaled child')
        ''')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'status {-signal.SIGTERM}', result.stderr)
        self.assertIn('after signaled child', result.stdout)
        self.assertIn('2 files attempted; 1 failed', result.stderr)

    def test_function_tests_are_collected_and_failures_propagate(self):
        self.write('test_functions.py', "def test_reject():\n    assert False, 'function assertion ran'\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('function assertion ran', result.stdout)
        self.assertIn('1 files attempted; 1 failed', result.stderr)

    def test_script_main_checks_run_and_failures_propagate(self):
        self.write('test_script.py', "if __name__ == '__main__':\n    raise ValueError('script check ran')\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('script check ran', result.stderr)
        self.assertIn('1 files attempted; 1 failed', result.stderr)

    def test_top_level_assertions_are_run(self):
        self.write('test_top.py', "assert False, 'top assertion ran'\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('top assertion ran', result.stderr)

    def test_same_interpreter_optimization_and_bytecode_flags(self):
        self.write('test_flags.py', '''
            import sys, unittest
            class Flags(unittest.TestCase):
                def test_flags(self):
                    self.assertEqual(sys.flags.optimize, 1)
                    self.assertTrue(sys.dont_write_bytecode)
        ''')
        result = self.invoke('-O')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(list(self.tests.rglob('*.pyc')))

    def test_missing_directory_fails_and_empty_directory_keeps_standard_result(self):
        missing = self.invoke(directory=self.folder / 'missing')
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('does not exist', missing.stderr)
        stock = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                                '-s', str(self.tests), '-v'], capture_output=True,
                               text=True, timeout=20)
        empty = self.invoke()
        self.assertEqual(empty.returncode, int(bool(stock.returncode)), empty.stderr)
        self.assertIn('Ran 0 tests', empty.stderr)
        self.assertIn(stock.stderr.strip().splitlines()[-1], empty.stderr)

    def test_unsupported_packages_or_nested_files_fail_before_partial_run(self):
        self.write('test_a.py', 'raise RuntimeError("partial suite must not run")\n')
        self.write('package/__init__.py', '')
        self.write('package/test_inside.py', '')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('without packages', result.stderr)
        self.assertNotIn('partial suite must not run', result.stderr)
        (self.tests / 'package/__init__.py').unlink()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('without nested tests', result.stderr)
        self.assertNotIn('partial suite must not run', result.stderr)

    def test_real_launch_oserror_is_nonzero_and_every_file_is_attempted(self):
        self.write('test_a.py', '')
        self.write('test_b.py', '')
        denied = self.folder / 'not-executable'
        denied.write_text('not an executable')
        denied.chmod(0o600)
        client = ('import runpy,sys;sys.executable=sys.argv[1];'
                  'sys.argv=[sys.argv[2],sys.argv[3]];'
                  'runpy.run_path(sys.argv[0],run_name="__main__")')
        result = subprocess.run([sys.executable, '-B', '-c', client,
                                 str(denied), str(RUNNER), str(self.tests)],
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.count('Could not start unittest child:'), 2)
        self.assertIn('2 files attempted; 2 failed', result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'POSIX interrupt/reaping behavior')
    def test_interrupt_is_incomplete_nonzero_and_owned_child_is_reaped(self):
        self.write('test_wait.py', '''
            import os, time, unittest
            from pathlib import Path
            class Waiting(unittest.TestCase):
                def test_wait(self):
                    Path(__file__).with_suffix('.pid').write_text(str(os.getpid()))
                    while True: time.sleep(1)
        ''')
        process = subprocess.Popen([sys.executable, '-B', str(RUNNER), str(self.tests)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child = None
        child_reaped = False
        try:
            deadline = time.monotonic() + 10
            pid_file = self.tests / 'test_wait.pid'
            while not pid_file.exists() and time.monotonic() < deadline:
                if process.poll() is not None: break
                time.sleep(0.01)
            self.assertTrue(pid_file.exists(), 'owned fixture child did not start')
            child = int(pid_file.read_text())
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn('inventory is incomplete', stderr)
            self.assertNotIn('files attempted;', stderr)
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)
            child_reaped = True
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
            if child is not None and not child_reaped:
                try: os.kill(child, signal.SIGKILL)
                except ProcessLookupError: pass

    @unittest.skipUnless(shutil.which('make'), 'make is required for Makefile integration')
    def test_actual_makefile_delegates_to_real_runner(self):
        (self.folder / 'tools').mkdir()
        shutil.copy2(RUNNER, self.folder / 'tools/run_tests.py')
        shutil.copy2(ROOT / 'Makefile', self.folder / 'Makefile')
        self.write('test_make.py', '''
            import unittest
            class MakeIntegration(unittest.TestCase):
                def test_real_make(self): print('actual make child')
        ''')
        result = subprocess.run(['make', '--no-print-directory', 'test',
                                 'PYTHON=' + sys.executable + ' -B'], cwd=self.folder,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tools/run_tests.py', result.stdout)
        self.assertIn('actual make child', result.stdout)
        self.assertIn('test_make.MakeIntegration.test_real_make', result.stderr)
        self.assertIn('1 files attempted; 0 failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
