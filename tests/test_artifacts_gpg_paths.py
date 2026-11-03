"""Keep private GPG homes isolated across native and MSYS tool paths."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('artifacts_gpg_paths', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class GpgPathTests(unittest.TestCase):
    def test_msys_converter_receives_one_literal_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'gpg.exe'
            converter = Path(directory) / 'cygpath.exe'
            converter.touch()
            native = 'D:/private review/public key.asc'
            with patch.object(a, 'os', SimpleNamespace(name='nt')), \
                    patch.object(a.shutil, 'which', return_value=str(executable)), \
                    patch.object(a.subprocess, 'check_output', return_value='/d/private review/public key.asc\n') as convert:
                self.assertEqual(a.gpg_path(native), '/d/private review/public key.asc')
            convert.assert_called_once_with([str(converter), '-u', '-a', native], text=True, encoding='utf-8')

    def test_native_windows_gpg_keeps_native_paths_without_a_converter(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(a, 'os', SimpleNamespace(name='nt')), \
                    patch.object(a.shutil, 'which', return_value=str(Path(directory) / 'gpg.exe')), \
                    patch.object(a.subprocess, 'check_output') as convert:
                self.assertEqual(a.gpg_path('D:/private home'), 'D:/private home')
            convert.assert_not_called()

    def test_posix_gpg_does_not_probe_or_run_another_tool(self):
        with patch.object(a, 'os', SimpleNamespace(name='posix')), \
                patch.object(a.shutil, 'which') as lookup, \
                patch.object(a.subprocess, 'check_output') as convert:
            self.assertEqual(a.gpg_path('/tmp/private home'), '/tmp/private home')
        lookup.assert_not_called()
        convert.assert_not_called()