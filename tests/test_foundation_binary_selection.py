"""A native export must read the same selected artifact that was authenticated."""
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class SelectedBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = [importlib.import_module(name) for name in
                       ('foundation_millis', 'foundation_duration_guards')]
        cls.target = cls.modules[0].TARGET
        if not cls.target.is_file() or cls.target.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')

    def check_selection(self, module):
        retained = module.inspect(self.target)
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / 'external node94'
            # The alternate artifact can live on another filesystem.
            shutil.copyfile(self.target, selected)
            records = json.loads((module.PACKET / 'records.json').read_text())
            exports = {}
            if module.__name__ == 'foundation_millis':
                for row in records['windows']:
                    exports[int(row['start_va'], 16)] = (module.PACKET / (row['name'] + '.objdump.txt')).read_text()
            else:
                exports[int(records['start_va'], 16)] = (module.PACKET / 'function.objdump.txt').read_text()

            def native_export(command, **kwargs):
                # The mocked provider returns retained decoded bytes, but checks
                # the actual path sent across the subprocess/CWD boundary.
                observed = Path(command[-1])
                if not observed.is_absolute():
                    observed = Path(kwargs['cwd']) / observed
                self.assertEqual(observed.resolve(), selected.resolve())
                self.assertEqual(observed.stat().st_size, self.target.stat().st_size)
                start = next(arg for arg in command if arg.startswith('--start-address='))
                return exports[int(start.split('=', 1)[1], 16)]

            for path in (selected, Path(os.path.relpath(selected, Path.cwd()))):
                with self.subTest(module=module.__name__, path=str(path)):
                    with patch.object(module.subprocess, 'check_output', side_effect=native_export) as native:
                        self.assertEqual(module.inspect(path, 'fixture-objdump'), retained)
                        self.assertTrue(native.called)

    def test_millis_native_export_uses_selected_absolute_and_relative_binary(self):
        self.check_selection(self.modules[0])

    def test_duration_native_export_uses_selected_absolute_and_relative_binary(self):
        self.check_selection(self.modules[1])

    def test_invalid_selected_input_never_reaches_native_export(self):
        with tempfile.TemporaryDirectory() as directory:
            pointer = Path(directory) / 'unmaterialized-node94'
            pointer.write_text('version https://git-lfs.github.com/spec/v1\n')
            for module in self.modules:
                with self.subTest(module=module.__name__):
                    with patch.object(module.subprocess, 'check_output') as native:
                        with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                            module.inspect(pointer, 'fixture-objdump')
                        native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
