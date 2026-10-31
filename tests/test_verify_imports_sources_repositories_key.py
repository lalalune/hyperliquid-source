import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def load_verify_imports():
    spec = importlib.util.spec_from_file_location('artifacts', TOOLS / 'artifacts.py')
    artifacts = importlib.util.module_from_spec(spec)
    sys.modules['artifacts'] = artifacts
    spec.loader.exec_module(artifacts)
    spec = importlib.util.spec_from_file_location('verify_imports', TOOLS / 'verify_imports.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vi = load_verify_imports()


class VerifyImportsSourcesKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'provenance').mkdir()
        (self.root / 'provenance' / 'imports.json').write_text(
            json.dumps({'files': []}))

    def _write_sources(self, document):
        (self.root / 'provenance' / 'sources.json').write_text(
            json.dumps(document))

    def test_sources_missing_repositories_rejected(self):
        self._write_sources({'captured_on': '2026-10-28'})
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_non_dict_sources_rejected(self):
        self._write_sources(['refs/repo'])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_sources_with_repositories_still_verifies(self):
        self._write_sources({'repositories': []})
        vi.verify(self.root)


if __name__ == '__main__':
    unittest.main()
