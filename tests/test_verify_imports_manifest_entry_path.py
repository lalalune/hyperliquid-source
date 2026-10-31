import hashlib
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


class VerifyImportsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'provenance').mkdir()

    def _write_manifests(self, files, repositories=()):
        (self.root / 'provenance' / 'imports.json').write_text(
            json.dumps({'files': files}))
        (self.root / 'provenance' / 'sources.json').write_text(
            json.dumps({'repositories': list(repositories)}))

    def test_entry_missing_path_rejected(self):
        self._write_manifests([{'size': 0,
                                'sha256': hashlib.sha256(b'').hexdigest()}])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_non_dict_entry_rejected(self):
        self._write_manifests(['bin/node'])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_valid_entry_still_verifies(self):
        data = b'good'
        (self.root / 'bin').mkdir()
        (self.root / 'bin' / 'node').write_bytes(data)
        self._write_manifests([{'path': 'bin/node', 'size': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()}])
        vi.verify(self.root)


if __name__ == '__main__':
    unittest.main()
