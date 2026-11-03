"""A non-string path value in either provenance manifest must fail closed.

The record validators in verify() checked only that a path key is
present, so a record whose path value is a number, boolean, null, list
or object passed validation and then escaped as a bare TypeError —
unhashable at the duplicate-path set() check, or an unsupported operand
at the root / path join — instead of the module's ValueError. The CLI
contract (merged #801) is one-line failures: __main__ catches only
(ValueError, OSError), so a TypeError prints a full traceback. Sibling
fields do not escape: a non-string commit fails its comparison as a
ValueError mismatch, and size/sha256 mismatches are refused by
artifacts.check() as ValueError.
"""
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

SHA = hashlib.sha256(b'good').hexdigest()
BAD_PATHS = (123, True, None, ['bin/node'], {'x': 1})


class VerifyImportsPathTypeTests(unittest.TestCase):
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

    def test_import_entry_nonstring_path_rejected(self):
        for bad in BAD_PATHS:
            with self.subTest(path=bad):
                self._write_manifests([{'path': bad, 'size': 4, 'sha256': SHA}])
                with self.assertRaisesRegex(ValueError, 'Invalid import manifest record'):
                    vi.verify(self.root)

    def test_source_repo_nonstring_path_rejected(self):
        for bad in BAD_PATHS:
            with self.subTest(path=bad):
                self._write_manifests([], [{'path': bad, 'commit': '0' * 40}])
                with self.assertRaisesRegex(ValueError, 'Invalid source repository record'):
                    vi.verify(self.root)

    def test_valid_entry_still_verifies(self):
        data = b'good'
        (self.root / 'bin').mkdir()
        (self.root / 'bin' / 'node').write_bytes(data)
        self._write_manifests([{'path': 'bin/node', 'size': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()}])
        vi.verify(self.root)

    def test_empty_manifests_still_verify(self):
        self._write_manifests([])
        vi.verify(self.root)


if __name__ == '__main__':
    unittest.main()
