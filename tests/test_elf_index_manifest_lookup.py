import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
spec = importlib.util.spec_from_file_location('elf_index', Path(__file__).resolve().parents[1] / 'tools/elf_index.py')
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)

REL = 'artifacts/node/94/hl-node'


class ManifestLookupTests(unittest.TestCase):
    def run_main(self, manifest):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'provenance').mkdir()
        (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
        with patch.object(ei, 'ROOT', root), patch.object(sys, 'argv', ['elf_index.py', '--release', '94']):
            ei.main()

    def test_manifest_without_files_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Invalid artifact manifest'):
            self.run_main({})

    def test_entry_without_path_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            self.run_main({'files': [{'size': 1, 'sha256': 'x'}]})

    def test_missing_release_entry_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'No provenance/artifacts.json entry'):
            self.run_main({'files': [{'path': 'artifacts/node/115/hl-node', 'size': 1, 'sha256': 'x'}]})

    def test_valid_entry_reaches_artifact_check(self):
        # The lookup itself succeeds; the artifact is absent in the tmp root,
        # so artifacts.check() raises its own ValueError, not a lookup error.
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            self.run_main({'files': [{'path': REL, 'size': 1, 'sha256': 'x'}]})


if __name__ == '__main__':
    unittest.main()
