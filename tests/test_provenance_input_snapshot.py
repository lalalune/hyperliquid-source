"""Provenance must describe the exact captured bytes whose digest was admitted."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_provenance as provenance


@unittest.skipUnless((ROOT / provenance.TARGETS['115']).stat().st_size > 1000000,
                     'materialize pinned captures with git lfs pull')
class ProvenanceSnapshotTests(unittest.TestCase):
    maxDiff = 300
    def test_atomic_release_replacement_cannot_relabel_node115_as_node94(self):
        before = provenance.record('94')
        other = provenance.record('115')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / provenance.TARGETS['94']
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / provenance.TARGETS['94'], target)
            replacement = root / 'replacement.so'
            shutil.copyfile(ROOT / provenance.TARGETS['115'], replacement)
            (root / 'provenance').mkdir()
            shutil.copyfile(ROOT / 'provenance/artifacts.json', root / 'provenance/artifacts.json')
            real_open = Path.open
            replaced = []

            @contextmanager
            def replace_after_read(path, *args, **kwargs):
                with real_open(path, *args, **kwargs) as stream:
                    yield stream
                if path == target and (args[0] if args else kwargs.get('mode')) == 'rb' and not replaced:
                    replacement.replace(target)
                    replaced.append(True)

            with patch.object(provenance, 'ROOT', root), patch.object(Path, 'open', replace_after_read):
                result = provenance.record('94')
            self.assertEqual(replaced, [True], 'the actual file replacement must occur')
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), other['sha256'])
            self.assertEqual(result, before, 'facts were read from node115 under node94 identity')
            self.assertNotEqual(result['facts'], other['facts'])

    def rejection(self, wrong_release):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / provenance.TARGETS['94']
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / provenance.TARGETS['115' if wrong_release else '94'], target)
            if not wrong_release:
                with target.open('r+b') as stream:
                    stream.seek(-1, 2)
                    value = stream.read(1)[0]
                    stream.seek(-1, 2)
                    stream.write(bytes([value ^ 1]))
            (root / 'provenance').mkdir()
            shutil.copyfile(ROOT / 'provenance/artifacts.json', root / 'provenance/artifacts.json')
            with patch.object(provenance, 'ROOT', root), self.assertRaises(ValueError):
                provenance.record('94')

    def test_wrong_release_at_admission_is_rejected(self):
        self.rejection(True)

    def test_same_length_corruption_is_rejected(self):
        self.rejection(False)


if __name__ == '__main__':
    unittest.main()
