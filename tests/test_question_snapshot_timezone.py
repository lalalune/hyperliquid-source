"""A hand-edited/legacy ownership snapshot must degrade to unknown, not crash."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('question_registry', ROOT / 'tools/question_registry.py')
REGISTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTRY)


class SnapshotTimezoneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'research/questions', self.root / 'research/questions')

    def test_naive_fetched_at_is_not_accepted(self):
        path = self.root / 'research/questions/ownership-snapshot.json'
        snapshot = json.loads(path.read_text())
        snapshot['fetched_at'] = '2026-11-27T00:00:00'  # no Z / no offset
        path.write_text(json.dumps(snapshot))
        self.assertIsNone(REGISTRY.read_ownership_snapshot(self.root))
        data, note = REGISTRY.snapshot_state(self.root)
        self.assertIsNone(data)
        self.assertIn('no valid ownership snapshot', note)


if __name__ == '__main__':
    unittest.main()
