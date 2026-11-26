"""Ownership refresh must follow the issue links recorded in the questions."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import question_registry as registry


class RefreshLinkedIssuesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / 'research/questions', self.root / 'research/questions')
        for relative in ('provenance/artifacts.json', 'research/components.json'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        target = self.root / 'research/questions/qcp-expected-root-provenance.json'
        row = json.loads(target.read_text())
        row['linked_issue']['url'] = 'https://github.com/lalalune/hyperliquid-source/issues/9999'
        target.write_text(json.dumps(row))

    def test_refresh_reads_the_linked_issue_from_the_question_record(self):
        requested = []

        def fake(command, **kwargs):
            url = command[2]
            requested.append(url)
            if '/issues/' in url:
                return json.dumps({'state': 'open', 'assignees': [], 'html_url': url})
            if url.endswith('/reviews?per_page=100'):
                return '[]'
            if url.endswith('/requested_reviewers'):
                return '{"users": []}'
            return json.dumps({'state': 'open', 'head': {'sha': 'abc'},
                               'user': {'login': 'someone'}, 'html_url': url})

        with mock.patch.object(registry.subprocess, 'check_output', side_effect=fake):
            registry.refresh_ownership(self.root)
        snapshot = json.loads((self.root / 'research/questions/ownership-snapshot.json').read_text())
        self.assertIn('9999', snapshot['issues'])


if __name__ == '__main__':
    unittest.main()
