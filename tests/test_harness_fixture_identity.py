"""RE-003's declared payload identity must contain a SHA-256 digest."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import harness_plan as hp

PACKET = Path('research/work-items/RE-003-harness-design')
POSITIVE = 'syn-94-pos-equal-window-v1'


class FixturePayloadIdentityTests(unittest.TestCase):
    def setUp(self):
        self.protocol = hp.load_json(ROOT / PACKET / 'protocol.json')
        self.fixtures = hp.load_json(ROOT / PACKET / 'fixture-identities.json')

    def test_committed_empty_payload_template_remains_valid(self):
        fixtures = hp.validate_fixtures(self.fixtures, self.protocol)
        self.assertEqual(len(fixtures), 3)
        self.assertTrue(all(row['payload_sha256'] == hashlib.sha256(b'').hexdigest()
                            for row in fixtures.values()))
        # The intentionally wrong target is retained as a negative control;
        # this check validates payload syntax, not known-target equivalence.
        self.assertEqual(fixtures['syn-94-neg-wrong-digest-v1']['target_sha256'], '0' * 64)
        request = hp.load_json(ROOT / PACKET / 'examples/plan-only.json')
        self.assertEqual(hp.validate_request(request, fixtures)['status'], 'planned')

    def test_malformed_declared_payload_hash_rejected(self):
        for value in ('not-a-sha256', 'g' * 64, None):
            with self.subTest(value=value):
                fixtures = copy.deepcopy(self.fixtures)
                row = next(row for row in fixtures['fixtures'] if row['fixture_id'] == POSITIVE)
                row['payload_sha256'] = value
                with self.assertRaisesRegex(ValueError, 'invalid payload_sha256'):
                    hp.validate_fixtures(fixtures, self.protocol)

    def test_real_cli_refuses_malformed_fixture_identity(self):
        # Real committed source/packet copies, no mocked parser, approval,
        # target or comparator. The captured executables are never read.
        with tempfile.TemporaryDirectory(prefix='re003-payload-') as temporary:
            root = Path(temporary)
            (root / 'tools').mkdir()
            shutil.copyfile(ROOT / 'tools/harness_plan.py', root / 'tools/harness_plan.py')
            (root / PACKET).parent.mkdir(parents=True)
            shutil.copytree(ROOT / PACKET, root / PACKET)
            path = root / PACKET / 'fixture-identities.json'
            fixtures = json.loads(path.read_text())
            row = next(row for row in fixtures['fixtures'] if row['fixture_id'] == POSITIVE)
            row['payload_sha256'] = 'not-a-sha256'
            path.write_text(json.dumps(fixtures, indent=2) + '\n')
            result = subprocess.run(
                [sys.executable, '-B', str(root / 'tools/harness_plan.py'),
                 '--request', str(root / PACKET / 'examples/plan-only.json')],
                cwd=root, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid payload_sha256', result.stderr)
            self.assertNotIn('"status": "planned"', result.stdout)


if __name__ == '__main__':
    unittest.main()
