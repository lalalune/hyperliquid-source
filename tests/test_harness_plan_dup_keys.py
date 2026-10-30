"""harness_plan must reject duplicate keys in JSON inputs.

Sibling of open #142 (catalogue generate) and merged-by-pattern #114
(artifact manifest) / #115 (imports verification): plain json.loads keeps
the last value for a duplicated key, so a harness request file that lists
a wrong target_sha256 first and the correct digest second is silently
accepted as planned. The validator never sees the first value.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'
WRONG = '0' * 64


def _dup_request_text():
    text = (PACKET / 'examples/plan-only.json').read_text()
    return text.replace('"target_sha256":',
                        f'"target_sha256": "{WRONG}", "target_sha256":', 1)


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'req.json'
        p.write_text(text)
        return hp.load_json(p)


class DuplicateKeyTests(unittest.TestCase):
    def test_duplicate_target_sha256_rejected(self):
        with self.assertRaises(ValueError):
            _load_text(_dup_request_text())

    def test_duplicate_network_key_rejected(self):
        text = (PACKET / 'examples/plan-only.json').read_text()
        dup = text.replace('"network":',
                           '"network": "allow", "network":', 1)
        with self.assertRaises(ValueError):
            _load_text(dup)

    def test_duplicate_key_inside_nested_object_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"outer": {"a": 1, "a": 2}}')

    def test_clean_plan_only_still_loads_and_validates(self):
        protocol = hp.load_json(PACKET / 'protocol.json')
        fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol)
        plan = hp.validate_request(
            hp.load_json(PACKET / 'examples/plan-only.json'), fixtures)
        self.assertEqual(plan['status'], 'planned')


if __name__ == '__main__':
    unittest.main()
