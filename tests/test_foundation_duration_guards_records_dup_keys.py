"""foundation_duration_guards must reject duplicate keys in its records input.

Sibling of open #165 (foundation_duration_guards --check input) and of
#705 (foundation_millis records input): inspect() loads the retained
packet records file with plain json.loads, so a duplicated key in that
file is silently resolved to its last value — a records file that lists
a wrong target_sha256 first and the correct digest second passes the
identity require in analyze(), and a duplicated key inside the
relative_slots map is checked against the last copy only. The
validator never sees the first value. The fix rejects any duplicate
key, at any nesting level, before analyze() runs. The --check input is
a different load site, covered by #165; this loader is not.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from foundation_duration_guards import SHA256, load_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/foundation-duration-guards-94'


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'records.json'
        p.write_text(text)
        return load_records(p)


class RecordsDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_target_sha256_rejected(self):
        text = ('{"target_sha256": "' + '0' * 64 + '", '
                '"target_sha256": "' + SHA256 + '"}')
        with self.assertRaises(ValueError):
            _load_text(text)

    def test_duplicate_nested_relative_slot_rejected(self):
        text = ('{"target_sha256": "' + SHA256 + '", '
                '"relative_slots": {"0x392fb1e": "0x1", '
                '"0x392fb1e": "0x2"}}')
        with self.assertRaises(ValueError):
            _load_text(text)

    def test_clean_records_still_load(self):
        doc = _load_text('{"target_sha256": "' + SHA256 + '", '
                         '"relative_slots": {}}')
        self.assertEqual(doc['target_sha256'], SHA256)
        self.assertEqual(doc['relative_slots'], {})

    def test_retained_records_still_load(self):
        doc = load_records(PACKET / 'records.json')
        self.assertEqual(doc['target_sha256'], SHA256)
        self.assertTrue(doc['relative_slots'])


if __name__ == '__main__':
    unittest.main()
