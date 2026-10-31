"""foundation_millis must reject duplicate keys in its records input.

Sibling of open #164 (foundation_millis --check input) and of #151 /
#155 / #156 / #157 / #160 / #165: inspect() loads the retained packet
records file with plain json.loads, so a duplicated key in that file is
silently resolved to its last value — a records file that lists a wrong
target_sha256 first and the correct digest second passes the identity
require in analyze(), and a duplicated body_sha256 inside a window row
is checked against the last copy only. The validator never sees the
first value. The fix rejects any duplicate key, at any nesting level,
before analyze() runs. The --check input is a different load site,
covered by #164; this loader is not.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from foundation_millis import SHA256, load_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/foundation-millis-94'


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'records.json'
        p.write_text(text)
        return load_records(p)


class RecordsDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_target_sha256_rejected(self):
        text = ('{"target_sha256": "' + '0' * 64 + '", '
                '"target_sha256": "' + SHA256 + '", "windows": []}')
        with self.assertRaises(ValueError):
            _load_text(text)

    def test_duplicate_nested_window_key_rejected(self):
        text = ('{"target_sha256": "' + SHA256 + '", "windows": ['
                '{"name": "conversion", "body_sha256": "0", '
                '"body_sha256": "1"}]}')
        with self.assertRaises(ValueError):
            _load_text(text)

    def test_clean_records_still_load(self):
        doc = _load_text('{"target_sha256": "' + SHA256 + '", "windows": []}')
        self.assertEqual(doc['target_sha256'], SHA256)
        self.assertEqual(doc['windows'], [])

    def test_retained_records_still_load(self):
        doc = load_records(PACKET / 'records.json')
        self.assertEqual(doc['target_sha256'], SHA256)
        self.assertTrue(doc['windows'])


if __name__ == '__main__':
    unittest.main()
