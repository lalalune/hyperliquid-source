"""foundation_duration_guards must reject duplicate keys in its --check input.

Sibling of #160 (foundation_hour) and #164 (foundation_millis), and
of open #142: the --check file is the retained-evidence drift gate —
main() requires the freshly computed result to equal it exactly.
Loaded with plain json.loads, a duplicated key in that file is
silently resolved to its last value, so a check file that contains
both a drifted value and the matching value passes the gate instead
of being rejected as corrupt. The fix rejects any duplicate key, at
any nesting level, before comparison.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from foundation_duration_guards import load_check


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'check.json'
        p.write_text(text)
        return load_check(p)


class CheckDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_top_level_key_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"a": 1, "a": 2}')

    def test_duplicate_nested_key_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"outer": {"x": 1, "x": 2}}')

    def test_clean_check_still_loads(self):
        doc = _load_text('{"a": 1, "outer": {"x": 2}}')
        self.assertEqual(doc, {"a": 1, "outer": {"x": 2}})


if __name__ == '__main__':
    unittest.main()
