import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import owner


class CatalogueOwnerPatternsEntryTypeTests(unittest.TestCase):
    def test_non_string_pattern_rejected(self):
        components = [{'id': 'exchange', 'patterns': [123]}]
        with self.assertRaises(ValueError):
            owner('base/l1/foo.rs', components)

    def test_string_patterns_accepted(self):
        components = [{'id': 'exchange', 'patterns': ['base/*']}]
        self.assertEqual(owner('base/l1/foo.rs', components), 'exchange')


if __name__ == '__main__':
    unittest.main()
