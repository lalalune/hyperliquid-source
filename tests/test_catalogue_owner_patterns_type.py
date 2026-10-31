import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import owner


class CatalogueOwnerPatternsTypeTests(unittest.TestCase):
    def test_non_list_patterns_rejected(self):
        components = [{'id': 'exchange', 'patterns': 123}]
        with self.assertRaises(ValueError):
            owner('base/l1/foo.rs', components)

    def test_list_patterns_accepted(self):
        components = [{'id': 'exchange', 'patterns': ['base/*']}]
        self.assertEqual(owner('base/l1/foo.rs', components), 'exchange')


if __name__ == '__main__':
    unittest.main()
