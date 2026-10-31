import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import validate_progress


def _progress(component_id):
    return {'gates': {}, 'components': {component_id: {
        'gates': {}, 'evidence': [], 'raw_equal_bodies': 0,
        'normalized_only_bodies': 0, 'total_function_windows': None}}}


class CatalogueComponentFirstTaskTests(unittest.TestCase):
    def test_missing_component_first_task_rejected(self):
        components = [{'id': 'exchange', 'name': 'Exchange', 'scope': 'Spot',
                       'artifact': 'hl-node', 'depends_on': []}]
        with self.assertRaises(ValueError):
            validate_progress(components, _progress('exchange'), Path('.'))

    def test_first_task_component_accepted(self):
        components = [{'id': 'exchange', 'name': 'Exchange', 'scope': 'Spot',
                       'artifact': 'hl-node', 'first_task': 'Map handlers',
                       'depends_on': []}]
        validate_progress(components, _progress('exchange'), Path('.'))


if __name__ == '__main__':
    unittest.main()
