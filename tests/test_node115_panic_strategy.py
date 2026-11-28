import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-panic-strategy'
spec = importlib.util.spec_from_file_location('node115_personality_census', PACKET / 'census.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class PersonalityCensusTest(unittest.TestCase):
    def test_full_capture_and_all_bounded_call_sites(self):
        observed = probe.census(probe.entry.TARGET.read_bytes())
        self.assertEqual(observed, json.loads((PACKET / 'census.json').read_text()))
        self.assertEqual(sum(p['fdes'] for p in observed['personalities']), 135313)
        self.assertEqual(sum(sum(p['call_sites'].values()) for p in observed['personalities']), 400843)

    def test_zero_landing_offset_is_not_a_cleanup(self):
        self.assertEqual(probe.call_sites(bytes.fromhex('ffff010400040000'), 0, 4), {'no_landing_pad': 1})

    def test_invalid_call_site_range_or_landing_cannot_count_as_cleanup(self):
        for table in ('ffff010400040400', 'ffff010402030100', 'ffff010400040001'):
            with self.subTest(table=table), self.assertRaises(ValueError):
                probe.call_sites(bytes.fromhex(table), 0, 4)
