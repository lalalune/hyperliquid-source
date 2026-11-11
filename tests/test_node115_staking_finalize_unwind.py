"""Byte results and operative controls remain strict across Python patch versions."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-010-node115-staking-finalize-unwind-boundary'
SPEC = importlib.util.spec_from_file_location('staking_finalize_unwind', PACKET / 'verify.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class StakingFinalizeUnwindTests(unittest.TestCase):
    def setUp(self):
        self.retained = json.loads((PACKET / 'verification.json').read_text())

    def test_python_patch_difference_is_reported_without_mutating_provenance(self):
        summary = dict(self.retained, python='3.12.99')
        before = copy.deepcopy(self.retained)
        self.assertEqual(CHECK.compare_retained(summary, self.retained), {
            'retained_python': self.retained['python'], 'current_python': '3.12.99',
        })
        self.assertEqual(self.retained, before)
        self.assertEqual(summary['python'], '3.12.99')

    def test_changed_semantic_count_is_rejected(self):
        summary = dict(self.retained, exception_sites_checked=0)
        with self.assertRaisesRegex(ValueError, 'retained verification differs'):
            CHECK.compare_retained(summary, self.retained)

    def test_missing_operative_control_result_is_rejected(self):
        summary = copy.deepcopy(self.retained)
        summary['corruptions_rejected'].pop()
        with self.assertRaisesRegex(ValueError, 'retained verification differs'):
            CHECK.compare_retained(summary, self.retained)

    def test_static_packet_and_all_four_operative_controls(self):
        data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        packet = json.loads((PACKET / 'records.json').read_text())
        result = CHECK.verify_packet(data, packet)
        self.assertEqual(result['exception_sites_checked'], 4)
        self.assertEqual(CHECK.self_test(data, packet), self.retained['corruptions_rejected'])
        self.assertEqual(len(self.retained['corruptions_rejected']), 4)


if __name__ == '__main__':
    unittest.main()
