import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import replay_timer_delay_pointer_115 as subject


class ReplayTimerDelayPointer115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.result = subject.verify(cls.data)

    def test_target_digest_and_four_exact_fde_windows(self):
        self.assertEqual(self.result['target_sha256'], subject.SHA)
        self.assertEqual(set(self.result['windows']), set(subject.FDE_SPECS))
        for name, (start, end) in subject.FDE_SPECS.items():
            self.assertEqual((self.result['windows'][name]['start'],
                              self.result['windows'][name]['end']), (start, end))

    def test_pointer_flow_is_narrow_and_explicit(self):
        self.assertEqual(len(self.result['pointer_flow']), 9)
        self.assertIn('remain inferred/unresolved', self.result['claim_status'])
        self.assertFalse(self.result['captured_target_executed'])
        self.assertFalse(self.result['component_gate_changed'])

    def test_relocations_are_exact_relative_targets(self):
        self.assertEqual(self.result['relocations']['0x64e0f70']['addend'], 0x15ed960)
        self.assertEqual(self.result['relocations']['0x64e0f78']['addend'], 0x162a9a0)

    def test_retained_records_match_authenticated_target(self):
        retained = json.loads((subject.PACKET / 'records.json').read_text())
        self.assertEqual(retained, self.result)

    def test_anchor_mutations_are_rejected(self):
        for name, window in self.result['windows'].items():
            with self.subTest(window=name):
                changed = bytearray(self.data)
                anchor = window['anchors'][0]['va']
                changed[window['file_offset'] + anchor - window['start']] ^= 1
                with self.assertRaises(ValueError):
                    subject.verify(changed, authenticate=False)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.verify(b'not node115')


if __name__ == '__main__':
    unittest.main()
