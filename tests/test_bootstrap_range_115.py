"""Node115-specific entry/range regression and closed evaluation boundaries."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap_range_115 as subject

PACKET = subject.ROOT / 'research/work-items/RE-014-bootstrap-range-rust-115'


class RangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        blob = subject.TARGET.read_bytes()
        if len(blob) != 105896032 or hashlib.sha256(blob).hexdigest() != subject.SHA:
            raise ValueError('node115 target identity')
        cls.image = subject.cpu.Image(blob)

    def test_span_and_borrow_boundaries(self):
        for lower, target, expected in [(0, 30000, 'W\t0\t99'), (0, 30001, 'S'),
                                        (1, 30001, 'W\t1\t100'), (100, 50, 'R')]:
            self.assertEqual(subject.evaluate(self.image, lower, target)[0], expected)

    def test_inclusive_equality_and_saturation_are_fresh115_semantics(self):
        maximum = subject.cpu.U64
        for lower, target, expected in [(0, 0, 'W\t0\t0'), (0, 100, 'W\t0\t99'),
                                        (maximum - 98, maximum, f'W\t{maximum-98}\t{maximum}'),
                                        (maximum, maximum, f'W\t{maximum}\t{maximum}')]:
            self.assertEqual(subject.evaluate(self.image, lower, target)[0], expected)

    def test_unqualified_memory_and_helpers_fail_closed(self):
        m = subject.Machine(self.image)
        for address, write in [(subject.STATE, False), (subject.LOW, True),
                               (subject.cpu.STACK, True)]:
            with self.assertRaisesRegex(ValueError, 'unqualified'):
                m.bounds(address, 8, write)
        with self.assertRaisesRegex(ValueError, 'no bootstrap115 helper'):
            m.call(0)

    def test_before_rust_freeze_keeps_historical_logic_disclosure(self):
        freeze = json.loads((PACKET / 'FREEZE.json').read_text())
        self.assertEqual(freeze['target_sha256'], subject.SHA)
        self.assertEqual(freeze['rows'], 53038)
        self.assertFalse(freeze['node115_production_source_exists'])
        self.assertTrue(freeze['retired94_logic_preexisted'])
        record = json.loads((PACKET / 'native-context.json').read_text())
        lo, hi = (int(record['owner'][field], 16) for field in ('start', 'end'))
        self.assertEqual(self.image.fde_of(0x5a88391), (lo, hi))
        raw = self.image.data[self.image.file_offset(lo):self.image.file_offset(hi)]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), record['owner']['sha256'])
        controls = json.loads((PACKET / 'native-controls.json').read_text())
        self.assertEqual(len(controls), 5)
        for control in controls:
            self.assertNotEqual(control['before'], control['after'])
            self.assertTrue(control['full_body_binding_rejects'])


if __name__ == '__main__':
    unittest.main()
