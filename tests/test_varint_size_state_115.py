"""Actual five-ABI node115 counter boundaries and bounded memory controls."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import varint_size_state_115 as subject

PACKET = subject.ROOT / 'research/work-items/RE-005-varint-size-state-rust-115'


class SizeStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        blob = subject.TARGET.read_bytes()
        if hashlib.sha256(blob).hexdigest() != subject.SHA:
            raise ValueError('pinned115target')
        cls.image = subject.cpu.Image(blob)

    def test_marker_precommit_and_first_overflow_on_every_abi(self):
        maximum = subject.cpu.U64
        for which in range(5):
            self.assertEqual(subject.evaluate(self.image, which, 251, maximum-1)[0], f'P\t{maximum}')
            self.assertEqual(subject.evaluate(self.image, which, 0, maximum)[0], f'P\t{maximum}')
            self.assertEqual(subject.evaluate(self.image, which, 251, maximum-3)[0], f'O\t{maximum}')

    def test_payload_width_and_qualified_modes(self):
        for which in (0, 3, 4):
            self.assertEqual(subject.evaluate(self.image, which, 1 << 32, 0)[0], 'O\t9')
        for flag in (0, 1, 2, 128, 255):
            self.assertEqual(subject.evaluate(self.image, 0, 65536, 0, flag)[0], 'O\t5')
        for which in (1, 2):
            with self.assertRaisesRegex(ValueError, 'domain'):
                subject.evaluate(self.image, which, 1 << 32, 0)

    def test_memory_and_helpers_are_closed(self):
        machine = subject.Machine(self.image); machine.counter = subject.COUNTER
        with self.assertRaisesRegex(ValueError, 'outside qualified'):
            machine.store(subject.VALUE, 8, 1)
        with self.assertRaisesRegex(ValueError, 'outside qualified'):
            machine.load(subject.OUT+8, 8)
        with self.assertRaisesRegex(ValueError, 'calls forbidden'):
            machine.call(0)

    def test_physical_and_logical_denominators_and_fresh_source_binding(self):
        freeze = json.loads((PACKET / 'FREEZE.json').read_text())
        self.assertEqual((freeze['rows'], freeze['distinct_logical_width_value_count']), (83250, 18000))
        self.assertEqual(sum(freeze['rows_per_owner']), freeze['rows'])
        self.assertFalse(freeze['new115_source_exists'])
        self.assertTrue(freeze['retired_mit_counter_logic_preexisted'])
        owners = json.loads((PACKET / 'owners.json').read_text())
        self.assertEqual((sum(x['bytes'] for x in owners), sum(len(x['instructions']) for x in owners)), (753, 225))
        for row in owners:
            self.assertEqual(row['location']['path'], 'z_forks/bincode-fork/src/enc/write.rs')
            self.assertEqual((row['location']['line'], row['location']['column']), (78, 9))
        for control in json.loads((PACKET / 'native-controls.json').read_text()):
            self.assertNotEqual(control['before'], control['after'])


if __name__ == '__main__':
    unittest.main()
