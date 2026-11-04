"""Node115 exchange prelude order, dual-width cadence and closed evaluator."""
import hashlib
import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import exchange_freeze_115 as subject


class PreludeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = subject.TARGET.read_bytes()
        if hashlib.sha256(data).hexdigest() != subject.SHA:
            raise ValueError('node115 identity')
        cls.image = subject.cpu.Image(data)

    def test_periodic_first_outer_handoff_and_repeated_target_gate(self):
        for lane in range(3):
            cadence = 0 if lane == 0 else 2
            self.assertEqual(subject.evaluate(self.image, lane, 2, 1, 10000, 9999, cadence)[0], 'R')
            self.assertEqual(subject.evaluate(self.image, lane, 0, 1, 10000, 9999, cadence)[0], 'X')
            self.assertEqual(subject.evaluate(self.image, lane, 2, 1, 10001, 10000, cadence)[0], 'X')
            self.assertEqual(subject.evaluate(self.image, lane, 2, None, 10000, None, 1)[0], 'R')

    def test_secondary_and_basic_preparation_and_both_division_widths(self):
        maximum = subject.cpu.U64
        self.assertEqual(subject.evaluate(self.image, 0, 0, 0, 1000, maximum, 0)[0], 'K')
        for lane in (1, 2):
            self.assertEqual(subject.evaluate(self.image, lane, 0, 0, 1000, maximum, 1000)[0], 'P\t0\t0')
            self.assertEqual(subject.evaluate(self.image, lane, 0, 0, 1 << 32, maximum, 1 << 32)[0], 'P\t0\t0')
            self.assertEqual(subject.evaluate(self.image, lane, 0, 0, 1, maximum, 1)[0], 'P\t0\t0')
            with self.assertRaisesRegex(ValueError, 'positive secondary cadence'):
                subject.evaluate(self.image, lane, 0, 0, 1, maximum, 0)

    def test_selected_ror_permutation_flags_and_domain(self):
        machine = subject.Machine(self.image)
        machine.flags = [True, True, False, True]
        self.assertEqual(machine.shift(1, 0x8000000000000001, 4, 64), 0x1800000000000000)
        self.assertEqual(machine.flags, [False, True, False, None])
        for count in (0, 1, 2, 5):
            with self.assertRaisesRegex(ValueError, 'selected ROR64 domain'):
                machine.shift(1, 1, count, 64)

    def test_supporting_label_bytes_and_selector_after_unclosed_helpers(self):
        data, image = self.image.data, self.image
        for freeze_lea, periodic_lea, selector in ((0x5a08003, 0x5a0800a, 0x5a08011),
                                                    (0x5a08863, 0x5a0886a, 0x5a08871)):
            for va, prefix, expected in ((freeze_lea, '488d05', b'freeze'),
                                         (periodic_lea, '488d15', b'periodic')):
                at = image.file_offset(va)
                raw = data[at:at+7]
                self.assertEqual(raw[:3].hex(), prefix)
                target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
                self.assertEqual(data[image.file_offset(target):image.file_offset(target)+len(expected)], expected)
            at = image.file_offset(selector)
            self.assertEqual(data[at:at+7].hex(), '4584ed480f45d0')

    def test_readonly_context_and_helpers_are_closed(self):
        machine = subject.Machine(self.image); machine.case = subject.CASES[0]
        with self.assertRaisesRegex(ValueError, 'outside exchange prelude'):
            machine.store(subject.CTX + machine.case['tag'], 4, 1)
        with self.assertRaisesRegex(ValueError, 'outside exchange prelude'):
            machine.load(subject.CTX + 0x39c8, 8)
        with self.assertRaisesRegex(ValueError, 'helper execution forbidden'):
            machine.call(0)


if __name__ == '__main__':
    unittest.main()
