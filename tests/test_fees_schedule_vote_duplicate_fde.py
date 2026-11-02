"""Fdes in fees_schedule_vote must refuse duplicate FDE starts.

Fdes builds its lookup straight from the shared .eh_frame records walker
(`fde_extents.eh_frame_records`) as a dict keyed by start, bypassing the
validated `fde_extents` path whose unwind index rejects duplicate starts.
The dict comprehension kept only the last record for a repeated start, so
one FDE silently shadowed the other. This consumer decides reachability
with the fold: `closure()` treats a start missing from `by_start` as a
stop and decodes every reached function out to `range_of`'s end, so the
surviving range decides which functions are reached and how much code is
decoded — and record order decided which range survived. The sibling
copy in fees_schedule_admission already refuses the duplicate in its
fold; this copy must do the same.
"""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from test_fde_extents import build
import fees_schedule_vote as T


class DuplicateFdeStartTests(unittest.TestCase):
    def test_rejects_duplicate_start_narrow_then_wide(self):
        data, _ = build([(0x1000, 0x10, None, 'zR'), (0x1000, 0x40, None, 'zR'),
                         (0x1038, 0x8, None, 'zR')])
        with self.assertRaises(T.EvidenceError):
            T.Fdes(bytes(data))

    def test_rejects_duplicate_start_wide_then_narrow(self):
        data, _ = build([(0x1000, 0x40, None, 'zR'), (0x1000, 0x10, None, 'zR'),
                         (0x1038, 0x8, None, 'zR')])
        with self.assertRaises(T.EvidenceError):
            T.Fdes(bytes(data))

    def test_rejects_duplicate_start_identical_ranges(self):
        data, _ = build([(0x1000, 0x10, None, 'zR'), (0x1000, 0x10, None, 'zR'),
                         (0x1038, 0x8, None, 'zR')])
        with self.assertRaises(T.EvidenceError):
            T.Fdes(bytes(data))

    def test_distinct_starts_still_resolve(self):
        data, _ = build()
        fdes = T.Fdes(bytes(data))
        self.assertEqual(len(fdes.by_start), 3)
        self.assertEqual(fdes.range_of(0x1000)['end'], 0x1010)
        self.assertEqual(fdes.range_of(0x1020)['end'], 0x1030)
        self.assertEqual(fdes.range_of(0x1038)['end'], 0x1040)
        with self.assertRaises(T.EvidenceError):
            fdes.range_of(0x1010)


if __name__ == '__main__':
    unittest.main()
