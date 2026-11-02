"""Target-grounded and corruption controls for the inner removal evidence."""
import unittest

from tools import staking_inner_removal94 as subject


class InnerRemovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()

    def test_digest_is_checked_before_parsing(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256 mismatch'):
            subject.load_image(expected='0' * 64)

    def test_selected_fdes_and_file_backing(self):
        self.assertEqual(self.image.exact_fde(0x2fc8d70), (0x2fc8d70, 0x2fc95a9))
        self.assertEqual(self.image.exact_fde(0x2fae350), (0x2fae350, 0x2fae795))
        for start, end in (self.image.exact_fde(v) for v in subject.FUNCTIONS.values()):
            raw, off = subject.file_bytes(self.image, start, end-start)
            self.assertEqual(len(raw), end-start)
            self.assertGreater(off, 0)
            self.assertTrue(subject.decode_range(self.image, start, end))

    def test_rejects_outside_file_backed_and_cross_boundary_ranges(self):
        with self.assertRaises(subject.EvidenceError):
            subject.file_bytes(self.image, 0, 0)
        with self.assertRaises(subject.EvidenceError):
            subject.file_bytes(self.image, (1 << 63), 1)
        section = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(subject.EvidenceError):
            subject.file_bytes(self.image, section['address'] + section['size'] - 1, 2)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(subject.EvidenceError):
            subject.file_bytes(self.image, bss['address'], 1)

    def test_every_instruction_anchor_rejects_one_byte_corruption(self):
        self.assertEqual(len(subject.verify_pins(self.image)), len(subject.PINS))
        for name, address, raw in subject.PINS:
            with self.subTest(name=name):
                first = bytes.fromhex(raw)[0]
                with self.assertRaisesRegex(subject.EvidenceError, 'pin mismatch'):
                    subject.verify_pins(self.image, {address:first ^ 1})

    def test_root_leaf_compaction_at_boundaries(self):
        for n in range(1,12):
            for slot in {0,n//2,n-1}:
                with self.subTest(n=n, slot=slot):
                    result=subject.run_leaf(self.image,('single',n,0,'leaf',slot))
                    self.assertFalse(result['boundary'])
                    self.assertEqual((result['flag'],result['frees']), (0,0))

    def test_leaf_merges_in_both_directions_and_reports_root(self):
        for side in ('left','right'):
            for sibling in (5,6):
                left,right=(5,sibling) if side=='left' else (sibling,5)
                with self.subTest(side=side, sibling=sibling):
                    result=subject.run_leaf(self.image,('pair',left,right,side,2))
                    self.assertEqual((result['boundary'],result['flag'],result['frees']), (False,1,1))
                    self.assertIn(subject.FUNCTIONS['merge'],result['seen'])

    def test_equal_to_minimum_occupancy_does_not_repair(self):
        for side in ('left','right'):
            left,right=(6,5) if side=='left' else (5,6)
            result=subject.run_leaf(self.image,('pair',left,right,side,0))
            self.assertEqual((result['boundary'],result['flag'],result['frees']), (False,0,0))
            self.assertNotIn(subject.FUNCTIONS['merge'],result['seen'])

    def test_borrow_is_a_checked_boundary(self):
        for side in ('left','right'):
            left,right=(5,7) if side=='left' else (7,5)
            result=subject.run_leaf(self.image,('pair',left,right,side,2))
            self.assertTrue(result['boundary'])
            self.assertIsNone(result['flag'])
            self.assertEqual(result['frees'],0)

    def test_cascading_leaf_merge(self):
        for family, expected in (('deep',2),('deep3',3)):
            for side in ('leftmost','middle','rightmost'):
                with self.subTest(family=family, side=side):
                    result=subject.run_leaf(self.image,(family,5,5,side,2))
                    self.assertFalse(result['boundary'])
                    self.assertEqual((result['flag'],result['frees']), (1,expected))

    def test_parent_repair_or_borrow_boundary(self):
        for side,left,right,stop in (('leftmost',5,7,True),('rightmost',7,5,True),
                                     ('middleleft',6,5,False),('middleright',5,6,False)):
            with self.subTest(side=side):
                result=subject.run_leaf(self.image,('matrix2',left,right,side,2))
                self.assertEqual(result['boundary'],stop)
                self.assertEqual(result['frees'],1)

    def test_direct_merge_cursor_and_children(self):
        for spec in subject.merge_cases():
            with self.subTest(spec=spec):
                result=subject.merge_fixture(self.image,*spec)
                self.assertFalse(result['panic'])
                self.assertEqual(result['cursor'][2],spec[4]+(spec[0]+1 if spec[3] else 0))

    def test_invalid_descriptors_hit_the_exact_guard_without_writes(self):
        for kind in ('cursor_left','cursor_right','overfull'):
            with self.subTest(kind=kind):
                self.assertTrue(subject.corruption_case(self.image,kind))

    def test_empty_parent_panics_after_leaf_compaction(self):
        self.assertIn(0x2fc9590,subject.empty_parent_case(self.image))

    def test_targeted_instruction_mutations_are_detected(self):
        results=subject.mutation_controls(self.image)
        self.assertEqual(len(results),11)
        self.assertEqual(len({row[0] for row in results}),11)


if __name__ == '__main__':
    unittest.main()
