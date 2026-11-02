import copy
import unittest

from tools import staking_snapshot_filter94 as target


class SnapshotFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = target.load_image()
        cls.table = target.checked_records(cls.image)

    def run_case(self, stakes, profiles, power, patch=None):
        item = target.case('test', stakes, profiles, power)
        return target.evaluate(self.image, item, patch)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(target.EvidenceError):
            target.load_image(expected='0' * 64)

    def test_fde_extents_and_boundaries(self):
        self.assertEqual(self.image.exact_fde(target.FILTER), (0x3bcfd70,0x3bd0521))
        self.assertEqual(self.image.exact_fde(target.PREDICATE), (0x33755f0,0x33757b7))
        self.assertEqual(self.image.exact_fde(target.ITER), (0x330f550,0x330f758))
        self.assertEqual(self.image.exact_fde(target.BULK), (0x2fb8dd0,0x2fb975b))
        with self.assertRaises(target.EvidenceError):
            self.image.exact_fde(target.FILTER + 1)
        with self.assertRaises(target.EvidenceError):
            target.file_bytes(self.image,0xfffffffffffffff0,64)
        bss = self.image.named['.bss']
        with self.assertRaises(target.EvidenceError):
            target.file_bytes(self.image,bss['address'],8)

    def test_corrupted_anchor_is_refused(self):
        changed = copy.copy(self.image)
        changed.blob = bytearray(self.image.blob)
        changed.blob[self.image.offset(0x3bcfdc3)] ^= 8
        with self.assertRaises(target.EvidenceError):
            target.checked_records(changed)

    def test_comparator_relocation_and_symbol(self):
        row = next(x for x in self.image.relocations() if x[0] == target.COMPARE)
        self.assertEqual(row[1],6)
        self.assertEqual(target.symbol_name(self.image,row[3]),'memcmp')
        with self.assertRaises(target.EvidenceError):
            target.symbol_name(self.image, 1 << 30)

    def test_target_word_not_effective_or_power(self):
        result = self.run_case([(1,11,73),(2,12,74)],[(1,101),(2,102)],[(101,999),(102,0)])
        self.assertEqual(result['rows'],[(1,73),(2,74)])
        self.assertEqual(result['logs'],[])
        self.assertEqual(result['drops'],[145,145])
        self.assertTrue(result['unchanged'])
        result = self.run_case([(1,0,0),(2,2,(1<<64)-1)],[(1,101),(2,102)],[(101,0),(102,0)])
        self.assertEqual(result['rows'],[(1,0),(2,(1<<64)-1)])

    def test_missing_profile_and_missing_power_have_distinct_effects(self):
        result = self.run_case([(1,1,10),(2,2,20),(3,3,30)],[(2,102),(3,103)],[(103,1)])
        self.assertEqual(result['rows'],[(3,30)])
        self.assertEqual(result['logs'],[145])
        self.assertEqual(result['drops'],[145,145])
        result = self.run_case([], [], [])
        self.assertEqual((result['rows'],result['logs'],result['drops']),([],[],[]))

    def test_shared_signer_does_not_deduplicate_validator_rows(self):
        result = self.run_case([(1,11,41),(2,12,42)],[(1,999),(2,999)],[(999,0)])
        self.assertEqual(result['rows'],[(1,41),(2,42)])

    def test_all_twenty_signer_bytes_matter(self):
        for n in range(20):
            with self.subTest(byte=n):
                other = 1 << ((19-n)*8)
                result = self.run_case([(1,1,11),(2,2,22)],[(1,0),(2,other)],[(other,0)])
                self.assertEqual(result['rows'],[(2,22)])

    def test_all_twenty_validator_bytes_matter(self):
        for n in range(20):
            with self.subTest(byte=n):
                other = 1 << ((19-n)*8)
                result = self.run_case([(0,4,11),(other,5,22)],[(other,77)],[(77,1)])
                self.assertEqual(result['rows'],[(other,22)])
                self.assertEqual(result['logs'],[145])

    def test_inline_search_compares_all_twenty_bytes(self):
        for n in range(20):
            with self.subTest(byte=n):
                other = 1 << ((19-n)*8)
                result = self.run_case([(0,1,10),(1,2,20),(2,3,30)],
                                       [(0,77),(1,0),(2,other)],[(77,1),(other,1)])
                self.assertEqual(result['rows'],[(0,10),(2,30)])
                result = self.run_case([(0,1,10),(1,2,20),(1+other,3,30)],
                                       [(0,77),(1+other,78)], [(77,1),(78,1)])
                self.assertEqual(result['rows'],[(0,10),(1+other,30)])

    def test_tree_growth_and_inorder(self):
        for n in (4,5,11,12,143,144):
            with self.subTest(rows=n):
                stakes = [(i,i,i+1000) for i in range(n)]
                profiles = [(i,i+300) for i in range(n)]
                power = [(i+300,0) for i in range(n)]
                result = self.run_case(stakes,profiles,power)
                self.assertEqual(result['rows'],[(i,i+1000) for i in range(n)])
                self.assertEqual(bool(result['grows']),n>4)
                self.assertTrue(result['unchanged'])

    def test_flipped_membership_branch_changes_result(self):
        args=([(1,10,20)],[(1,100)],[(100,30)])
        baseline=self.run_case(*args)
        changed=self.run_case(*args,patch={0x3bcfdee:0x74})
        self.assertEqual(baseline['rows'],[(1,20)])
        self.assertEqual(changed['rows'],[])

    def test_corrupt_second_word_load_changes_both_loop_forms(self):
        args=([(1,10,20),(2,11,21)],[(1,100),(2,101)],[(100,30),(101,31)])
        self.assertEqual(self.run_case(*args)['rows'],[(1,20),(2,21)])
        self.assertEqual(self.run_case(*args,patch={0x3bcfdc3:0})['rows'],[(1,10),(2,21)])
        self.assertEqual(self.run_case(*args,patch={0x3bd00de:0})['rows'],[(1,20),(2,11)])

    def test_corrupted_tree_length_is_rejected(self):
        h = target.SnapshotHarness(self.image)
        entries = [(target.key(i), (i).to_bytes(8,'little') + (i+1).to_bytes(8,'little')) for i in range(12)]
        h.holder(target.ROOT_STATE + 0x10, target.STAKE, entries)
        root = h.read(target.ROOT_STATE + 0x10)
        child = h.read(root + target.STAKE[4])
        h.write(child + target.STAKE[3], 12, 2)
        with self.assertRaises(target.Halt):
            h.check_tree(target.ROOT_STATE + 0x10, target.STAKE, entries)

    def test_duplicate_fixture_key_is_rejected(self):
        with self.assertRaises(target.Halt):
            self.run_case([(1,1,2),(1,3,4)],[],[])

    def test_filter_output_is_stored_in_bulk_tree(self):
        for n, height in ((0,None),(1,0),(11,0),(12,1),(144,2)):
            with self.subTest(rows=n):
                result = self.run_case([(i,100+i,1000+i) for i in range(n)],
                                       [(i,300+i) for i in range(n)],
                                       [(300+i,999) for i in range(n)])
                self.assertEqual(result['mapped_rows'],[(i,1000+i) for i in range(n)])
                self.assertEqual(result['map_height'],height)
                if n:
                    capacity = result['grows'][-1][1] if result['grows'] else 4
                    self.assertEqual(result['bulk_frees'],[capacity*32])
                else:
                    self.assertEqual(result['bulk_frees'],[])

    def test_sorted_duplicate_controls_keep_last_value(self):
        controls = list(target.bulk_cases())
        self.assertEqual(len(controls),37)
        for item in controls:
            with self.subTest(case=item['name']):
                result = target.evaluate_bulk(self.image,item)
                self.assertEqual(result['mapped_rows'],sorted(dict(item['input']).items()))
                self.assertEqual(result['bulk_frees'],[32*len(item['input'])])

    def test_unsorted_bulk_fixture_is_rejected(self):
        with self.assertRaises(target.EvidenceError):
            target.evaluate_bulk(self.image,{'name':'unsorted','input':[(2,5),(1,7)]})
        with self.assertRaises(target.EvidenceError):
            target.evaluate_bulk(self.image,{'name':'empty','input':[]})

    def test_bulk_corrupt_value_slot_is_rejected(self):
        item = target.case('corrupt-bulk',[(1,10,20)],[(1,100)],[(100,30)])
        with self.assertRaises(target.Halt):
            target.evaluate(self.image,item,{0x2fb8f2f:0x10})

    def test_bad_fixture_key_is_not_silently_truncated(self):
        with self.assertRaises(OverflowError):
            self.run_case([(1<<160,0,0)], [], [])


if __name__ == '__main__':
    unittest.main()
