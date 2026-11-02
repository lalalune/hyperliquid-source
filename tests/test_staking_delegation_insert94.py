"""Offline tests for the four digest-bound staking insertion bodies."""
import struct
import unittest

from tools import staking_delegation_insert94 as subject


class StakingInsertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        subject.validate_image(cls.image)

    def test_fde_bounds_and_full_window_hashes(self):
        for role, address in subject.FUNCTIONS.items():
            with self.subTest(role=role):
                start, end = self.image.exact_fde(address)
                self.assertEqual(end-start, subject.WINDOW_SIZES[role])
                self.assertEqual(len(subject.decode_range(self.image,start,end)),
                                 {'member':696,'user_balance':696,'user_books':764,'validator_group':783}[role])

    def test_incoming_calls_name_the_selected_bodies(self):
        for site, role in subject.CALL_SITES:
            with self.subTest(site=site):
                self.assertEqual(subject.call_target(self.image,site),subject.FUNCTIONS[role])

    def test_boundary_relocations(self):
        rows = subject.relocation_records(self.image)
        self.assertEqual(rows[subject.SLOT_MEMCPY][3], 'memcpy')
        self.assertEqual(rows[subject.SLOT_MEMMOVE][3], 'memmove')
        self.assertEqual(rows[subject.SLOT_ALLOC][0], 8)
        self.assertEqual(len(rows), 8)

    def test_all_leaf_gaps_and_sizes(self):
        for role, address in subject.FUNCTIONS.items():
            for size in range(12):
                for gap in range(size+1):
                    with self.subTest(role=role,size=size,gap=gap):
                        observed = subject.evaluate(self.image,address,(),(),size,gap)
                        self.assertEqual(observed['keys'],size+1)
                        self.assertEqual(observed['depth'], int(size==11))
                        self.assertEqual(observed['allocations'],
                                         ([584,680] if role=='validator_group' else [496,592]) if size==11 else [])

    def test_full_leaf_pivot_boundaries(self):
        for role, address in subject.FUNCTIONS.items():
            for gap in range(12):
                with self.subTest(role=role,gap=gap):
                    observed = subject.evaluate(self.image,address,(),(),11,gap)
                    expected = (4,5,6) if gap < 5 else (5,6,5) if gap == 5 else (5,5,6) if gap == 6 else (6,6,5)
                    self.assertEqual((observed['pivot'],observed['left_count'],observed['right_count']), expected)

    def test_full_parent_split_and_new_root(self):
        for role,address in subject.FUNCTIONS.items():
            for edge in range(12):
                with self.subTest(role=role,edge=edge):
                    observed = subject.evaluate(self.image,address,(11,),(edge,),11,6)
                    self.assertEqual(observed['depth'],2)
                    self.assertEqual(observed['allocations'],[584,680,680] if role=='validator_group' else [496,592,592])
                    self.assertEqual(observed['pivot'],4 if edge < 5 else 5 if edge <= 6 else 6)

    def test_two_level_cascade_and_spare_parent(self):
        for role,address in subject.FUNCTIONS.items():
            for counts,edges,allocs,height in (((11,11),(5,6),[496,592,592,592],3),
                                                ((1,11),(0,11),[496,592],2),
                                                ((11,5),(6,5),[496],2)):
                with self.subTest(role=role,counts=counts):
                    observed = subject.evaluate(self.image,address,counts,edges,11,5)
                    if role == 'validator_group': allocs = [584 if x==496 else 680 for x in allocs]
                    self.assertEqual(observed['allocations'],allocs)
                    self.assertEqual(observed['depth'],height)

    def test_three_internal_levels_propagate_without_losing_a_child(self):
        for role,address in subject.FUNCTIONS.items():
            with self.subTest(role=role):
                observed = subject.evaluate(self.image,address,(11,11,11),(0,5,11),11,6)
                self.assertEqual(observed['depth'],4)
                self.assertEqual(observed['allocations'],[584,680,680,680,680] if role=='validator_group' else [496,592,592,592,592])

    def test_allocation_failure_paths(self):
        for role,address in subject.FUNCTIONS.items():
            for counts,edges,failed in (((),(),1),((),(),2),((11,),(6,),2),((11,),(6,),3)):
                with self.subTest(role=role,counts=counts,failed=failed):
                    observed = subject.evaluate(self.image,address,counts,edges,11,5,
                                                fail_alloc_at=failed,expect_panic=True)
                    self.assertIn('failure sink reached',observed['panic'])
                    self.assertEqual(len(observed['allocations']),failed)

    def test_corrupt_shapes_reach_failure_sink(self):
        for role,address in subject.FUNCTIONS.items():
            for counts,edges,corruption in (((),(),{'null_root':True}),
                                           ((1,),(0,),{'bad_cursor_depth':True}),
                                           ((),(),{'corrupt_leaf_count':22}),
                                           ((11,),(0,),{'corrupt_parent_count':22}),
                                           ((),(),{'root_height_override':2**64-1}),
                                           ((),(),{'root_height_override':1})):
                with self.subTest(role=role,corruption=corruption):
                    observed = subject.evaluate(self.image,address,counts,edges,11,5,
                                                expect_panic=True,**corruption)
                    self.assertIn('failure sink reached',observed['panic'])

    def test_capacity_corruption_is_detected_by_the_reference_model(self):
        for role,address in subject.FUNCTIONS.items():
            with self.subTest(role=role):
                with self.assertRaisesRegex(subject.Halt,'unexpected root height'):
                    offset, replacement = subject.MUTATIONS[role][0]
                    subject.evaluate(self.image,address,(),(),10,5,patches={address+offset:replacement})

    def test_pivot_and_key_copy_corruptions_are_detected(self):
        for role,address in subject.FUNCTIONS.items():
            for (offset,replacement),(count,gap) in zip(subject.MUTATIONS[role][1:],((11,0),(4,4),(10,5))):
                with self.subTest(role=role,offset=offset):
                    with self.assertRaises((subject.Halt,subject.Panicked,subject.EvidenceError)):
                        subject.evaluate(self.image,address,(),(),count,gap,patches={address+offset:replacement})

    def test_mutated_jump_cannot_leave_selected_fde(self):
        for role,address in subject.FUNCTIONS.items():
            with self.subTest(role=role):
                _, end = self.image.exact_fde(address)
                code = b'\xe9' + struct.pack('<i', end + 16 - (address + 5))
                patches = {address+i: byte for i,byte in enumerate(code)}
                with self.assertRaisesRegex(subject.Halt,'control left selected FDE'):
                    subject.evaluate(self.image,address,(),(),0,0,patches=patches)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(subject.EvidenceError,'SHA-256 mismatch'):
            subject.load_image(expected='0'*64)

    def test_outside_addresses_are_rejected(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.exact_fde(subject.FUNCTIONS['member']+1)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(2**63)
        with self.assertRaises(subject.EvidenceError):
            subject.at(self.image,subject.FUNCTIONS['member'],2**63)

    def test_anchor_and_call_opcode_corruption(self):
        with self.assertRaises(subject.EvidenceError):
            subject.require_anchor('capacity',bytes.fromhex('4883fb0a'),bytes.fromhex('4883fb0b'))
        with self.assertRaises(subject.EvidenceError):
            subject.call_target(self.image,subject.CALL_SITES[0][0]+1)

    def test_invalid_fixture_inputs_rejected(self):
        with self.assertRaises(ValueError):
            subject.evaluate(self.image,subject.FUNCTIONS['member'],(),(),11,12)
        with self.assertRaises(ValueError):
            subject.evaluate(self.image,subject.FUNCTIONS['member'],(5,),(6,),11,0)


if __name__ == '__main__':
    unittest.main()
