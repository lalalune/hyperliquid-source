"""Controls for a digest-bound registration stake-map insertion study."""
import unittest
import struct
from unittest.mock import patch

from tools import staking_register_stake_map94 as study


class StakeRegistrationMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = study.load_image()

    def test_digest_is_checked(self):
        with self.assertRaisesRegex(study.EvidenceError, 'SHA-256 mismatch'):
            study.load_image(expected='0' * 64)

    def test_fde_and_anchors(self):
        study.validate(self.image)
        self.assertEqual(self.image.exact_fde(0x2f54330), (0x2f54330, 0x2f54f90))
        self.assertEqual(self.image.exact_fde(0x33bede0), (0x33bede0, 0x33bef2a))

    def test_non_start_fde_rejected(self):
        with self.assertRaises(study.EvidenceError):
            self.image.exact_fde(0x2f54331)

    def test_not_file_backed(self):
        bss=next(s for s in self.image.sections if s['name']=='.bss')
        with self.assertRaises(study.EvidenceError):
            study.at(self.image,bss['address'],1)

    def test_range_crossing_section_is_rejected(self):
        sec=next(s for s in self.image.sections if s['name']=='.text')
        with self.assertRaises(study.EvidenceError):
            study.at(self.image,sec['address']+sec['size']-1,2)

    def test_negative_range_rejected(self):
        with self.assertRaises(study.EvidenceError):
            study.at(self.image,0x2f54330,-1)

    def test_corrupt_function_bytes_are_rejected(self):
        original=study.at
        def changed(image,va,n):
            raw=original(image,va,n)
            if va==study.FUNCTIONS['stake_insert']:
                return bytes([raw[0]^1])+raw[1:]
            return raw
        with patch.object(study,'at',side_effect=changed):
            with self.assertRaisesRegex(study.EvidenceError,'function bytes mismatch'):
                study.validate(self.image)

    def test_bad_instruction_witness_is_rejected(self):
        original=study.at
        def changed(image,va,n):
            raw=original(image,va,n)
            if va==0x3995703: return bytes([raw[0]^1])+raw[1:]
            return raw
        with patch.object(study,'at',side_effect=changed):
            with self.assertRaisesRegex(study.EvidenceError,'witness mismatch'):
                study.validate(self.image)

    def test_relocations_bind_memory_operations(self):
        records=study.relocation_records(self.image)
        self.assertEqual(records[study.SLOT_MEMMOVE][3], 'memmove')
        self.assertEqual(records[0x576e488][3], 'memcmp')

    def test_wrong_call_target_rejected(self):
        with self.assertRaisesRegex(study.EvidenceError,'direct call mismatch'):
            study.checked_call(self.image,0x3995707,0x33bede1)

    def test_all_leaf_gaps(self):
        for length in range(12):
            for slot in range(length+1):
                with self.subTest(length=length,slot=slot):
                    r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(),(),length,slot)
                    self.assertEqual(r['keys'],length+1)
                    self.assertEqual(r['depth'],int(length==11))

    def test_full_leaf_pivot_all_positions(self):
        for gap in range(12):
            r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(),(),11,gap)
            self.assertEqual(r['pivot'],4 if gap<5 else 5 if gap<=6 else 6)
            self.assertEqual(sum((r['left_count'],r['right_count'])),11)

    def test_parent_split_both_sides(self):
        for edge in (0,4,5,6,7,11):
            r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(11,),(edge,),11,6)
            self.assertEqual(r['depth'],2)
            self.assertEqual(r['allocations'],[0x198,0x1f8,0x1f8])

    def test_cascading_split(self):
        r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(11,11),(5,6),11,4)
        self.assertEqual(r['depth'],3)
        self.assertEqual(r['allocations'],[0x198,0x1f8,0x1f8,0x1f8])

    def test_adapter_initializes_empty_map(self):
        r=study.adapter_case(self.image,0,0,True,value_override=0)
        self.assertEqual(r['allocated'],[0x198])
        self.assertEqual(r['height'],0)

    def test_adapter_preserves_both_words(self):
        for value in (0,1,1<<64,(1<<128)-1):
            for n,gap in ((5,0),(5,3),(11,6),(11,11)):
                with self.subTest(value=value,n=n,gap=gap):
                    study.adapter_case(self.image,n,gap,value_override=value)

    def test_adapter_calls_split_through_multiple_levels(self):
        for counts,edges in (((1,),(0,)),((11,),(5,)),((11,11),(6,5))):
            r=study.adapter_case(self.image,11,6,value_override=0,counts=counts,edges=edges)
            self.assertEqual(r['height'],len(edges)+int(all(n==11 for n in counts)))

    def test_adapter_jump_outside_fdes_is_rejected(self):
        start=study.FUNCTIONS['stake_entry']
        end=self.image.exact_fde(start)[1]
        encoded=b'\xe9'+struct.pack('<i',end+16-(start+5))
        patches={start+i:byte for i,byte in enumerate(encoded)}
        with self.assertRaisesRegex(study.Halt,'control left selected FDEs'):
            study.adapter_case(self.image,0,0,True,patches=patches)

    def test_invalid_adapter_fixture_rejected(self):
        with self.assertRaises(ValueError):
            study.adapter_case(self.image,1,0,empty=True)

    def test_targeted_mutations_detected(self):
        rows=study.mutation_results(self.image)
        self.assertEqual([r[0] for r in rows],['capacity','pivot','full_branch','key_tail','second_word_offset','map_count_offset'])

    def test_first_node_allocation_failure(self):
        result=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(),(),11,5,
                              fail_alloc_at=1,expect_panic=True)
        self.assertIn('failure sink',result['panic'])
        self.assertEqual(result['allocations'],[0x198])

    def test_cascade_allocation_failure(self):
        result=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(11,),(6,),11,5,
                              fail_alloc_at=3,expect_panic=True)
        self.assertEqual(result['allocations'],[0x198,0x1f8,0x1f8])

    def test_empty_entry_allocation_failure(self):
        with self.assertRaises(study.Panicked):
            study.adapter_case(self.image,0,0,True,fail_alloc_at=1,value_override=0)

    def test_malformed_count_reaches_failure(self):
        r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(),(),11,5,
                         corrupt_leaf_count=22,expect_panic=True)
        self.assertIn('failure sink',r['panic'])

    def test_null_root_reaches_failure(self):
        r=study.evaluate(self.image,study.FUNCTIONS['stake_insert'],(),(),11,5,
                         null_root=True,expect_panic=True)
        self.assertIn('failure sink',r['panic'])


if __name__=='__main__':
    unittest.main()
