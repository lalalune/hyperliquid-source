"""Controls for the node 94 vote-jail tracker insertion evaluator."""
import hashlib
import unittest

from tools import staking_vote_jail_insert94 as m


class VoteJailInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.load_image()

    def test_digest_and_fde_bodies(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), m.SHA256)
        m.validate_image(self.image)
        for role, (start,end,_) in m.WINDOWS.items():
            self.assertEqual(self.image.exact_fde(start), (start,end),role)

    def test_wrong_digest_fails(self):
        with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
            m.load_image(expected='0'*64)

    def test_corrupt_body_fails(self):
        original=self.image.blob
        off=self.image.offset(m.FUNCTIONS['outer'])
        try:
            self.image.blob=original[:off]+bytes((original[off]^1,))+original[off+1:]
            with self.assertRaisesRegex(m.EvidenceError,'unexpected function body'):
                m.validate_image(self.image)
        finally:
            self.image.blob=original

    def test_corrupt_call_fails(self):
        original=self.image.blob
        off=self.image.offset(m.CALLS[0][0])
        try:
            self.image.blob=original[:off]+b'\x90'+original[off+1:]
            with self.assertRaises(m.EvidenceError):
                m.validate_image(self.image)
        finally:
            self.image.blob=original

    def test_boundary_rejection(self):
        with self.assertRaises(m.EvidenceError):
            self.image.exact_fde(m.FUNCTIONS['outer']+1)
        with self.assertRaises(m.EvidenceError):
            m.at(self.image,0xffffffffffffffff,1)
        sec=m.unique_section(self.image,'.text')
        with self.assertRaises(m.EvidenceError):
            m.at(self.image,sec['address']+sec['size']-1,2)

    def test_all_windows_decode_to_fde_end(self):
        for start,end,_ in m.WINDOWS.values():
            rows=m.decode_range(self.image,start,end)
            self.assertEqual(rows[-1].next,end)
            starts={row.va for row in rows}
            for row in rows:
                if row.op in ('jmp','jcc'):
                    self.assertIn(row.target,starts)

    def test_actual_call_edges(self):
        for site,role in m.CALLS:
            self.assertEqual(m.call_target(self.image,site),m.FUNCTIONS[role])
        with self.assertRaisesRegex(m.EvidenceError,'not a direct'):
            m.call_target(self.image,m.FUNCTIONS['outer'])

    def test_allocator_and_copy_relocations(self):
        r=m.relocation_records(self.image)
        self.assertEqual(r[m.SLOT_MEMCPY][3],'memcpy')
        self.assertEqual(r[m.SLOT_MEMMOVE][3],'memmove')
        self.assertEqual(r[m.SLOT_ALLOC][0],8)

    def test_outer_all_leaf_positions(self):
        for n in range(12):
            for gap in range(n+1):
                with self.subTest(n=n,gap=gap):
                    r=m.evaluate(self.image,m.FUNCTIONS['outer'],(),(),n,gap)
                    self.assertEqual(r['keys'],n+1)
                    self.assertEqual(r['depth'],int(n==11))

    def test_outer_full_leaf_pivots(self):
        for gap in range(12):
            r=m.evaluate(self.image,m.FUNCTIONS['outer'],(),(),11,gap)
            self.assertEqual(r['pivot'],4 if gap<5 else 5 if gap<=6 else 6)
            self.assertEqual(r['left_count']+r['right_count'],11)
            self.assertEqual(r['allocations'],[0x248,0x2a8])

    def test_outer_parent_absorbs_split(self):
        r=m.evaluate(self.image,m.FUNCTIONS['outer'],(10,),(5,),11,7)
        self.assertEqual(r['depth'],1)
        self.assertEqual(r['allocations'],[0x248])

    def test_two_helpers_composed_on_one_heap(self):
        r=m.nested_helper_case(self.image,(),(),1,0)
        self.assertEqual((r['outer_count'],r['inner_count']),(2,1))
        r=m.nested_helper_case(self.image,(11,11,11),(0,5,11),11,6)
        self.assertEqual(r['outer_depth'],4)
        self.assertEqual(r['allocations'],[0x248,0x2a8,0x2a8,0x2a8,0x2a8])

    def test_inner_empty_and_synthetic_full_leaves(self):
        r=m.inner_case(self.image,0,0)
        self.assertEqual((r['count'],r['depth'],r['allocations']),(1,0,[]))
        for gap in range(12):
            r=m.inner_case(self.image,11,gap)
            self.assertEqual(r['count'],12)
            self.assertEqual(r['allocations'],[0x220,0x280])

    def test_inner_synthetic_parent_and_cascade(self):
        absorbed=m.inner_tree_case(self.image,(10,),(5,),7)
        self.assertEqual(absorbed['depth'],1)
        self.assertEqual(absorbed['allocations'],[0x220])
        propagated=m.inner_tree_case(self.image,(11,11,11),(0,5,11),6)
        self.assertEqual(propagated['depth'],4)
        self.assertEqual(propagated['allocations'],[0x220,0x280,0x280,0x280,0x280])
        with self.assertRaises(ValueError):
            m.inner_tree_case(self.image,(1,),(2,),0)

    def test_allocator_failure_for_each_helper(self):
        for fail in (1,2):
            for role in ('outer','inner'):
                with self.subTest(role=role,fail=fail):
                    r=(m.evaluate(self.image,m.FUNCTIONS['outer'],(),(),11,5,
                                  fail_alloc_at=fail,expect_panic=True)
                       if role=='outer' else m.inner_case(self.image,11,5,fail_alloc_at=fail))
                    self.assertIn('failure sink reached',r['panic'])
                    self.assertEqual(len(r['allocations']),fail)

    def test_corrupt_cursor_tree_metadata(self):
        for kw,counts,edges in (({'corrupt_leaf_count':22},(),()),({'null_root':True},(),()),
                                ({'root_height_override':m.MASK[8]},(),()),
                                ({'root_height_override':1},(),()),
                                ({'corrupt_parent_count':22},(11,),(0,))):
            with self.subTest(corruption=kw):
                result=m.evaluate(self.image,m.FUNCTIONS['outer'],counts,edges,11,5,
                                  expect_panic=True,**kw)
                self.assertIn('failure sink reached',result['panic'])

    def test_corrupt_inner_tree_metadata(self):
        for kw in ({'corrupt_count':22},{'null_root':True},
                   {'height_override':m.MASK[8]},{'height_override':1}):
            with self.subTest(corruption=kw):
                result=m.inner_case(self.image,11,5,expect_panic=True,**kw)
                self.assertIn('failure sink reached',result['panic'])
        result=m.inner_tree_case(self.image,(11,),(0,),5,corrupt_parent_count=22,expect_panic=True)
        self.assertIn('failure sink reached',result['panic'])

    def test_wrong_branch_is_detected_by_independent_model(self):
        self.assertEqual(m.at(self.image,0x2f3d600,1),b'\x72')
        with self.assertRaises((m.Halt,m.Panicked,m.EvidenceError)):
            m.evaluate(self.image,m.FUNCTIONS['outer'],(),(),3,1,patches={0x2f3d600:0x73})
        self.assertEqual(m.at(self.image,0x2f9cc72,1),b'\x72')
        with self.assertRaises((m.Halt,m.Panicked,m.EvidenceError)):
            m.inner_case(self.image,3,1,patches={0x2f9cc72:0x73})

    def test_unsorted_tree_control(self):
        f=m.Fixture(self.image,layout=m.LAYOUT_OUTER)
        root,_=f.build((),(),2,1)
        f.put(root+f.layout['key'],b'\xff'*20)
        with self.assertRaisesRegex(m.Halt,'key order'):
            f.inspect(root,0)

    def test_bad_cursor_rejected_by_fixture(self):
        with self.assertRaises(ValueError):
            m.evaluate(self.image,m.FUNCTIONS['outer'],(),(),1,2)
        with self.assertRaises(ValueError):
            m.inner_case(self.image,1,2)

    def test_overlap_copy_control(self):
        f=m.Fixture(self.image,layout=m.LAYOUT_OUTER)
        f.machine.regs[m.RDI]=m.ARENA
        f.machine.regs[m.RSI]=m.ARENA+1
        f.machine.regs[m.RDX]=8
        with self.assertRaisesRegex(m.Halt,'overlapping memcpy'):
            f.on_memcpy(f.machine)
        f.on_copy(f.machine)


if __name__ == '__main__':
    unittest.main()
