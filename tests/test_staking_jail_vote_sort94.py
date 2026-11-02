"""Negative and boundary controls for the jail-vote static evidence."""
import copy
import hashlib
import struct
import unittest

from tools import staking_jail_vote_sort94 as subject


class JailVoteStaticEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=subject.load_image()
        subject.validate_image(cls.image)

    def test_digest_failure_is_not_skipped(self):
        with self.assertRaisesRegex(subject.EvidenceError,'SHA-256'):
            subject.load_image(expected='0'*64)

    def test_fde_extents_and_window_hashes(self):
        self.assertEqual(len(subject.SIZES),8)
        for start,n in subject.SIZES.items():
            self.assertEqual(self.image.exact_fde(start),(start,start+n))
            self.assertEqual(hashlib.sha256(subject.bytes_at(self.image,start,n,True)).hexdigest(),subject.HASHES[start])
            rows=subject.decode_range(self.image,start,start+n)
            self.assertEqual((rows[0].va,rows[-1].next),(start,start+n))

    def test_changed_fde_is_rejected(self):
        image=copy.copy(self.image)
        image.fde_ends=dict(self.image.fde_ends)
        image.fde_ends[0x33e7840]-=1
        with self.assertRaisesRegex(subject.EvidenceError,'FDE'): subject.validate_image(image)

    def test_body_corruption_is_rejected(self):
        image=copy.copy(self.image)
        blob=bytearray(self.image.blob)
        blob[image.offset(0x33e792a)]^=1
        image.blob=blob
        with self.assertRaisesRegex(subject.EvidenceError,'body mismatch'):subject.validate_image(image)

    def test_diagnostic_corruption_is_rejected(self):
        image=copy.copy(self.image)
        blob=bytearray(self.image.blob)
        blob[image.offset(0x57ada0)]^=1
        image.blob=blob
        with self.assertRaisesRegex(subject.EvidenceError,'diagnostic'):subject.validate_image(image)

    def test_relocation_corruption_and_duplicates_rejected(self):
        image=copy.copy(self.image)
        blob=bytearray(self.image.blob)
        rel=image.named['.rela.dyn']
        offsets={}
        for off in range(rel['offset'],rel['offset']+rel['size'],24):
            slot=struct.unpack_from('<Q',blob,off)[0]
            if slot in (0x5776250,0x5775fd0):offsets[slot]=off
        struct.pack_into('<q',blob,offsets[0x5776250]+16,0)
        image.blob=blob
        with self.assertRaisesRegex(subject.EvidenceError,'relocation'):subject.relocation_records(image)
        struct.pack_into('<q',blob,offsets[0x5776250]+16,0x3bc24a0)
        struct.pack_into('<Q',blob,offsets[0x5775fd0],0x5776250)
        with self.assertRaisesRegex(subject.EvidenceError,'duplicate'):subject.relocation_records(image)

    def test_nobits_outside_and_bad_call_are_rejected(self):
        bss=next(s for s in self.image.sections if s['name']=='.bss')
        self.assertEqual(bss['type'],8)
        for va in (0,bss['address'],0xffffffffffffffff):
            with self.assertRaises(subject.EvidenceError):subject.bytes_at(self.image,va,1)
        with self.assertRaises(subject.EvidenceError):subject.call_target(self.image,0x3993f26)

    def test_static_call_chain_and_slot(self):
        self.assertEqual(subject.call_target(self.image,0x3993f25),0x33e7840)
        self.assertEqual(subject.call_target(self.image,0x33e799d),0x2f0a230)
        self.assertEqual(subject.call_target(self.image,0x3bc256b),0x38711a0)
        self.assertEqual(subject.relocation_records(self.image)[0x5776250],(8,0x3bc24a0,0))

    def test_row_range_controls(self):
        for fields in ((1<<31,0,0,0,0),(0,1<<32,0,0,0),(0,0,0,1<<64,0),(0,0,0,0,-1)):
            with self.assertRaises(ValueError):subject.make_row(*fields)
        with self.assertRaises(ValueError):subject.evaluate_sort(self.image,[bytes(24)]*20)
        with self.assertRaises(ValueError):subject.evaluate_sort(self.image,[bytes(23)]*21)

    def test_comparator_field_order_and_signed_date(self):
        rows=[subject.make_row(-1,2,3,5,0),subject.make_row(-1,2,3,4,1),
              subject.make_row(-1,2,2,99,2),subject.make_row(-1,1,99,99,3),
              subject.make_row(-2,0xffffffff,0xffffffff,0xffffffffffffffff,4),
              subject.make_row(1,0,0,0,5)]*4
        runner,actual=subject.evaluate_sort(self.image,rows)
        self.assertEqual(actual,sorted(rows,key=subject.order))
        self.assertEqual(runner.allocations,[])

    def test_equal_rows_are_stable_in_tested_fixture(self):
        rows=[subject.make_row(1,2,3,4,i) for i in reversed(range(65))]
        _,actual=subject.evaluate_sort(self.image,rows)
        self.assertEqual(actual,rows)

    def test_stack_and_heap_boundary(self):
        for n,alloc in ((169,[]),(170,[]),(171,[4104]),(172,[4128])):
            rows=[subject.make_row((i*7)%5,i%3,i%11,i%13,i) for i in range(n)]
            runner,_=subject.evaluate_sort(self.image,rows)
            self.assertEqual(runner.allocations,alloc)
            self.assertEqual(runner.frees,alloc)

    def test_large_allocation_and_overflow_guards(self):
        for n,alloc in ((333333,[7999992]),(666666,[7999992]),(666667,[8000016]),((1<<64)-1,[])):
            r=subject.capacity_probe(self.image,n)
            self.assertEqual(r.allocations,alloc)
            self.assertEqual(r.failure[0],0x3bc25b1 if alloc else 0x3bc2523)
        with self.assertRaises(ValueError):subject.capacity_probe(self.image,1<<64)

    def test_small_partition_capacity(self):
        for n in (0,1):
            self.assertEqual(subject.small_probe(self.image,n,0)[1],'sorted')
        for n in (2,5,32):
            self.assertEqual(subject.small_probe(self.image,n,n+15)[1],'trap')
            self.assertEqual(subject.small_probe(self.image,n,n+16)[1],'sorted')
        with self.assertRaises(ValueError):subject.small_probe(self.image,33,64)

    def test_empty_novoter_clones_keep_height(self):
        for h in range(6):
            r,status=subject.clone_probe(self.image,height=h)
            self.assertEqual(status,'empty')
            self.assertEqual(r.allocations,[0x90]+[0xf0]*h)

    def test_nonempty_novoter_clone_hits_exact_diagnostic(self):
        for h in range(4):
            for level in range(h+1):
                r,status=subject.clone_probe(self.image,height=h,nonempty_level=level)
                self.assertEqual(status,'no_voter')
                self.assertEqual(r.failure,(0x2f0a23d,subject.DIAGNOSTIC.decode('ascii')))

    def test_clone_allocation_failure_boundaries(self):
        for height,fail,site in ((0,1,0x33e797f),(1,1,0x33e797f),(1,2,0x33e795e)):
            r,status=subject.clone_probe(self.image,height=height,fail_at=fail)
            self.assertEqual(status,'failure')
            self.assertEqual(r.failure[0],site)
        with self.assertRaises(ValueError):subject.clone_probe(self.image,height=1,nonempty_level=2)

    def test_mutated_control_flow_is_detected(self):
        rows=[subject.make_row((i*7)%19-9,(i*17)%23,(i*13)%11,(i*5)%17,i) for i in range(65)][::-1]
        with self.assertRaises(subject.Halt):subject.evaluate_sort(self.image,rows,patches={0x3bc24f5:0x72})
        with self.assertRaisesRegex(subject.Halt,'sorted result'):subject.evaluate_sort(self.image,rows,patches={0x338417e:0x92})
        with self.assertRaises(subject.Panicked):subject.clone_probe(self.image,height=0,patches={0x33e792a:0x74})


if __name__=='__main__':
    unittest.main()
