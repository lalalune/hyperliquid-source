import hashlib
from pathlib import Path
import unittest

from tools import receipt_blob_quantities94 as p


class ReceiptBlobQuantitiesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = p.Image(p.BINARY.read_bytes())
        cls.constants = p.validate(cls.image)
        cls.denominator = cls.constants['denominator']

    def test_digest_and_fde_extents(self):
        self.assertEqual(p.digest(self.image.blob), p.SHA)
        self.assertEqual(self.image.fde(0x26b79b0)['end'], 0x26b7e66)
        self.assertEqual(self.image.fde(0x4e5b5b0)['end'], 0x4e5c144)

    def test_wrong_artifact_digest_fails(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.Image(self.image.blob, '0' * 64)

    def test_file_backing_rejects_nobits_and_bad_address(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read(0, 1, True)
        with self.assertRaises(ValueError):
            self.image.offset(-1, 1)

    def test_corrupt_immediate_with_recomputed_hash_fails_window(self):
        blob = bytearray(self.image.blob)
        off = self.image.offset(0x4e5b757, 1, True)
        blob[off] ^= 1
        altered = p.Image(bytes(blob), hashlib.sha256(blob).hexdigest())
        body = altered.read(0x4e5b5b0, 0x4e5c144 - 0x4e5b5b0, True)
        pinned = dict(p.BODIES)
        pinned[0x4e5b5b0] = (0x4e5c144, p.digest(body))
        with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
            p.validate(altered, pinned)

    def test_branch_mutation_with_recomputed_hash_fails_window(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x4e5b73c, 1, True)] ^= 1
        altered = p.Image(bytes(blob), hashlib.sha256(blob).hexdigest())
        body = altered.read(0x4e5b5b0, 0x4e5c144 - 0x4e5b5b0, True)
        pinned = dict(p.BODIES)
        pinned[0x4e5b5b0] = (0x4e5c144, p.digest(body))
        with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
            p.validate(altered, pinned)

    def test_mutated_tag_constant_with_recomputed_artifact_hash(self):
        blob=bytearray(self.image.blob)
        blob[self.image.offset(0x2080f0,1)] ^= 1
        altered=p.Image(bytes(blob),hashlib.sha256(blob).hexdigest())
        with self.assertRaisesRegex(ValueError,'tag constant mismatch'):
            p.validate(altered)

    def test_missing_and_duplicate_fde_fail_closed(self):
        original = self.image.fdes
        try:
            selected = self.image.fde(0x26b79b0)
            self.image.fdes = original + [selected]
            with self.assertRaisesRegex(ValueError, 'duplicate FDE'):
                self.image.fde(0x26b79b0)
            self.image.fdes = [row for row in original if row['start'] != 0x26b79b0]
            with self.assertRaisesRegex(ValueError, 'missing or duplicate FDE'):
                self.image.fde(0x26b79b0)
        finally:
            self.image.fdes = original

    def test_wrong_call_or_missing_relocation_is_rejected(self):
        self.assertEqual(self.image.call_target(0x26b7b22), (0x5774700, 0x4e5b5b0))
        with self.assertRaisesRegex(ValueError, 'call encoding'):
            self.image.call_target(0x26b79c4)
        old = self.image.rel.pop(0x5774700)
        try:
            with self.assertRaisesRegex(ValueError, 'relocation'):
                self.image.call_target(0x26b7b22)
        finally:
            self.image.rel[0x5774700] = old

    def test_branch_targets_and_nonbranch(self):
        self.assertEqual(self.image.branch(0x4e5b73b)[0], 0x4e5b863)
        self.assertEqual(self.image.branch(0x4e5b7fd)[0], 0x4e5b760)
        with self.assertRaisesRegex(ValueError, 'branch encoding'):
            self.image.branch(0x4e5b716)

    def test_constants_and_blob_bound(self):
        self.assertEqual((self.denominator, self.constants['gas_shift'], self.constants['overflow_shift']), (3338477, 17, 47))
        self.assertEqual(self.constants['denominator_immediates'], [3338477]*3)
        kwargs = dict(valid=1,blob=1,excess_present=0,excess=0,index=0,current=1,previous=[],denom=self.denominator,shift=17)
        max_count = (1 << 47) - 1
        self.assertEqual(p.receipt_case(count=max_count, **kwargs)['gas'], max_count << 17)
        self.assertEqual(p.receipt_case(count=max_count+1, **kwargs)['status'], 'blob_count_overflow')
        self.assertEqual(p.receipt_case(count=p.MASK, **{**kwargs,'blob':0})['gas_present'], 0)

    def test_optional_price_and_zero(self):
        kwargs = dict(valid=1,blob=1,count=1,excess=0,index=0,current=0,previous=[],denom=self.denominator,shift=17)
        missing = p.receipt_case(excess_present=0,**kwargs)
        present = p.receipt_case(excess_present=1,**kwargs)
        self.assertEqual((missing['gas_present'],missing['price_present']), (1,0))
        self.assertEqual((present['gas'],present['price'],present['price_present']), (131072,1,1))

    def test_delta_underflow_precedes_blob_overflow(self):
        got=p.receipt_case(1,1,p.MASK,1,p.MASK,1,9,[10],self.denominator,17)
        self.assertEqual(got['status'], 'delta_underflow')
        got=p.receipt_case(0,1,p.MASK,1,p.MASK,1,9,[10],self.denominator,17)
        self.assertEqual(got['status'], 'receipt_rejected')

    def test_blob_tag_requires_all_128_bits(self):
        original=self.image.read(0x2080f0,16)
        self.assertTrue(p.matches_blob_tag(self.image,original))
        for bit in range(128):
            changed=bytearray(original)
            changed[bit//8] ^= 1 << (bit%8)
            self.assertFalse(p.matches_blob_tag(self.image,bytes(changed)))
        with self.assertRaises(ValueError):
            p.matches_blob_tag(self.image,original[:8])

    def test_receipt_tag_is_exact_and_excess_flag_is_nonzero(self):
        args = dict(blob=1,count=1,excess=0,index=0,current=0,previous=[],denom=self.denominator,shift=17)
        self.assertEqual(p.receipt_case(valid=2,excess_present=1,**args)['status'],'receipt_rejected')
        self.assertEqual(p.receipt_case(valid=255,excess_present=1,**args)['status'],'receipt_rejected')
        self.assertEqual(p.receipt_case(valid=1,excess_present=128,**args)['price'],1)
        with self.assertRaises(ValueError):
            p.receipt_case(valid=256,excess_present=1,**args)
        with self.assertRaises(ValueError):
            p.caller_gate(2,0,1,0)

    def test_receipt_gate_walk_matches_all_byte_controls(self):
        d = self.denominator
        for byte in range(256):
            with self.subTest(decoder=byte):
                args=(byte,1,1,1,0,0,0,[],d,17)
                self.assertEqual(p.walk_gate(self.image,*args),p.receipt_case(*args))
            with self.subTest(presence=byte):
                args=(1,1,1,byte,0,0,0,[],d,17)
                self.assertEqual(p.walk_gate(self.image,*args),p.receipt_case(*args))

    def test_gate_walk_detects_flipped_presence_branch(self):
        original=self.image.blob
        altered=bytearray(original)
        altered[self.image.offset(0x4e5b73c,1,True)] ^= 1
        try:
            self.image.blob=altered
            args=(1,1,1,0,0,0,0,[],self.denominator,17)
            self.assertNotEqual(p.walk_gate(self.image,*args),p.receipt_case(*args))
        finally:
            self.image.blob=original

    def test_previous_index_cases(self):
        args = dict(valid=1,blob=0,count=0,excess_present=0,excess=0,current=9,previous=[3],denom=self.denominator,shift=17)
        self.assertEqual(p.receipt_case(index=0,**args)['delta'],9)
        self.assertEqual(p.receipt_case(index=1,**args)['delta'],6)
        self.assertEqual(p.receipt_case(index=2,**args)['delta'],0)

    def test_series_known_boundaries(self):
        d=self.denominator
        self.assertEqual(p.run_series(0,d)['price'],1)
        self.assertEqual(p.run_series(d,d)['price'],2)
        edge=p.boundary(d)
        self.assertEqual(edge,192204552)
        self.assertEqual(p.run_series(edge,d), {'status':'ok','price':10079293834132079738693097,'iterations':168})
        self.assertEqual(p.run_series(edge+1,d)['status'],'product_overflow')

    def test_limb_lift_matches_wide_model(self):
        d=self.denominator
        edge=p.boundary(d)
        samples = [0,1,d-1,d,d+1,edge-1,edge,edge+1,p.MASK]
        samples += [i*edge//137 for i in range(138)]
        for x in samples:
            with self.subTest(x=x):
                self.assertEqual(p.run_series(x,d),p.specification(x,d))

    def test_real_byte_walk_agrees_at_and_around_failure(self):
        d = self.denominator
        edge = p.boundary(d)
        coverage = {}
        for x in (0, 1, d, edge-1, edge, edge+1, p.MASK):
            with self.subTest(x=x):
                self.assertEqual(p.execute_loop(self.image,x,d,coverage),p.specification(x,d))
        self.assertIn(0x4e5b760,coverage)
        self.assertIn(0x4e5b7e4,coverage)

    def test_byte_walk_rejects_unknown_instruction(self):
        original = self.image.blob
        altered = bytearray(original)
        altered[self.image.offset(0x4e5b760,1,True)] = 0
        try:
            self.image.blob = altered
            with self.assertRaisesRegex(ValueError,'unmodeled byte-walk instruction'):
                p.execute_loop(self.image,0,self.denominator)
        finally:
            self.image.blob = original

    def test_valid_opcode_mutation_changes_the_result(self):
        original = self.image.blob
        altered = bytearray(original)
        altered[self.image.offset(0x4e5b760,1,True)] ^= 1
        try:
            self.image.blob = altered
            self.assertNotEqual(p.execute_loop(self.image,0,self.denominator),p.specification(0,self.denominator))
        finally:
            self.image.blob = original

    def test_byte_walk_rejects_missing_division_relocation(self):
        old = self.image.rel.pop(0x576e1a8)
        try:
            with self.assertRaisesRegex(ValueError,'unexpected divide call'):
                p.execute_loop(self.image,0,self.denominator)
        finally:
            self.image.rel[0x576e1a8] = old

    def test_rounding_witness_has_exact_rational_bounds(self):
        d=self.denominator
        lower,upper=p.ideal_exp_bounds(100000000,d)
        lo=lower.numerator//lower.denominator
        hi=upper.numerator//upper.denominator
        self.assertEqual((lo,hi),(10203769478520,10203769478520))
        self.assertEqual(p.execute_loop(self.image,100000000,d)['price'],10203769476395)
        with self.assertRaises(ValueError):
            p.ideal_exp_bounds(p.MASK,d)
        with self.assertRaises(ValueError):
            p.ideal_exp_bounds(1,0)

    def test_limb_add_and_multiply_controls(self):
        self.assertEqual(p.add64(p.MASK,1), (0,1))
        self.assertEqual(p.add64(p.MASK,p.MASK,1), (p.MASK,1))
        self.assertEqual(p.mul64(p.MASK,p.MASK), (1,p.MASK-1))
        with self.assertRaises(ValueError):
            p.run_series(1<<64,self.denominator)
        with self.assertRaises(ValueError):
            p.run_series(1,0)

    def test_two_limb_price_packing(self):
        for q in (0,1,255,256,(1<<64)-1,1<<64,(1<<128)-1):
            low, high = q & p.MASK, q >> 64
            middle = ((high << 56) | (low >> 8)) & p.MASK
            upper = high >> 8
            result_low = ((middle << 8) & p.MASK) | (low & 255)
            result_high = ((upper << 8) | (middle >> 56)) & p.MASK
            self.assertEqual(result_low | (result_high << 64),q)

    def test_iterator_advancement_and_late_counter_failure(self):
        self.assertEqual(p.caller_gate(0,0,1,0),('first_empty',0,0))
        self.assertEqual(p.caller_gate(1,1,1,0),('first_sentinel',1,0))
        self.assertEqual(p.caller_gate(1,0,0,0),('second_empty',1,0))
        self.assertEqual(p.caller_gate(1,0,1,p.MASK),('counter_overflow_after_call',1,1))
        self.assertEqual(p.caller_gate(1,0,1,p.MASK-1),('call_and_increment',1,1))

    def test_inputs_outside_u64(self):
        with self.assertRaises(ValueError):
            p.caller_gate(1,0,1,-1)
        with self.assertRaises(ValueError):
            p.receipt_case(1,1,-1,0,0,0,0,[],self.denominator,17)

if __name__ == '__main__':
    unittest.main()
