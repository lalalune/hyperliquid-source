import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import order_pair_rank94 as m


class OrderPairRankTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=m.BINARY.read_bytes()
        cls.secs=m.sections(cls.data)
        cls.cap=(1<<63)-2

    def row(self,price=1,size=1,side=0,asset=1):
        return m.record(price,asset,size,0x1234,side,b'abcdefg')

    def test_authenticate_binary(self):
        m.authenticate(self.data)

    def test_corrupt_digest_rejected(self):
        with patch.object(m,'DIGEST','0'*64),self.assertRaisesRegex(ValueError,'SHA-256'):
            m.authenticate(self.data)

    def test_corrupt_function_rejected_even_with_rebound_digest(self):
        bad=bytearray(self.data)
        off=m.resolve(self.data,self.secs,0x4dbabb0,1)
        bad[off]^=1
        with patch.object(m,'DIGEST',hashlib.sha256(bad).hexdigest()):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError,'body hash'):
                    m.generate(bad,Path(directory))

    def test_rank_anchor_rejects_changed_size_comparison(self):
        start=0x4dba8f0;end=m.FNS[start][0]
        off=m.resolve(self.data,self.secs,start,end-start)
        body=bytearray(self.data[off:off+end-start])
        m.validate_rank_anchors(body)
        body[0x4dbabb0-start+11]^=1
        with self.assertRaisesRegex(ValueError,'rank instruction'):
            m.validate_rank_anchors(body)

    def test_backing_and_invalid_addresses(self):
        self.assertGreater(m.resolve(self.data,self.secs,0x4dba8f0,1),0)
        with self.assertRaises(ValueError):m.resolve(self.data,self.secs,m.U64,1)
        with self.assertRaises(ValueError):m.resolve(self.data,self.secs,0x4dba8f0,0)
        bss=next(x for x in self.secs if x['name']=='.bss' and x['type']==8)
        with self.assertRaises(ValueError):m.resolve(self.data,self.secs,bss['address'],1)

    def test_branch_mutation_rejected(self):
        bad=bytearray(self.data)
        off=m.resolve(self.data,self.secs,0x4dbad0e,1)
        bad[off]=0x90
        with self.assertRaisesRegex(ValueError,'branch opcode'):
            m.decode_branch(bad,self.secs,0x4dbad0e)

    def test_branch_displacement_changes_destination(self):
        bad=bytearray(self.data)
        off=m.resolve(self.data,self.secs,0x4dbb040,2)
        original=m.decode_branch(self.data,self.secs,0x4dbb040)[0]
        bad[off+1]^=1
        self.assertNotEqual(original,m.decode_branch(bad,self.secs,0x4dbb040)[0])

    def test_minimum_signed_position_magnitude(self):
        row=self.row(size=1<<63,side=0)
        self.assertEqual(m.lower_instructions(row,m.I64_MIN,self.cap)[0],1)
        row=self.row(size=(1<<63)+1,side=0)
        self.assertEqual(m.lower_instructions(row,m.I64_MIN,self.cap)[0],0)

    def test_zero_position_and_zero_size(self):
        self.assertEqual(m.lower_instructions(self.row(size=0,side=0),0,self.cap)[0],1)
        self.assertEqual(m.lower_instructions(self.row(size=0,side=1),0,self.cap)[0],0)
        self.assertEqual(m.lower_instructions(self.row(size=1,side=0),0,self.cap)[0],0)

    def test_boolean_side_zero_versus_any_nonzero(self):
        for side in (1,2,127,255):
            with self.subTest(side=side):
                self.assertEqual(m.lower_instructions(self.row(side=side),1,self.cap)[0],1)
        self.assertEqual(m.lower_instructions(self.row(side=0),1,self.cap)[0],0)

    def test_position_size_boundary(self):
        self.assertEqual(m.lower_instructions(self.row(size=2,side=0),-2,self.cap)[0],1)
        self.assertEqual(m.lower_instructions(self.row(size=3,side=0),-2,self.cap)[0],0)

    def test_product_limit_inclusive(self):
        self.assertEqual(m.lower_instructions(self.row(price=self.cap,size=1),0,self.cap)[1],0)
        self.assertEqual(m.lower_instructions(self.row(price=self.cap+1,size=1),0,self.cap)[1],1)

    def test_product_high_half_makes_invalid(self):
        eligibility,invalid,low,high=m.lower_instructions(self.row(price=m.U64,size=2),0,self.cap)
        self.assertEqual((invalid,low,high),(1,m.U64-1,1))

    def test_eligibility_is_primary_key(self):
        noneligible=self.row(price=999,size=1,side=0,asset=1)
        eligible=self.row(price=1,size=1,side=1,asset=2)
        self.assertFalse(m.decision_lift(noneligible,1,eligible,1,self.cap))
        self.assertTrue(m.decision_lift(eligible,1,noneligible,1,self.cap))

    def test_invalid_product_precedes_valid_on_equal_priority(self):
        a=self.row(price=self.cap+1,side=0,asset=1)
        b=self.row(price=1,side=0,asset=2)
        self.assertFalse(m.decision_lift(a,0,b,0,self.cap))
        self.assertTrue(m.decision_lift(b,0,a,0,self.cap))

    def test_equal_priority_valid_products_are_ascending(self):
        low=self.row(price=1,side=0,asset=1)
        high=self.row(price=2,side=0,asset=2)
        self.assertFalse(m.decision_lift(low,0,high,0,self.cap))
        self.assertTrue(m.decision_lift(high,0,low,0,self.cap))
        self.assertFalse(m.decision_lift(low,0,low,0,self.cap))

    def test_all_fixture_pairs_agree_with_independent_key(self):
        items=m.fixtures(self.cap)
        for _,a,apos in items:
            for _,b,bpos in items:
                self.assertEqual(m.decision_lift(a,apos,b,bpos,self.cap),
                                 m.independent_decision(a,apos,b,bpos,self.cap))

    def test_bad_row_or_position_rejected(self):
        with self.assertRaises(ValueError):m.fields(b'\0'*39,0)
        with self.assertRaises(ValueError):m.fields(self.row(),m.I64_MIN-1)
        with self.assertRaises(ValueError):m.record(0,0,m.U64+1,0,0)

    def test_bounded_length_paths(self):
        self.assertEqual(m.bounded_length_case(0),'worker-returns-before-comparison')
        self.assertEqual(m.bounded_length_case(1),'worker-returns-before-comparison')
        self.assertEqual(m.bounded_length_case(2),'two-row-comparison')
        self.assertEqual(m.bounded_length_case(3),'outside-bounded-scope')
        with self.assertRaises(ValueError):m.bounded_length_case(-1)

    def test_all_flag_classes_match_independent_order(self):
        for e0 in (0,1):
            for e1 in (0,1):
                for bad0 in (0,1):
                    for bad1 in (0,1):
                        for low0 in (0,1,2):
                            for low1 in (0,1,2):
                                actual=m.flag_decision(e0,e1,bad0,bad1,low0,low1)
                                key0=(e0,1-bad0,0 if bad0 else low0)
                                key1=(e1,1-bad1,0 if bad1 else low1)
                                self.assertEqual(actual,key0>key1)
        with self.assertRaises(ValueError):m.flag_decision(2,0,0,0,0,0)

    def test_five_word_swap_preserves_all_row_bytes(self):
        start=0x4dba8f0;end=m.FNS[start][0]
        off=m.resolve(self.data,self.secs,start,end-start)
        body=bytearray(self.data[off:off+end-start])
        a=self.row(price=1,size=2,side=7,asset=11)
        b=self.row(price=3,size=4,side=9,asset=12)
        self.assertEqual(m.replay_pair_swap(body,a,b,True),b+a)
        self.assertEqual(m.replay_pair_swap(body,a,b,False),a+b)
        body[0x4dbb3e0-start]^=1
        with self.assertRaisesRegex(ValueError,'rank instruction'):
            m.replay_pair_swap(body,a,b,True)

    def test_tree_search_hits_misses_and_descends(self):
        cases=m.lookup_fixtures()
        answers={(name,key):m.tree_lookup(node,height,key)
                 for name,node,height,key in cases}
        self.assertEqual(answers['empty',0],(False,0,'empty-root'))
        self.assertEqual(answers['leaf',10],(True,-9,'0'))
        self.assertEqual(answers['leaf',15],(False,0,'1'))
        self.assertEqual(answers['branch',20],(True,-2,'0'))
        self.assertEqual(answers['branch',30],(True,3,'1/0'))
        self.assertEqual(answers['branch',45],(False,0,'2/0'))
        self.assertEqual(answers['branch',55],(False,0,'2/1'))

    def test_tree_search_rejects_invalid_fixture_and_opcode(self):
        with self.assertRaises(ValueError):m.tree_lookup(([2,1],[0,0],[]),0,1)
        with self.assertRaises(ValueError):m.tree_lookup(([2],[0],[]),1,1)
        with self.assertRaises(ValueError):m.tree_lookup(None,0,m.U64+1)
        start=0x4dba8f0;end=m.FNS[start][0]
        off=m.resolve(self.data,self.secs,start,end-start)
        body=bytearray(self.data[off:off+end-start])
        body[0x4dbab30-start]^=1
        with self.assertRaisesRegex(ValueError,'rank instruction'):
            m.validate_rank_anchors(body)

    def test_wrong_cap_changes_boundary_decision(self):
        high=self.row(price=self.cap,size=1,asset=1)
        low=self.row(price=1,size=1,asset=2)
        original=m.decision_lift(high,0,low,0,self.cap)
        changed=m.decision_lift(high,0,low,0,self.cap-1)
        self.assertNotEqual(original,changed)


if __name__=='__main__':unittest.main()
