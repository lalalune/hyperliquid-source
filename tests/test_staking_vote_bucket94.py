"""Target-bound controls for validator vote bucket insertion and cleanup."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from tools import staking_vote_bucket94 as e


class VoteBucketEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=e.load_image()
        e.validate_image(cls.image)

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(),e.SHA256)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(e.EvidenceError,'SHA-256 mismatch'):
            e.load_image(expected='0'*64)

    def test_body_corruption_rejected(self):
        damaged=copy.copy(self.image);damaged.blob=bytearray(self.image.blob)
        damaged.blob[damaged.offset(e.FUNCTIONS['inner'])]^=1
        with self.assertRaisesRegex(e.EvidenceError,'body hash mismatch'):e.validate_image(damaged)

    def test_non_start_fde_rejected(self):
        with self.assertRaises(e.EvidenceError):self.image.exact_fde(e.FUNCTIONS['inner']+1)

    def test_unmapped_and_nobits_rejected(self):
        with self.assertRaises(e.EvidenceError):e.at(self.image,0xffffffffffffffff,1)
        bss=next(s for s in self.image.sections if s['name']=='.bss')
        self.assertEqual(bss['type'],8)
        with self.assertRaises(e.EvidenceError):self.image.offset(bss['address'])

    def test_cross_section_range_rejected(self):
        text=next(s for s in self.image.sections if s['name']=='.text')
        with self.assertRaises(e.EvidenceError):e.at(self.image,text['address']+text['size']-1,2)

    def test_context_call_target(self):
        self.assertEqual(e.call_target(self.image,0x33c02b2),e.FUNCTIONS['inner'])
        with self.assertRaises(e.EvidenceError):e.call_target(self.image,0x33c02b3)

    def test_relocations(self):
        slot=e.unwind_slot(self.image);r=e.relocation_records(self.image,[slot,e.SLOT_MEMMOVE])
        self.assertEqual(r[slot][4],'_Unwind_Resume');self.assertEqual(r[e.SLOT_MEMMOVE][4],'memmove')
        with self.assertRaises(e.EvidenceError):e.relocation_records(self.image,[slot+1])

    def test_lsda_cleanup_landings(self):
        rows=e.lsda_records(self.image,'pair_drop')
        row=next(r for r in rows if r[2]<=0x3376ce7<r[3])
        self.assertEqual((row[4],row[5]),(0x3376cff,0))
        row=next(r for r in rows if r[2]<=0x3376d09<r[3])
        self.assertEqual((row[4],row[5]),(0x3376d16,1))

    def test_invalid_lsda_header_rejected(self):
        damaged=copy.copy(self.image);damaged.blob=bytearray(self.image.blob)
        p=damaged.offset(damaged.fde_records[e.FUNCTIONS['inner']]['lsda']);damaged.blob[p]=0
        with self.assertRaisesRegex(e.EvidenceError,'landing base'):e.lsda_records(damaged,'inner')

    def test_empty_and_ordinary_leaf(self):
        self.assertEqual(e.inner_case(self.image,0,0)['allocations'],[])
        self.assertEqual(e.inner_case(self.image,10,5)['count'],11)

    def test_split_pivot_boundaries(self):
        expected={0:(4,5,6),4:(4,5,6),5:(5,6,5),6:(5,5,6),7:(6,6,5),11:(6,6,5)}
        for gap,triplet in expected.items():
            with self.subTest(gap=gap):
                r=e.inner_case(self.image,11,gap)
                self.assertEqual((r['pivot'],r['left_count'],r['right_count']),triplet)

    def test_propagation_into_full_parent(self):
        r=e.inner_tree_case(self.image,[11],[11],11)
        self.assertEqual((r['depth'],r['allocations']),(2,[0x220,0x280,0x280]))
        r=e.inner_tree_case(self.image,[11,11],[5,11],6)
        self.assertEqual((r['depth'],r['allocations']),(3,[0x220,0x280,0x280,0x280]))

    def test_invalid_gaps_rejected(self):
        with self.assertRaises(ValueError):e.inner_case(self.image,3,4)
        with self.assertRaises(ValueError):e.inner_case(self.image,3,-1)

    def test_allocation_failures_and_corrupt_descriptor(self):
        for kw,address in (({'fail_alloc_at':1},'0x2f527fa'),({'fail_alloc_at':2},'0x2f52823'),
                           ({'null_root':True,'expect_panic':True},'0x2f52811'),
                           ({'height_override':(1<<64)-1,'expect_panic':True},'0x2f52832')):
            self.assertIn(address,e.inner_case(self.image,11,0,**kw)['panic'])

    def test_insertion_then_projected_cleanup(self):
        for n,g in ((0,0),(5,3),(11,0),(11,6),(11,11)):
            with self.subTest(n=n,gap=g):
                r=e.chain_case(self.image,n,g)
                self.assertEqual(r['calls'],2);self.assertEqual(r['height'],int(n==11))

    def test_pair_cleanup_order(self):
        for role in ('pair_drop','pair_drop_copy','promoted_drop'):
            r=e.drop_case(self.image,role)
            self.assertEqual((r['calls'],r['offsets']),(2,'0,24'))

    def test_option_tag_controls_cleanup(self):
        self.assertEqual(e.drop_case(self.image,'option_pair_drop',flag=0)['calls'],0)
        for flag in (1,2,255):self.assertEqual(e.drop_case(self.image,'option_pair_drop',flag=flag)['offsets'],'8,32')

    def test_remaining_iterator_is_stubbed(self):
        r=e.remaining_case(self.image,5)
        self.assertEqual((r['rows'],r['fetches'],r['calls']),(5,6,10))

    def test_landing_projection(self):
        for role in ('inner','pair_drop','pair_drop_copy','promoted_drop','option_pair_drop','remaining_drop'):
            with self.subTest(role=role):self.assertEqual(e.landing_case(self.image,role)['calls'],2 if role=='inner' else 1)

    def test_bounded_scan_limits_and_unreachable_shapes(self):
        self.assertEqual(e.scan_case(self.image,0,0,100)['length'],0)
        self.assertEqual(e.scan_case(self.image,1,0,100)['length'],1)
        for extra,total in ((0,99),(1,100),(2,101)):
            with self.subTest(rows=total):
                r=e.scan_case(self.image,9,1,100,extra=extra)
                self.assertEqual((r['rows'],r['capacity'],r['length']),(total,min(total,100),min(total,100)))

    def test_scan_failures(self):
        for kw,limit,address in (({'allocation_failure':True},100,'0x3bd9f87'),
                                 ({'declared':1000},100,'0x3bd9f68'),
                                 ({'declared':1<<63},1<<63,'0x3bd9cef')):
            self.assertIn(address,e.scan_case(self.image,1,0,limit,**kw)['panic'])

    def test_changed_context_pin_rejected(self):
        damaged=copy.copy(self.image);damaged.blob=bytearray(self.image.blob)
        damaged.blob[damaged.offset(0x394691c)]^=1
        with self.assertRaisesRegex(e.EvidenceError,'context pin mismatch'):
            e.validate_image(damaged)

    def test_patch_controls(self):
        rows=e.observe_controls(self.image)
        self.assertEqual(len(rows),6);self.assertEqual({r[1] for r in rows},{'rejected'})

    def test_generated_files_reproduce(self):
        root=Path(__file__).resolve().parents[1]
        reference=root/'research/work-items/staking-vote-bucket-lifecycle-94'
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp);summary=e.generate(self.image,output)
            self.assertEqual(summary['functions'],7);self.assertEqual(summary['mutations_rejected'],6)
            expected={p.name for p in reference.iterdir() if p.is_file() and p.name not in ('README.md','MANIFEST.sha256')}
            self.assertEqual({p.name for p in output.iterdir()},expected)
            for generated in sorted(output.iterdir()):
                self.assertEqual(generated.read_bytes(),(reference/generated.name).read_bytes(),generated.name)
            self.assertEqual(json.loads((output/'summary.json').read_text())['target_sha256'],e.SHA256)


if __name__=='__main__':unittest.main()
