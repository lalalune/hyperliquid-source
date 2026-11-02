import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import book_cancel_short_order94 as subject
from elf_index import sections


class TestStaticEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = sections(cls.data)

    def test_authenticated_target_and_ranges(self):
        subject.authenticate(self.data)
        subject.validate_ranges(self.data, self.secs)
        self.assertEqual(len(subject.FUNCTIONS), 3)
        self.assertEqual(len(subject.WINDOWS), 16)

    def test_digest_corruption_rejected(self):
        bad = bytearray(self.data)
        bad[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.authenticate(bad)

    def test_function_corruption_rejected(self):
        bad = bytearray(self.data)
        bad[subject.resolve(bad, self.secs, 0x433a0c1, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'function'):
            subject.validate_ranges(bad, self.secs)

    def test_host_window_corruption_rejected(self):
        bad = bytearray(self.data)
        bad[subject.resolve(bad, self.secs, 0x4cddd34, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'window'):
            subject.validate_ranges(bad, self.secs)

    def test_invalid_addresses_and_nobits(self):
        with self.assertRaises(ValueError):
            subject.resolve(self.data, self.secs, -1, 1)
        with self.assertRaises(ValueError):
            subject.resolve(self.data, self.secs, 0, 0)
        with self.assertRaises(ValueError):
            subject.resolve(self.data, self.secs, 1 << 63, 8)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            subject.resolve(self.data, [bss], bss['address'], 1)

    def test_duplicate_mapping_rejected(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            subject.resolve(self.data, [text, dict(text)], 0x4339fe0, 1)

    def test_code_must_be_executable(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        nonexec = dict(text, flags=text['flags'] & ~4)
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            subject.read(self.data, [nonexec], 0x4339fe0, 1)

    def test_branch_displacement_outside_code_rejected(self):
        bad = bytearray(self.data)
        offset = subject.resolve(bad, self.secs, 0x4cddd35, 6, executable=True)
        bad[offset+2:offset+6] = (0x7fffffff).to_bytes(4, 'little')
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            subject.branch(bad, self.secs, 0x4cddd35)

    def test_branch_targets_and_bad_opcode(self):
        self.assertEqual(subject.branch(self.data, self.secs, 0x433a0bb)[0], 0x433a0d6)
        self.assertEqual(subject.branch(self.data, self.secs, 0x4cddd35)[0], 0x4cde25b)
        with self.assertRaisesRegex(ValueError, 'branch opcode'):
            subject.branch(self.data, self.secs, 0x4339fe0)

    def test_direct_edges_and_bad_opcode(self):
        for site, expected in subject.CALLS:
            self.assertEqual(subject.direct_call(self.data, self.secs, site), expected)
        with self.assertRaisesRegex(ValueError, 'call opcode'):
            subject.direct_call(self.data, self.secs, 0x4339fe0)

    def test_constants_and_large_sort_relocation(self):
        c = subject.instructions_constants(self.data, self.secs)
        self.assertEqual(c['slot_stride'], 248)
        self.assertEqual(c['row_stride'], 40)
        self.assertEqual(c['large_sort_min'], 21)
        self.assertEqual(c['product_limit'], (1 << 63) - 2)
        self.assertEqual(c['cancel_reason'], 7)
        self.assertEqual(subject.relocation(self.data, self.secs, 0x5776740), 0x44885a0)
        for site, prefix, slot, target in subject.INDIRECT:
            self.assertEqual(subject.indirect_edge(self.data, self.secs, site, prefix)[:2], (slot,target))
        with self.assertRaisesRegex(ValueError, 'opcode'):
            subject.indirect_edge(self.data, self.secs, 0x4cde26b, b'\x90\x90')

    def test_duplicate_relocation_is_rejected(self):
        blob = struct.pack('<QQq', 16, 8, 4) * 2
        fake = [{'type': 4, 'offset': 0, 'size': len(blob)}]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            subject.relocation(blob, fake, 16)

    def test_partial_relocation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'partial'):
            subject.relocation(bytes(25), [{'type': 4, 'offset': 0, 'size': 25}], 0)

    def test_location_path_is_relative_suffix(self):
        self.assertEqual(subject.location(self.data,self.secs,0x5742338)[2:],
                         ('l1/src/books.rs',19,47))
        with self.assertRaises(ValueError):
            subject.location(self.data,self.secs,0)

    def test_regeneration_matches_retained_evidence(self):
        location = ROOT / 'research/work-items/RE-006-cancel-candidate-rank-94'
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory)
            subject.generate(self.data, generated)
            files = sorted(p.name for p in generated.iterdir())
            self.assertEqual(files, ['branches.tsv','calls.tsv','evidence.json',
                                     'gap-cases.tsv','indirect.tsv','locations.tsv','lookup-cases.tsv','pipeline-cases.tsv',
                                     'rank-cases.tsv','sort-cases.tsv','transition-cases.tsv',
                                     'tree-cases.tsv','windows.tsv'])
            for name in files:
                self.assertEqual((generated/name).read_bytes(), (location/name).read_bytes(), name)


class TestModels(unittest.TestCase):
    multiplier = 0xf1357aea2e62a9c5
    limit = (1 << 63) - 2

    def test_prebuilt_lookup_controls(self):
        rows = subject.lookup_cases(self.multiplier)
        self.assertEqual([x[-2] for x in rows],
                         ['empty-map','key-absent','key-absent','slot-out-of-range',
                          'vacant-slot','owner-mismatch','matched','vacant-slot'])

    def test_probe_collision_then_matching_candidate(self):
        key = 47
        user = bytes(range(20))
        h = subject.hash64(key, self.multiplier)
        i = h & 31
        tag = h >> 57
        controls = [0xff] * 32
        controls[i] = controls[(i+1)&31] = tag
        buckets = {i: (key+1, 0), (i+1)&31: (key, 0)}
        self.assertEqual(subject.probe(key,user,controls,buckets,[(0,user)],2,self.multiplier),
                         ('matched',0))

    def test_probe_skips_tombstone_and_wraps(self):
        user = bytes(range(20))
        key = next(x for x in range(10000) if subject.hash64(x,self.multiplier)&31 == 31)
        tag = subject.hash64(key,self.multiplier) >> 57
        controls = [0xff] * 32
        controls[31], controls[0] = 0x80, tag
        self.assertEqual(subject.probe(key,user,controls,{0:(key,0)},[(0,user)],1,self.multiplier),
                         ('matched',0))

    def test_probe_rejects_full_table_without_empty_marker(self):
        with self.assertRaisesRegex(ValueError, 'no empty marker'):
            subject.probe(9,bytes(20),[0x80]*32,{},[],1,self.multiplier)

    def test_probe_rejects_invalid_fixture(self):
        with self.assertRaises(ValueError):
            subject.probe(1,bytes(19),[255]*16,{},[],1,self.multiplier)
        with self.assertRaises(ValueError):
            subject.probe(1,bytes(20),[255]*15,{},[],1,self.multiplier)
        with self.assertRaises(ValueError):
            subject.probe(-1,bytes(20),[255]*16,{},[],1,self.multiplier)

    def test_probe_requires_bucket_for_matching_control(self):
        key = 8
        controls = [0xff]*16
        controls[subject.hash64(key,self.multiplier)&15] = subject.hash64(key,self.multiplier)>>57
        with self.assertRaisesRegex(ValueError, 'no bucket'):
            subject.probe(key,bytes(20),controls,{},[],1,self.multiplier)

    def test_slot_field_copy_and_padding(self):
        slot = bytearray(248)
        struct.pack_into('<Q',slot,0xa0,123)
        struct.pack_into('<Q',slot,0xc8,456)
        struct.pack_into('<Q',slot,0xd8,789)
        slot[0xc2] = 1
        result = subject.row_from_slot(slot,10004,b'1234567')
        self.assertEqual(struct.unpack('<QQQQB7s',result),(123,10004,456,789,1,b'1234567'))
        with self.assertRaises(ValueError):
            subject.row_from_slot(slot[:-1],0,bytes(7))
        with self.assertRaises(ValueError):
            subject.row_from_slot(slot,0,bytes(6))

    def test_product_boundary_and_overflow(self):
        rank = lambda price,size: subject.rank_flags(subject.row(price,1,size,1,1),0,self.limit)
        self.assertEqual(rank(self.limit,1)[1],0)
        self.assertEqual(rank(self.limit+1,1)[1],1)
        self.assertEqual(rank(subject.U64,2)[1],1)
        self.assertEqual(rank(subject.U64,0)[1],0)

    def test_signed_minimum_and_nonboolean_side(self):
        a = subject.row(1,1,1 << 63,1,0)
        b = subject.row(1,1,1 << 63,1,2)
        self.assertEqual(subject.rank_flags(a,subject.I64_MIN,self.limit)[0],1)
        self.assertEqual(subject.rank_flags(b,subject.I64_MIN,self.limit)[0],0)
        self.assertEqual(subject.rank_flags(subject.row(1,1,(1<<63)+1,1,0),subject.I64_MIN,self.limit)[0],0)

    def test_missing_position_and_zero_size(self):
        self.assertEqual(subject.rank_flags(subject.row(0,1,0,1,0),0,self.limit)[0],1)
        self.assertEqual(subject.rank_flags(subject.row(0,1,1,1,0),0,self.limit)[0],0)

    def test_tree_lookup_hits_misses_and_children(self):
        left = ([10],[-1],[])
        right = ([30],[5],[])
        root = ([20],[-2],[left,right])
        self.assertEqual(subject.position_lookup(None,0,20), (0,[]))
        self.assertEqual(subject.position_lookup(root,1,10), (-1,[0,0]))
        self.assertEqual(subject.position_lookup(root,1,20), (-2,[0]))
        self.assertEqual(subject.position_lookup(root,1,30), (5,[1,0]))
        self.assertEqual(subject.position_lookup(root,1,25), (0,[1,0]))
        self.assertEqual(len(subject.tree_cases()),18)

    def test_tree_lookup_rejects_malformed_fixtures(self):
        with self.assertRaises(ValueError):
            subject.position_lookup(([2,1],[0,0],[]),0,0)
        with self.assertRaises(ValueError):
            subject.position_lookup(([1],[0],[]),1,0)
        with self.assertRaises(ValueError):
            subject.position_lookup(([-1],[0],[]),0,0)

    def test_flag_grid_and_tie_retention(self):
        self.assertEqual(len(subject.rank_cases()),144)
        self.assertFalse(subject.flag_decision((0,0,3),(0,0,3)))
        self.assertFalse(subject.flag_decision((0,1,9),(0,1,1)))
        self.assertTrue(subject.flag_decision((0,0,1),(0,1,1)))
        with self.assertRaises(ValueError):
            subject.flag_decision((2,0,0),(0,0,0))

    def test_short_sort_full_records_and_boundary(self):
        a = subject.row(3,1,2,12,1,b'abcdefg')
        b = subject.row(3,1,2,13,1,b'1234567')
        c = subject.row(0,1,2,14,1,b'7654321')
        result = subject.short_sort([a,b,c],{1:-3},self.limit,21)
        self.assertEqual(result,[c,a,b])
        self.assertEqual(len(subject.short_sort([a]*20,{1:-3},self.limit,21)),20)
        with self.assertRaisesRegex(ValueError,'outside'):
            subject.short_sort([a]*21,{1:-3},self.limit,21)

    def test_entry_gap_signed_extremes(self):
        self.assertEqual(subject.entry_gap(8,3),(5,False))
        self.assertEqual(subject.entry_gap(3,8),(0,False))
        self.assertEqual(subject.entry_gap(subject.I64_MAX,-1),(subject.I64_MAX,True))
        self.assertEqual(subject.entry_gap(subject.I64_MIN,1),(0,True))
        with self.assertRaises(ValueError):
            subject.entry_gap(1 << 63,0)

    def test_transition_table(self):
        rows = subject.transition_cases(10000)
        self.assertEqual([(x[0],x[-1]) for x in rows],
                         [('no-rows','end'),('first-sentinel','sentinel'),
                          ('bad-book','book-bound-failure'),('nonzero-then-success','threshold'),
                          ('success-below-threshold','threshold'),('counter-increases','end'),
                          ('threshold-zero','threshold'),
                          ('selected-book-market-bound','market-row-bound-failure'),
                          ('nonzero-skips-market-bound','end')])
        self.assertEqual(rows[3][-2], '11,12')
        self.assertEqual(rows[4][-2], '11,12')
        self.assertEqual(rows[6][-2], '11')

    def test_transition_missing_outcome_rejected(self):
        a = subject.row(1,0,1,1,0)
        with self.assertRaisesRegex(ValueError,'callee result'):
            subject.consume([a],1,1,1,{}, {},10000,book_assets={0:0},market_count=1)
        with self.assertRaisesRegex(ValueError,'post-cancel'):
            subject.consume([a],1,1,1,{1:0}, {},10000,book_assets={0:0},market_count=1)
        with self.assertRaisesRegex(ValueError,'book asset'):
            subject.consume([a],1,1,1,{1:0}, {1:0},10000,book_assets={},market_count=1)
        with self.assertRaisesRegex(ValueError,'loop fixture'):
            subject.consume([],1,1,1,{}, {},0,book_assets={},market_count=1)

    def test_composed_lookup_sort_and_cancel(self):
        constants = {'hash_multiplier':self.multiplier, 'slot_stride':248,
                     'product_limit':self.limit,'large_sort_min':21,'asset_divisor':10000}
        result = subject.pipeline_case(constants)[0]
        self.assertEqual(result[1], 'matched,matched,owner-mismatch,slot-out-of-range')
        self.assertEqual(result[2:], ('11,12','12,11','12,11','threshold'))


if __name__ == '__main__':
    unittest.main()
