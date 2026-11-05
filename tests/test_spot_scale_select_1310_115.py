import json
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import spot_scale_select_1310_115 as subject


class SpotScaleSelect1310Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])
        cls.hbody = bytes.fromhex(cls.record['helper']['body_hex'])

    def test_exact_target_scope_and_evidence(self):
        self.assertEqual(self.record,
                         json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 672)
        self.assertEqual(self.record['native_instructions'], 157)
        self.assertEqual(len(self.hbody), 180)
        self.assertEqual(self.record['helper']['native_instructions'], 56)
        self.assertFalse(self.record['gates_changed'])

    def test_locations_are_the_spot_meta_panic_sites(self):
        locs = {(l['file'], l['line'], l['col']) for l in self.record['locations']}
        self.assertEqual(locs, {
            ('l1/src/spot_meta.rs', 590, 25),
            ('l1/src/spot_meta.rs', 119, 33),
            ('l1/src/spot_meta.rs', 1055, 9),
            ('/home/ubuntu/hl/code_Mainnet/z_vendor/indexmap/src/map.rs', 762, 26),
        })

    def test_slots_resolve(self):
        resolved = {e['slot']: e['resolved'] for e in self.record['indirect_slots']}
        self.assertEqual(resolved[0x64e6a78], 0x3d1a200)
        self.assertEqual(resolved[0x64df620], 0x1680cbf)
        self.assertEqual(resolved[0x64df830], 0x1680c10)
        self.assertEqual(resolved[0x64df848], 0x1681e40)

    def test_panic_shim_messages(self):
        msgs = {s['shim']: (s['message_text'], s['message_length_immediate'])
                for s in self.record['panic_shims']}
        self.assertEqual(msgs[0x1680c10],
                         ('called `Option::unwrap()` on a `None` value', 43))
        self.assertEqual(msgs[0x1681e40],
                         ('attempt to subtract with overflow', 67))

    def test_census(self):
        census = self.record['census']
        self.assertEqual(len(census['direct_call_sites']), 15)
        self.assertEqual(census['direct_tail_jumps'], [])
        self.assertEqual(len(census['caller_fdes']), 13)
        self.assertEqual(census['stored_qwords'], [])
        self.assertEqual(census['relative_addends'], [])
        helper = census['helper']
        self.assertEqual(helper['direct_call_sites'], [])
        self.assertEqual([s['site'] for s in helper['slot_call_sites']],
                         [0x289215e, 0x5a0131e])
        self.assertEqual(helper['relative_addends'], [0x64e6a78])
        self.assertEqual(helper['stored_qwords'], [])

    def test_cascade_transcription_matches_closed_form(self):
        values = {0, 1, 2**64 - 1}
        for k in range(0, 21):
            for base in (10**k,):
                for delta in (-2, -1, 0, 1, 2):
                    v = base + delta
                    if 0 <= v < 2**64:
                        values.add(v)
        rng = random.Random(0x1310)
        values.update(rng.randrange(2**64) for _ in range(4000))
        for v in values:
            self.assertEqual(subject.cascade_transcribed(v),
                             subject.cascade_closed(v), f'v={v}')

    def test_pow10_walk_matches_saturating_closed_form(self):
        for d in range(0, 256):
            kind, product = subject.pow10_transcribed(d)
            if 10**d <= 2**64 - 1:
                self.assertEqual((kind, product), ('value', 10**d), f'd={d}')
            else:
                self.assertEqual(kind, 'cascade', f'd={d}')

    def test_subject_model_decision_table(self):
        m = subject.subject_model
        # Override short-circuits everything, including bad pairs.
        self.assertEqual(m(1000, 0, 10**30, 10**30, 0, 0, 0), ('return', 1000))
        # Pair entries must be below the table count (second checked first).
        self.assertEqual(m(0, 0, 0, 5, 5, 0, 0), ('panic', 'unwrap_none'))
        self.assertEqual(m(0, 0, 5, 0, 5, 0, 0), ('panic', 'unwrap_none'))
        # Negative byte difference is the subtract-overflow panic.
        self.assertEqual(m(0, 0, 0, 0, 5, 7, 3), ('panic', 'subtract_overflow'))
        # Result is min(cascade, 10**d).
        self.assertEqual(m(0, 10**9, 0, 0, 5, 2, 5),
                         ('return', min(10**4, 10**3)))
        self.assertEqual(m(0, 123, 0, 0, 5, 0, 0), ('return', 1))
        # d >= 32 saturates to the cascade (cascade(10**9) = 10**5).
        self.assertEqual(m(0, 10**9, 0, 0, 5, 0, 40), ('return', 10**5))
        # d == 19 fits u64; d == 20 saturates through the overflow check.
        # At the largest u64 the cascade is 10**15, so both return it.
        self.assertEqual(m(0, 2**64 - 1, 0, 0, 5, 0, 19), ('return', 10**15))
        self.assertEqual(m(0, 2**64 - 1, 0, 0, 5, 0, 20), ('return', 10**15))

    def test_helper_model_decision_table(self):
        h = subject.helper_model
        self.assertEqual(h(5, 5, 0, 0, 0), ('panic', 'bounds'))
        self.assertEqual(h(0, 5, 0, 0, 0), ('return', 0))
        self.assertEqual(h(0, 5, 42, 1, 42), ('return', 1000))
        self.assertEqual(h(0, 5, 42, 1, 43), ('return', 0))
        self.assertEqual(h(0, 5, 0, 3, 0, lookup_found=False), ('return', 0))
        self.assertEqual(h(0, 5, 0, 3, 0, lookup_found=True, lookup_value=2),
                         ('return', 1000))
        self.assertEqual(h(0, 5, 0, 3, 0, lookup_found=True, lookup_value=3),
                         ('panic', 'map_bounds'))

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def mutate(self, body, check, start, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - start
        self.assertEqual(body[offset:offset + len(original)], original)
        mutated = body[:offset] + altered + body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'instruction changed'):
            check(mutated)

    def test_entry_helper_slot_call_is_pinned(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a0131e, 'ff155457ae00', 'ff155457ae01')

    def test_first_cascade_threshold_is_100000(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a01334, '4981ffa0860100', '4981ffa1860100')

    def test_pair_stride_is_32(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a01492, '49c1e605', '49c1e606')

    def test_table_stride_is_344(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a014bd, '4869c958010000', '4869c959010000')

    def test_second_byte_offset_is_0x49(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a014c4, '0fb6540f49', '0fb6540f4a')

    def test_subtract_borrow_takes_the_panic(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a014d4, '0f82c9000000', '0f83c9000000')

    def test_result_is_the_minimum(self):
        self.mutate(self.body, subject.check_body, subject.START,
                    0x5a014e4, '480f42c1', '480f43c1')

    def test_helper_bounds_branch_is_unsigned(self):
        self.mutate(self.hbody, subject.check_helper_body, subject.HSTART,
                    0x3d1a20b, '737e', '727e')

    def test_helper_tag_one_is_the_special_variant(self):
        self.mutate(self.hbody, subject.check_helper_body, subject.HSTART,
                    0x3d1a226, '4883f801', '4883f802')

    def test_helper_override_value_is_1000(self):
        self.mutate(self.hbody, subject.check_helper_body, subject.HSTART,
                    0x3d1a274, 'b8e8030000', 'b8e9030000')

    def test_truncated_bodies(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_helper_body(self.hbody[:-1])


if __name__ == '__main__':
    unittest.main()
