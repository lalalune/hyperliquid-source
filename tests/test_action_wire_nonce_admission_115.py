import datetime
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_nonce_admission_115 as T  # noqa: E402

IMAGE = T.load_image()


def case_from(ring, nonce, sec=None, year=2025, ordinal=100, secs=0, nanos=0, fa=0, fb=0, cap=None, head=0):
    cap = cap or max(len(ring), 1)
    return (list(ring), cap, head, nonce, sec, T.pack_date(year, ordinal), secs, nanos, fa, fb)


class NonceAdmission115(unittest.TestCase):
    def test_digest_gate(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image(expected='0' * 64)

    def test_function_extents(self):
        sizes = {va: IMAGE.exact_fde(va)[1] - va for va, _ in T.FUNCTIONS}
        self.assertEqual(sizes, {0x4228080: 649, 0x4551530: 272, 0x450C430: 812, 0x4555F40: 284, 0x35BD8A0: 146,
                                 0x4228310: 616, 0x421A520: 347, 0x421A3C0: 347, 0x454B8C0: 1317, 0x4560AF0: 138})

    def test_clock_matches_calendar(self):
        epoch = datetime.date(1970, 1, 1)
        for year, ordinal in [(1970, 1), (2000, 60), (2000, 366), (2024, 366), (2100, 59), (2100, 60), (1999, 365), (2400, 100)]:
            day = datetime.date(year, 1, 1) + datetime.timedelta(days=ordinal - 1)
            want = ((day - epoch).days * 86400 + 3661) * 1000 + 5
            got = T.clock_ms(T.pack_date(year, ordinal), 3661, 5000000, T.DEFAULT)
            self.assertEqual(got, want)

    def test_clock_clamps_at_zero(self):
        self.assertEqual(T.clock_ms(T.pack_date(1900, 1), 0, 0, T.DEFAULT), 0)
        self.assertEqual(T.clock_ms(T.pack_date(-5, 10), 0, 0, T.DEFAULT), 0)

    def test_rule_order_and_bounds(self):
        now = T.clock_ms(T.pack_date(2025, 100), 0, 0, T.DEFAULT)
        ring = [now + 10, now + 20]
        self.assertEqual(T.predict(case_from(ring, now + 10)), (T.TAG_DUP, now + 10, None))
        self.assertEqual(T.predict(case_from(ring, now + 15)), (T.TAG_OK, 1, 1))
        self.assertEqual(T.predict(case_from(ring, now + 86400000)), (T.TAG_OK, 1, 2))
        self.assertEqual(T.predict(case_from(ring, now + 86400001)), (T.TAG_HIGH, now + 86400001, now + 86400000))
        self.assertEqual(T.predict(case_from(ring, now + 86400001, fb=1))[0], T.TAG_HIGH)
        self.assertEqual(T.predict(case_from(ring, now + 86400000 - 120000, fb=1)), (T.TAG_OK, 1, 2))
        low = now - 172800000
        self.assertEqual(T.predict(case_from(ring, low - 1)), (T.TAG_LOW, low - 1, low))
        self.assertEqual(T.predict(case_from(ring, low))[0], T.TAG_OK)
        low_flag = now - 172680000
        self.assertEqual(T.predict(case_from(ring, low_flag - 1, fb=1)), (T.TAG_LOW, low_flag - 1, low_flag))
        self.assertEqual(T.predict(case_from(ring, low_flag, fb=1))[0], T.TAG_OK)

    def test_full_ring_floor_and_eviction(self):
        now = T.clock_ms(T.pack_date(2025, 100), 0, 0, T.DEFAULT)
        ring = [now + i for i in range(100)]
        self.assertEqual(T.predict(case_from(ring, now - 1)), (T.TAG_LOW, now - 1, now))
        self.assertEqual(T.predict(case_from(ring, now + 100))[0], T.TAG_OK)
        pending = ('tree', [now])
        self.assertEqual(T.predict(case_from(ring, now + 100, sec=pending))[0], T.TAG_FULL)
        self.assertEqual(T.predict(case_from(ring, now + 100, sec=('tree', [now + 1])))[0], T.TAG_OK)
        self.assertEqual(T.predict(case_from(ring[:99], now + 100, sec=pending))[0], T.TAG_OK)

    def test_display_texts(self):
        texts = {t: T.display_arm(IMAGE, t) for t in (T.TAG_FULL, T.TAG_LOW, T.TAG_HIGH, T.TAG_DUP)}
        self.assertEqual(texts[T.TAG_FULL][3], 'Too many pending nonces')
        self.assertTrue(texts[T.TAG_LOW][3].startswith('Invalid nonce: nonce too low'))
        self.assertTrue(texts[T.TAG_HIGH][3].startswith('Invalid nonce: nonce too high'))
        self.assertTrue(texts[T.TAG_DUP][3].startswith('Invalid nonce: duplicate nonce'))

    def test_machine_agrees_with_model(self):
        machine = T.Machine(IMAGE)
        seen = set()
        for case in T.make_cases(400, T.CASE_SEED):
            got = T.run_case(machine, case)
            self.assertTrue(T.agrees(got, T.predict(case)), case)
            seen.add(got[0])
        self.assertEqual(seen, {T.TAG_OK, T.TAG_LOW, T.TAG_HIGH, T.TAG_DUP, T.TAG_FULL})

    def test_callees_agree_with_model(self):
        machine = T.Machine(IMAGE)
        kinds = set()
        for item in T.direct_cases(600, T.CASE_SEED + 2):
            ok, _ = T.run_direct(machine, item)
            self.assertTrue(ok, item[0])
            kinds.add(item[0])
        self.assertEqual(kinds, {'search64', 'search24', 'tree', 'fold'})

    def test_tree_builder_splits_large_key_sets(self):
        machine = T.Machine(IMAGE)
        root, height = T.build_tree(machine.memory, list(range(1, 60)))
        self.assertEqual(height, 1)
        self.assertEqual(machine.memory.read(root + 0xE6, 2), 4)

    def test_negative_model_mutants_are_detected(self):
        machine = T.Machine(IMAGE)
        remaining = {name: change for name, change in T.MUTANTS if name not in T.EQUIVALENT_REASON and name != 'upper-before-early'}
        for case in T.make_cases(1500, T.CASE_SEED):
            got = T.run_case(machine, case)
            for name in list(remaining):
                o = dict(T.DEFAULT)
                o.update(remaining[name])
                if not T.agrees(got, T.predict(case, o)):
                    del remaining[name]
        self.assertEqual(remaining, {})

    def test_negative_byte_corruptions_are_detected(self):
        cases = list(T.make_cases(300, T.CASE_SEED + 1))
        for at, original, new in [(0x42280BB, 0x72, 0x73), (0x42280E1, 0xCB, 0xCC), (0x42281C3, 0xCC, 0xCD)]:
            self.assertEqual(IMAGE.blob[IMAGE.offset(at)], original, hex(at))
            patched = T.Machine(IMAGE, {at: new})
            bad = 0
            for case in cases:
                try:
                    if not T.agrees(T.run_case(patched, case), T.predict(case)):
                        bad += 1
                except (T.Halt, T.EvidenceError):
                    bad += 1
            self.assertGreater(bad, 0, hex(at))

    def test_special_address_sets_come_from_the_bytes(self):
        set_a, set_b, consts = T.special_sets(IMAGE)
        self.assertEqual((len(set_a), len(set_b), len(consts)), (8, 8, 3))
        self.assertTrue(all(len(a) == 20 for a in set_a | set_b | set(consts)))
        self.assertFalse(set_a & set_b)

    def test_wrapper_flag_and_insertion(self):
        sets = T.special_sets(IMAGE)
        special = sorted(sets[0])[0]
        plain = bytes(20)
        now = T.clock_ms(T.pack_date(2025, 100), 0, 0, T.DEFAULT)
        ring = [now + i for i in range(100)]
        case = case_from(ring, now + 500, cap=101)
        result, after = T.wrap_model(sets, plain, case)
        self.assertEqual(result[0], T.TAG_OK)
        self.assertEqual(after, ring[1:] + [now + 500])
        result, after = T.wrap_model(sets, special, case)
        self.assertEqual(after, ring + [now + 500])
        result, after = T.wrap_model(sets, plain, case_from(ring, now + 50, cap=101))
        self.assertEqual(result[0], T.TAG_DUP)
        self.assertEqual(after, ring)

    def test_wrapper_agrees_with_machine(self):
        machine = T.Machine(IMAGE)
        sets = T.special_sets(IMAGE)
        seen = set()
        for addr, case in T.wrap_cases(IMAGE, 300, T.CASE_SEED + 4):
            got, ring_after, cap, _ = T.run_wrap(machine, addr, case)
            want, want_ring = T.wrap_model(sets, addr, case)
            self.assertTrue(T.wrap_agrees(got, ring_after, cap, want, want_ring, case))
            seen.add(want[0])
        self.assertEqual(seen, {T.TAG_OK, T.TAG_LOW, T.TAG_HIGH, T.TAG_DUP, T.TAG_FULL})

    def test_wrapper_mutants_are_detected(self):
        machine = T.Machine(IMAGE)
        sets = T.special_sets(IMAGE)
        remaining = dict(T.WRAP_MUTANTS)
        for addr, case in T.wrap_cases(IMAGE, 800, T.CASE_SEED + 4):
            got, ring_after, cap, _ = T.run_wrap(machine, addr, case)
            for name in list(remaining):
                o = dict(T.WRAP_DEFAULT)
                o.update(remaining[name])
                want, want_ring = T.wrap_model(sets, addr, case, o)
                if not T.wrap_agrees(got, ring_after, cap, want, want_ring, case):
                    del remaining[name]
        self.assertEqual(remaining, {})

    def test_front_end_layouts_come_from_the_bytes(self):
        got = {va: T.front_layout(IMAGE, va) for va, _ in T.FRONT_FUNCTIONS}
        self.assertEqual(got, {0x2C766E0: (0xB40, 0xB48, 0x3AF0), 0x560DBB0: (0x16B0, 0x16B8, 0x4660), 0x560DCA0: (0xB40, 0xB48, 0x3AF0)})
        self.assertEqual({va: IMAGE.exact_fde(va)[1] - va for va, _ in T.FRONT_FUNCTIONS}, {va: 233 for va, _ in T.FRONT_FUNCTIONS})
        self.assertEqual({va: IMAGE.exact_fde(va)[1] - va for va, _ in T.LOOKUP_FUNCTIONS},
                         {0x3BE7E80: 313, 0x4717440: 363, 0x45927A0: 471, 0x3EE6E80: 300, 0x3EC72B0: 1041, 0x3EE0ED0: 1953, 0x3DDD030: 162})

    def test_front_end_layout_rejects_other_code(self):
        with self.assertRaises(T.EvidenceError):
            T.front_layout(IMAGE, 0x4228310)

    def test_full_ring_insert_grows_capacity(self):
        now = T.clock_ms(T.pack_date(2025, 100), 0, 0, T.DEFAULT)
        ring = [now + i for i in range(10)]
        self.assertEqual(T.expected_cap(case_from(ring, now + 50, cap=10), True), 20)
        self.assertEqual(T.expected_cap(case_from(ring, now + 50, cap=11), True), 11)
        self.assertEqual(T.expected_cap(case_from(ring, now + 5, cap=10), False), 10)
        self.assertEqual(T.expected_cap(case_from(ring[:1], now + 50, cap=1), True), 4)

    def test_grow_fixup_runs_for_full_rings(self):
        machine = T.Machine(IMAGE)
        sets = T.special_sets(IMAGE)
        grown = 0
        for addr, case in T.wrap_cases(IMAGE, 300, T.CASE_SEED + 4):
            got, ring_after, cap, seen = T.run_wrap(machine, addr, case)
            want, want_ring = T.wrap_model(sets, addr, case)
            self.assertTrue(T.wrap_agrees(got, ring_after, cap, want, want_ring, case))
            if T.GROW_FIX in seen:
                grown += 1
                self.assertEqual(want[0], T.TAG_OK)
                self.assertEqual(cap, max(2 * case[1], 4))
        self.assertGreater(grown, 5)

    def test_front_counters_saturate(self):
        self.assertEqual(T.sat_inc(0), 1)
        self.assertEqual(T.sat_inc(T.M64X), T.M64X)
        self.assertEqual(T.sat_inc(T.M64X - 1), T.M64X)
        self.assertEqual(T.sat_inc(T.M64X, wrap=True), 0)

    def test_front_ends_agree_with_model(self):
        machine = T.Machine(IMAGE)
        sets = T.special_sets(IMAGE)
        tags = set()
        for va, _ in T.FRONT_FUNCTIONS:
            layout = T.front_layout(IMAGE, va)
            for addr, case, key, c1, c2 in T.front_cases(IMAGE, 120, T.CASE_SEED + 6):
                run = T.run_front(machine, va, layout, addr, case, key, c1, c2)
                want = T.front_model(sets, addr, case, key, (c1, c2, T.CTX + layout[2]))
                self.assertTrue(T.front_agrees(run, want, case, key, layout), (hex(va), case))
                tags.add(want[0][0])
        self.assertEqual(tags, {T.TAG_OK, T.TAG_LOW, T.TAG_HIGH, T.TAG_DUP})

    def test_front_mutants_are_detected(self):
        machine = T.Machine(IMAGE)
        sets = T.special_sets(IMAGE)
        layout = T.front_layout(IMAGE, 0x2C766E0)
        remaining = dict(T.FRONT_MUTANTS)
        for addr, case, key, c1, c2 in T.front_cases(IMAGE, 400, T.CASE_SEED + 6):
            run = T.run_front(machine, 0x2C766E0, layout, addr, case, key, c1, c2)
            for name in list(remaining):
                o = dict(T.FRONT_DEFAULT)
                o.update(remaining[name])
                alt = T.front_model(sets, addr, case, key, (c1, c2, T.CTX + layout[2]), o)
                if not T.front_agrees(run, alt, case, key, layout):
                    del remaining[name]
        self.assertEqual(remaining, {})

    def test_siphash_matches_machine(self):
        machine = T.Machine(IMAGE)
        for k0, k1, key in T.hasher_cases(60, 7):
            self.assertEqual(T.run_hasher(machine, k0, k1, key)[0], T.siphash13(k0, k1, key))
        self.assertNotEqual(T.siphash13(1, 2, bytes(20)), T.siphash13(1, 2, bytes(19) + b'\x01'))

    def test_table_mirror_and_slot_rules(self):
        table = T.Table(4)
        table.set_ctrl(1, 0x11)
        self.assertEqual(table.ctrl[1], 0x11)
        self.assertEqual(table.ctrl[((1 - 16) & 3) + 16], 0x11)
        table.set_ctrl(3, T.DELETED)
        self.assertEqual(table.insert_slot(3), 3)
        self.assertEqual(table.find(0x11 << 57 | 1, lambda i: True, []), 1)

    def test_lookup_agrees_with_model(self):
        machine = T.Machine(IMAGE)
        hits = misses = 0
        for state, key in T.lookup_cases(200, T.CASE_SEED + 20):
            run = T.run_lookup(machine, state, key)
            want = T.lookup_model(state, key)
            self.assertTrue(T.lookup_agrees(run, want))
            if want[1]['items'] == state['items']:
                hits += 1
            else:
                misses += 1
        self.assertGreater(hits, 20)
        self.assertGreater(misses, 20)

    def test_lookup_mutants_are_detected(self):
        machine = T.Machine(IMAGE)
        remaining = {name: change for name, change in T.LK_MUTANTS if name not in T.GROW_MUTANTS}
        for state, key in T.lookup_cases(500, T.CASE_SEED + 20):
            run = T.run_lookup(machine, state, key)
            for name in list(remaining):
                o = dict(T.LK_DEFAULT)
                o.update(remaining[name])
                try:
                    alt = T.lookup_model(state, key, o)
                except (T.EvidenceError, IndexError):
                    continue
                if not T.lookup_agrees(run, alt):
                    del remaining[name]
        self.assertEqual(remaining, {})

    def test_lookup_byte_corruption_is_detected(self):
        machine = T.Machine(IMAGE)
        cases = list(T.lookup_cases(80, T.CASE_SEED + 22))
        at = 0x3EE6ED6
        original = IMAGE.blob[IMAGE.offset(at)]
        patched = T.Machine(IMAGE, {at: original ^ 1})
        bad = 0
        for state, key in cases:
            try:
                bad += not T.lookup_agrees(T.run_lookup(patched, state, key), T.lookup_model(state, key))
            except (T.Halt, T.EvidenceError, KeyError, IndexError):
                bad += 1
        self.assertGreater(bad, 0)

    def test_reserve_capacity_rules(self):
        self.assertEqual([T.Table(n).capacity() for n in (4, 8, 16, 32, 128)], [3, 7, 14, 28, 112])
        entries = [((0, 8, 0, 0), h << 57 | n, bytes(20)) for n, h in enumerate((1, 2, 3))]
        full = T.Table(4)
        for n, entry in enumerate(entries):
            slot = full.insert_slot(entry[1])
            full.growth -= 1
            full.set_ctrl(slot, entry[1] >> 57)
            full.bucket[slot] = n
            full.items += 1
        grown = full.reserve(entries)
        self.assertEqual((grown.mask + 1, grown.items, grown.growth), (8, 3, 4))
        self.assertEqual(sorted(grown.bucket[i] for i in range(8) if grown.ctrl[i] < 0x80), [0, 1, 2])

    def test_grow_arm_agrees_with_machine(self):
        machine = T.Machine(IMAGE)
        resized = in_place = 0
        for state, key in T.lookup_cases(700, T.CASE_SEED + 20):
            run = T.run_lookup(machine, state, key)
            self.assertTrue(T.lookup_agrees(run, T.lookup_model(state, key)))
            if T.REHASH in run[2]:
                resized += run[1]['buckets'] > state['buckets']
                in_place += run[1]['buckets'] == state['buckets']
        self.assertGreater(resized, 10)
        self.assertGreater(in_place, 10)

    def test_grow_mutants_are_detected_by_the_model(self):
        remaining = {name: change for name, change in T.LK_MUTANTS if name in T.GROW_MUTANTS}
        for state, key in T.lookup_cases(T.LOOKUP_CASES, T.CASE_SEED + 20):
            want = T.lookup_model(state, key)
            for name in list(remaining):
                o = dict(T.LK_DEFAULT)
                o.update(remaining[name])
                if not T.lookup_agrees(want, T.lookup_model(state, key, o)):
                    del remaining[name]
        self.assertEqual(remaining, {})

    def test_grow_byte_corruption_is_detected(self):
        at = 0x3EE131D
        self.assertEqual(IMAGE.blob[IMAGE.offset(at)], 0xFF)
        patched = T.Machine(IMAGE, {at: 0xFE})
        bad = 0
        for state, key in T.lookup_cases(150, T.CASE_SEED + 22):
            try:
                bad += not T.lookup_agrees(T.run_lookup(patched, state, key), T.lookup_model(state, key))
            except (T.Halt, T.EvidenceError, KeyError, IndexError):
                bad += 1
        self.assertGreater(bad, 0)

    def test_small_proof_run(self):
        saved = (T.FRONT_CASES, T.FRONT_PATCH, T.LOOKUP_CASES, T.HASH_CASES, T.LOOKUP_PATCH)
        T.FRONT_CASES, T.FRONT_PATCH, T.LOOKUP_CASES, T.HASH_CASES, T.LOOKUP_PATCH = 60, 30, 60, 30, 30
        try:
            r = T.prove(IMAGE, 300, 150, direct=300, direct_patch=200, wrap=200, wrap_patch=100)
        finally:
            T.FRONT_CASES, T.FRONT_PATCH, T.LOOKUP_CASES, T.HASH_CASES, T.LOOKUP_PATCH = saved
        self.assertEqual(r['negative'], r['found'] + len(r['equivalent']))
        self.assertGreaterEqual(r['negative'], 150)
        self.assertEqual(r['front']['total'], 180)
        self.assertEqual(r['total'], 800 + 180 + r['lookup']['total'] + r['lookup']['hashes'])


if __name__ == '__main__':
    unittest.main()
