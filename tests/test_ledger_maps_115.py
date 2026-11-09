import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import ledger_maps_115 as t  # noqa: E402

WORK = ROOT / 'research' / 'work-items' / 'fees-ledger-maps-115'


_CACHE = {}


def loaded():
    if not _CACHE:
        data = (ROOT / t.BINARY).read_bytes()
        t.check_digest(data)
        img = t.Image(data)
        fdes = t.Fdes(img)
        code, extents = t.decode_subjects(img, fdes)
        _CACHE.update(data=data, img=img, fdes=fdes, code=code, extents=extents, ctl=t.control_vectors())
    return _CACHE


class Base(unittest.TestCase):
    def setUp(self):
        c = loaded()
        self.data, self.img, self.fdes = c['data'], c['img'], c['fdes']
        self.code, self.extents, self.ctl = c['code'], c['extents'], c['ctl']

    def obs(self, fn, payload):
        o, _ = t.observe(self.img, self.code, fn, payload)
        return o


class TestSipModel(unittest.TestCase):
    def test_streaming_object_equals_closed_form(self):
        rng = t.Rng(7)
        for i in range(300):
            data = rng.bytes(i % 41)
            k0, k1 = rng.next(), rng.next()
            h = t.Hasher(k0, k1)
            cut = 0
            while cut < len(data):
                step = 1 + rng.below(9)
                h.write(data[cut:cut + step])
                cut += step
            self.assertEqual(h.finish(), t.siphash(k0, k1, data))

    def test_zero_key_zero_message_value(self):
        self.assertEqual(t.siphash(0, 0, b''), t.Hasher(0, 0).finish())

    def test_length_byte_matters(self):
        self.assertNotEqual(t.siphash(1, 2, bytes(8)), t.siphash(1, 2, bytes(9)))
        self.assertNotEqual(t.siphash(1, 2, bytes(8)), t.siphash(1, 2, bytes(8), length_byte=False))

    def test_key_halves_not_symmetric(self):
        self.assertNotEqual(t.siphash(1, 2, b'abc'), t.siphash(2, 1, b'abc'))
        self.assertEqual(t.siphash(1, 2, b'abc'), t.siphash(2, 1, b'abc', swap_keys=True))

    def test_rounds_are_one_and_three(self):
        base = t.siphash(5, 6, bytes(20))
        self.assertNotEqual(base, t.siphash(5, 6, bytes(20), c=2))
        self.assertNotEqual(base, t.siphash(5, 6, bytes(20), d=2))
        self.assertNotEqual(base, t.siphash(5, 6, bytes(20), d=4))

class TestTableModel(unittest.TestCase):
    def test_insert_sets_tag_and_mirror(self):
        tb = t.RawTable(8)
        idx = tb.insert(0x55 << 57 | 3, 0)
        self.assertEqual(idx, 3)
        self.assertEqual(tb.ctrl[3], 0x55)
        self.assertEqual(tb.ctrl[((3 - 16) & 7) + 16], 0x55)

    def test_probe_finds_and_misses(self):
        tb = t.RawTable(16)
        keys = [bytes([i]) * 20 for i in range(5)]
        hs = [(i + 1) << 57 | i for i in range(5)]
        for i, h in enumerate(hs):
            tb.insert(h, i)
        for i in range(5):
            self.assertIsNotNone(t.probe_find(tb, hs[i], 5, lambda v, i=i: keys[v] == keys[i]))
        self.assertIsNone(t.probe_find(tb, hs[0], 5, lambda v: False))

    def test_bounds_panic(self):
        tb = t.RawTable(8)
        tb.insert(0x10 << 57, 9)
        with self.assertRaises(t.Bounds):
            t.probe_find(tb, 0x10 << 57, 2, lambda v: True)

    def test_deleted_never_matches(self):
        tb = t.RawTable(8)
        tb.insert(0x10 << 57, 0)
        tb.set_ctrl(0, t.DELETED)
        self.assertIsNone(t.probe_find(tb, 0x10 << 57, 1, lambda v: True))


class TestDecoder(Base):
    def test_decoder_lands_on_every_fde_end(self):
        for fn, (lo, hi) in self.extents.items():
            self.assertEqual(self.fdes.range_of(fn)['end'], hi)
            insns = [self.code[v] for v in sorted(self.code) if lo <= v < hi]
            self.assertEqual(insns[-1].va + insns[-1].size, hi)

    def test_instruction_counts(self):
        counts = {fn: sum(1 for v in self.code if lo <= v < hi) for fn, (lo, hi) in self.extents.items()}
        self.assertEqual(counts[t.S_H20], 91)
        self.assertEqual(counts[t.S_H16], 91)
        self.assertEqual(counts[t.S_WRITE], 141)
        self.assertEqual(counts[t.S_FA], 77)
        self.assertEqual(counts[t.S_ENTRY], 40)

    def test_sip_constants_in_each_hasher(self):
        t.constants_check(self.img)

    def test_unlisted_opcode_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_one(b'\x0f\x0b' + b'\x90' * 16, 0, 0x1000)

    def test_not_an_fde_start(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_subjects_one(self.img, self.fdes, t.S_H20 + 1)

    def test_nobits_refused(self):
        with self.assertRaises(t.EvidenceError):
            self.img.read(self.img.sec['.bss'][0], 4)

    def test_truncated_uleb(self):
        with self.assertRaises(t.EvidenceError):
            t.uleb(b'\x80\x80', 0)

    def test_digest_flip(self):
        with self.assertRaises(t.EvidenceError):
            t.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))


class TestHashers(Base):
    def run_group(self, fn, count, step):
        done = 0
        for k, (group, f, payload) in enumerate(t.case_stream()):
            if f != fn or k % step:
                continue
            o = self.obs(f, payload)
            self.assertTrue(t.agree(f, o, t.expected(f, payload)), (group, k))
            done += 1
            if done >= count:
                break
        self.assertGreaterEqual(done, min(count, 20))

    def test_hash20(self):
        self.run_group(t.S_H20, 120, 7)

    def test_hash16(self):
        self.run_group(t.S_H16, 80, 3)

    def test_hash16_is_not_hash20(self):
        key = bytes(range(16))
        o16, _ = t.run_hash(self.img, self.code, t.S_H16, 9, 8, key)
        o20, _ = t.run_hash(self.img, self.code, t.S_H20, 9, 8, key + bytes(4))
        self.assertNotEqual(o16[2], o20[2])

    def test_edge_keys(self):
        for k0, k1 in ((0, 0), (t.U64, t.U64), (1 << 63, 1)):
            o, _ = t.run_hash(self.img, self.code, t.S_H20, k0, k1, b'\xff' * 20)
            self.assertEqual(o[2], t.siphash(k0, k1, b'\xff' * 20))

class TestProbes(Base):
    def run_group(self, fn, count, step):
        done = 0
        for k, (group, f, payload) in enumerate(t.case_stream()):
            if f != fn or k % step:
                continue
            o = self.obs(f, payload)
            self.assertTrue(t.agree(f, o, t.expected(f, payload)), (group, k))
            done += 1
            if done >= count:
                break
        self.assertGreaterEqual(done, min(count, 20))

    def test_find_a(self):
        self.run_group(t.S_FA, 120, 5)

    def test_find_b(self):
        self.run_group(t.S_FB, 120, 5)

    def test_has_a(self):
        self.run_group(t.S_UA, 100, 5)

    def test_has_b(self):
        self.run_group(t.S_UB, 100, 5)

    def hand_case(self, fn):
        klen = t.SHAPES[fn][2]
        key = bytes(range(1, klen + 1))
        h = 0x21 << 57 | 5
        tb = t.RawTable(8)
        tb.insert(h, 0)
        return tb, [key], key, h

    def test_hand_found_everywhere(self):
        for fn in t.SHAPES:
            case = self.hand_case(fn)
            o, _ = t.run_find(self.img, self.code, fn, case)
            self.assertEqual(o[0], 'ok')
            self.assertEqual(o[2], 5 if fn in (t.S_FA, t.S_FB) else 1)

    def test_hand_wrong_tag_misses(self):
        for fn in t.SHAPES:
            tb, keys, q, h = self.hand_case(fn)
            o, _ = t.run_find(self.img, self.code, fn, (tb, keys, q, h ^ (1 << 57)))
            self.assertEqual(o[2], None if fn in (t.S_FA, t.S_FB) else 0)

    def test_hand_last_key_byte_matters(self):
        for fn in t.SHAPES:
            tb, keys, q, h = self.hand_case(fn)
            bad = q[:-1] + bytes([q[-1] ^ 0x40])
            o, _ = t.run_find(self.img, self.code, fn, (tb, keys, bad, h))
            self.assertEqual(o[2], None if fn in (t.S_FA, t.S_FB) else 0)

    def test_bounds_panic_location(self):
        for fn in t.SHAPES:
            tb, keys, q, h = self.hand_case(fn)
            tb.vals[5] = 7
            o, _ = t.run_find(self.img, self.code, fn, (tb, keys, q, h))
            self.assertEqual(o[:2], ('panic', t.LOC_BOUNDS_FIND))

    def test_second_group_probe(self):
        # 20 entries with one probe start: 16 sit in the first group, the rest in later groups
        rng = t.Rng(5)
        tb = t.RawTable(32)
        keys, hs = [], []
        for i in range(20):
            keys.append(rng.bytes(20))
            hs.append(0x33 << 57 | 2)
            tb.insert(hs[-1], i)
        for i in (0, 15, 16, 19):
            o, _ = t.run_find(self.img, self.code, t.S_FA, (tb, keys, keys[i], hs[i]))
            self.assertEqual(t.model_probe(t.S_FA, (tb, keys, keys[i], hs[i])), ('ok', o[2]))
            self.assertIsNotNone(o[2])

    def test_tombstone_group_continues(self):
        tb = t.RawTable(32)
        keys = [bytes([i + 1]) * 20 for i in range(3)]
        for i in range(3):
            tb.insert(0x41 << 57 | 1, i)
        for j in range(32):
            if tb.ctrl[j] == 0x41:
                tb.set_ctrl(j, t.DELETED)
        o, _ = t.run_find(self.img, self.code, t.S_FA, (tb, keys, keys[0], 0x41 << 57 | 1))
        self.assertIsNone(o[2])


class TestEntry(Base):
    def test_occupied_returns_row_address(self):
        for idx in range(4):
            o, _ = t.run_entry(self.img, self.code, ('occupied', idx, 4))
            self.assertEqual(o, ('ok', None, idx))

    def test_occupied_out_of_range_panics(self):
        o, _ = t.run_entry(self.img, self.code, ('occupied', 4, 4))
        self.assertEqual(o[:2], ('panic', t.LOC_BOUNDS_ENTRY))

    def test_vacant_arm_passes_its_arguments(self):
        o, _ = t.run_entry(self.img, self.code, ('vacant', 2, 5))
        self.assertEqual(o, ('ok', None, 2))

    def test_vacant_out_of_range_panics(self):
        o, _ = t.run_entry(self.img, self.code, ('vacant', 6, 5))
        self.assertEqual(o[:2], ('panic', t.LOC_BOUNDS_ENTRY))


class TestControls(Base):
    def test_control_slice_is_deep_enough(self):
        self.assertGreaterEqual(len(self.ctl), 400)

    def test_inverted_condition_is_caught(self):
        lo, hi = self.extents[t.S_FA]
        jcc = next(self.code[v] for v in sorted(self.code) if lo <= v < hi and self.code[v].op == 'jb')
        patch = t.cond_patch(jcc)
        img = t.Image(self.data, patch)
        fresh = t.decode_range(img, lo, hi)
        c2 = {v: i for v, i in self.code.items() if not lo <= v < hi}
        c2.update({i.va: i for i in fresh})
        self.assertIsNotNone(t.detects(img, c2, self.ctl, {t.S_FA}))

    def test_clean_image_is_not_flagged(self):
        self.assertIsNone(t.detects(self.img, self.code, self.ctl, {t.S_FA, t.S_H20, t.S_ENTRY}))

    def test_wrong_models_are_caught(self):
        for name, fn, variant in t.wrong_models():
            caught = False
            for f, payload in self.ctl:
                if f != fn:
                    continue
                o = self.obs(f, payload)
                if not t.agree(f, o, t.expected(f, payload, variant)):
                    caught = True
                    break
            self.assertTrue(caught, name)

    def test_selfcheck_refuses_patched_shift(self):
        with self.assertRaises(t.EvidenceError):
            t.selfcheck(t.Image(self.data, {0x47174c1: 0x38 ^ 1}), self.fdes)
        with self.assertRaises(t.EvidenceError):
            t.selfcheck(t.Image(self.data, {0x3ee628a: 0x39 ^ 1}), self.fdes)

    def test_constant_patch_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.constants_check(t.Image(self.data, {t.S_H20 + 9: 0x75 ^ 1}))

    def test_mutant_list_size(self):
        self.assertGreaterEqual(len(t.mutant_list(self.code, self.extents)), 70)

    def test_garbage_after_buffers(self):
        self.assertEqual(len(t.PAD), 40)
        self.assertEqual(len(set(t.PAD)), 40)


class TestEvidenceFiles(unittest.TestCase):
    def test_measure_matches_controls_and_evidence(self):
        m = json.loads((WORK / 'measure.json').read_text())
        ev = json.loads((WORK / 'evidence.json').read_text())
        self.assertEqual(m['cases'], ev['vectors'])
        self.assertEqual(m['negative_controls'], m['negative_detected'])
        rows = (WORK / 'controls.tsv').read_text().splitlines()[1:]
        self.assertEqual(sum(1 for r in rows if r.split('\t')[2] == 'detected'), m['negative_detected'])
        self.assertFalse([r for r in rows if 'MISSED' in r])
        self.assertGreaterEqual(m['cases'], 10000)
        self.assertGreaterEqual(m['negative_controls'], 30)

    def test_kept_rows_are_a_sample_of_the_digest_input(self):
        rows = (WORK / 'vectors.tsv').read_text().splitlines()[1:]
        idx = [int(r.split('\t')[0]) for r in rows]
        self.assertEqual(idx, sorted(idx))
        self.assertTrue(all(i % 9 in (0, 3, 6) for i in idx))

    def test_manifest_hashes(self):
        for line in (WORK / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_unexecuted_are_panic_or_padding(self):
        ev = json.loads((WORK / 'evidence.json').read_text())
        self.assertEqual(len(ev['unexecuted']), 27)
        self.assertEqual(ev['callee_not_claimed']['write'], ['0x45927a0', '0x4592977'])


if __name__ == '__main__':
    unittest.main()
