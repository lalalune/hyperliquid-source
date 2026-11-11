import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_state_serializer_115 as ser  # noqa: E402
import fde_extents  # noqa: E402

PACKET = ROOT / 'research/work-items/bridge-state-serializer-115'
DATA = ser.TARGET.read_bytes()
IMAGE = ser.B.Image(DATA)
_, RECS, _ = fde_extents.fde_extents(DATA)
BY_START = {r['start']: r for r in RECS}
BODIES = ser.load_bodies(IMAGE, BY_START)
INLINE = ser.inline_map(BODIES)
ROOT_COPY, SECOND, THIRD = ser.COPIES
PTR = 0x4000_0000


def make(ring, flag_seed=3):
    rng = ser.random.Random(flag_seed)
    st = ser.make_state(rng, 'unit')
    ser.set_ring(st, *ring)
    return st, bytes(rng.getrandbits(8) for _ in range(ser.SER_SIZE))


def both(copy, flag, ring, k=-1, sh=None):
    st, sb = make(ring)
    eng = ser.engine_case(IMAGE, BODIES, copy, flag, st, sb, k, sh)
    return eng, ser.model_case(flag, st, k, sh, INLINE[copy]), st


class RingDescriptor(unittest.TestCase):
    def test_wrapped_ring_two_slices(self):
        w = ser.ring_words(6, PTR, 8, 5)
        self.assertEqual(w, [2, PTR + 2 * 0x68, PTR + 6 * 0x68, PTR, PTR + 0x68, 0, PTR + 6 * 0x68, PTR, 1])

    def test_contiguous_ring_has_empty_second_slice(self):
        w = ser.ring_words(2, PTR, 8, 5)
        # first slice runs to the end of the buffer (6 slots), the whole length fits in it
        self.assertEqual(w[8], 0)
        self.assertEqual(w[1], PTR + 6 * 0x68)
        self.assertEqual(w[2], PTR + 11 * 0x68)

    def test_empty_ring_is_all_base(self):
        self.assertEqual(ser.ring_words(3, PTR, 8, 0), [2, PTR, PTR, PTR, PTR, 0, PTR, PTR, 0])

    def test_niche_forms(self):
        self.assertEqual(ser.ring_words(ser.ERR_NICHE, 0, 5, 9), [0, 0, 0, 5, 0, 0, 0, 5, 0])
        self.assertEqual(ser.ring_words(ser.ERR_NICHE, 7, 5, 9), [1, 0, 7, 5, 1, 0, 7, 5, 9])

    def test_head_above_capacity_takes_whole_capacity(self):
        w = ser.ring_words(12, PTR, 8, 3)
        self.assertEqual(w[1], PTR + 8 * 0x68)

    def test_matches_machine_code(self):
        for ring in [(r[1], r[2], r[3], r[4]) for r in ser.RING_FIXED]:
            for copy in ser.COPIES:
                (ev, out, _), (mev, mout), _ = both(copy, 2, ring)
                self.assertEqual(ev, mev, ring)
                self.assertEqual(out, mout)


class CleanRun(unittest.TestCase):
    def test_named_flag_writes_five_keys_in_order(self):
        (ev, out, steps), _, st = both(ROOT_COPY, 1, (5, PTR, 8, 3))
        self.assertEqual([e[2] for e in ev if e[0] == 'key'], list(ser.KEYS))
        self.assertEqual(out, (ser.OK_MARK, ser.CANARY[1], ser.CANARY[2]))
        self.assertEqual(len(ev), 21)
        self.assertGreater(steps, 100)

    def test_unnamed_flags_write_no_keys(self):
        for flag in (0, 2, 0xff):
            (ev, out, _), model, _ = both(ROOT_COPY, flag, (5, PTR, 8, 3))
            self.assertFalse([e for e in ev if e[0] == 'key'])
            self.assertEqual(len(ev), 16)
            self.assertEqual((ev, out), model)

    def test_header_arm_follows_flag_zero(self):
        (ev0, _, _), _, _ = both(ROOT_COPY, 0, (5, PTR, 8, 3))
        (ev1, _, _), _, _ = both(ROOT_COPY, 1, (5, PTR, 8, 3))
        self.assertEqual(ev0[0][0], 'begin0')
        self.assertEqual(ev1[0][0], 'begin1')
        self.assertEqual(ev0[0][3], 0xf)

    def test_scalar_members_read_state_words(self):
        (ev, _, _), _, st = both(ROOT_COPY, 0, (5, PTR, 8, 3))
        by = {e[0]: e for e in ev}
        self.assertEqual(by['f64'][-1], st[0x1c0])
        self.assertEqual(by['bal'][-1], st[0x1c8])
        self.assertEqual(by['pruned'][-1], st[0x1d0])
        self.assertEqual(by['oaw'][-1], st[0x1e4])
        self.assertLess(st[0x1e4], 1 << 32)

    def test_copy_variants_detected_from_bytes(self):
        self.assertEqual(INLINE, {ROOT_COPY: (False, False), SECOND: (True, True), THIRD: (True, False)})

    def test_second_copy_f64_uses_result_buffer(self):
        (ev, _, _), _, st = both(SECOND, 0, (5, PTR, 8, 3))
        f64 = [e for e in ev if e[0] == 'f64'][0]
        self.assertEqual(f64[1], ser.FRAME)
        self.assertEqual(f64[3], st[0x1c0])

    def test_pruned_name_inline_in_second_and_third_copy(self):
        for copy in (SECOND, THIRD):
            (ev, _, _), _, _ = both(copy, 1, (5, PTR, 8, 3))
            pruned = [e for e in ev if e[0] == 'pruned'][0]
            self.assertEqual(len(pruned), 4)
        (ev, _, _), _, _ = both(ROOT_COPY, 1, (5, PTR, 8, 3))
        pruned = [e for e in ev if e[0] == 'pruned'][0]
        self.assertEqual(pruned[3], b'last_pruned_deposit_block_number')


class ErrorExits(unittest.TestCase):
    def test_header_error_is_wrapped(self):
        (ev, out, _), (mev, mout), _ = both(ROOT_COPY, 1, (5, PTR, 8, 3), 0, 2)
        self.assertEqual(out, (ser.ERR_NICHE, 3, 0x5555))
        self.assertEqual((ev, out), (mev, mout))

    def test_key_error_is_wrapped_with_rax_rdx(self):
        sh = 3
        (ev, out, _), _, _ = both(ROOT_COPY, 1, (5, PTR, 8, 3), 1, sh)
        self.assertEqual(ev[-1][0], 'key')
        self.assertEqual(out, (ser.ERR_NICHE, ser.MASK, 0x7777))

    def test_member_error_is_copied(self):
        (ev, out, _), _, _ = both(ROOT_COPY, 1, (5, PTR, 8, 3), 2, 0)
        self.assertEqual(ev[-1][0], 'eth')
        self.assertEqual(out, ser.FAIL_SHAPES[0])

    def test_near_ok_marker_is_still_an_error(self):
        near = ser.FAIL_SHAPES.index((ser.OK_MARK + 1, 0xdddd, 0xeeee))
        (ev, out, _), model, _ = both(ROOT_COPY, 0, (5, PTR, 8, 3), 3, near)
        self.assertEqual(out[0], ser.OK_MARK + 1)
        self.assertEqual((ev, out), model)

    def test_nothing_runs_after_failure(self):
        for k in range(0, 21):
            roles = ser.role_list(1, INLINE[ROOT_COPY])
            poss = ser.possible_shapes(roles[k], INLINE[ROOT_COPY])
            (ev, out, _), model, _ = both(ROOT_COPY, 1, (5, PTR, 8, 3), k, poss[0])
            self.assertEqual(len(ev), k + 1)
            self.assertEqual((ev, out), model)


class Sweep(unittest.TestCase):
    def test_every_97th_case_matches_the_machine_code(self):
        n = 0
        for idx, copy, flag, ring, k, sh, st, sb in ser.case_stream(INLINE, every=97):
            eng = ser.engine_case(IMAGE, BODIES, copy, flag, st, sb, k, sh)[:2]
            self.assertEqual(eng, ser.model_case(flag, st, k, sh, INLINE[copy]), (idx, copy, flag, ring[0], k))
            n += 1
        self.assertGreater(n, 150)

    def test_stream_is_deterministic_and_large(self):
        a = [c[0] for c in ser.case_stream(INLINE, every=211)]
        b = [c[0] for c in ser.case_stream(INLINE, every=211)]
        self.assertEqual(a, b)
        self.assertGreater(len(list(ser.case_stream(INLINE, every=1))), 10000)


class NegativeControls(unittest.TestCase):
    def _subset(self):
        out = []
        for idx, copy, flag, ring, k, sh, st, sb in ser.case_stream(INLINE, every=53):
            ev, o, _ = ser.engine_case(IMAGE, BODIES, copy, flag, st, sb, k, sh)
            out.append(((flag, st, k, sh, INLINE[copy]), (ev, o)))
        return out

    def test_wrong_reconstructions_are_caught(self):
        subset = self._subset()
        for name, knobs in ser.MUTANTS:
            bad = 0
            with ser.Knobs(**knobs):
                for (flag, st, k, sh, inl), (ev, o) in subset:
                    if ser.model_case(flag, st, k, sh, inl) != (ev, o):
                        bad += 1
            self.assertGreater(bad, 0, name)

    def test_defaults_restored_after_knobs(self):
        with ser.Knobs(elem=1):
            self.assertEqual(ser.KNOBS['elem'], 1)
        self.assertEqual(ser.KNOBS['elem'], 0x68)

    def test_corrupted_displacement_is_caught(self):
        rows = BODIES[ROOT_COPY][1]
        sites = ser.find_patch_sites(rows, ROOT_COPY)
        self.assertEqual(len(sites), 10)
        for name, (va, val) in sorted(sites.items()):
            pimg = ser.PatchedImage(DATA, {va: val})
            bad = 0
            for idx, copy, flag, ring, k, sh, st, sb in ser.case_stream(INLINE, every=211):
                if copy != ROOT_COPY:
                    continue
                try:
                    ev, o, _ = ser.engine_case(pimg, BODIES, copy, flag, st, sb, k, sh)
                except ser.Reject:
                    bad += 1
                    continue
                if ser.model_case(flag, st, k, sh, INLINE[copy]) != (ev, o):
                    bad += 1
            self.assertGreater(bad, 0, name)

    def test_wrong_digest_rejected(self):
        with self.assertRaises(ser.Reject):
            ser.check_sha(bytes([DATA[0] ^ 1]) + DATA[1:])

    def test_non_fde_start_rejected(self):
        with self.assertRaises(ser.Reject):
            ser.load_bodies(IMAGE, BY_START, (ROOT_COPY + 1,))

    def test_truncated_body_rejected(self):
        short = dict(BY_START)
        short[ROOT_COPY] = dict(BY_START[ROOT_COPY], end=ROOT_COPY + 0x200)
        with self.assertRaises(ser.Reject):
            ser.load_bodies(IMAGE, short, (ROOT_COPY,))

    def test_missing_callee_stub_rejected(self):
        st, sb = make((5, PTR, 8, 3))
        roles = dict(BODIES[ROOT_COPY][2])
        roles.pop(next(iter(roles)))
        with self.assertRaises(ser.Reject):
            ser.execute(IMAGE, ROOT_COPY, roles, 1, st, sb, -1, (0, 0, 0))

    def test_step_limit_rejected(self):
        st, sb = make((5, PTR, 8, 3))
        with self.assertRaises(ser.Reject):
            ser.execute(IMAGE, ROOT_COPY, BODIES[ROOT_COPY][2], 1, st, sb, -1, (0, 0, 0), limit=40)

    def test_unsupported_instruction_rejected(self):
        with self.assertRaises(ser.Reject):
            ser.decode(IMAGE, 0x5fe820)


class Evidence(unittest.TestCase):
    def test_generated_files_match_the_tool(self):
        result = ser.build(DATA)
        files = ser.render(result)
        for name, text in files.items():
            self.assertEqual((PACKET / name).read_text(encoding='ascii'), text, name)
        summary = json.loads(files['summary.json'])
        self.assertEqual(summary['cases'], summary['matches'])
        self.assertGreaterEqual(summary['cases'], 10000)
        self.assertGreaterEqual(summary['negative_controls'], 30)
        self.assertEqual(summary['negative_controls'], summary['negative_detected'])
        self.assertEqual(json.loads(files['measure.json'])['cases'], summary['cases'])

    def test_manifest_hashes(self):
        lines = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        names = set()
        for line in lines:
            digest, name = line.split('  ')
            names.add(name)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        self.assertNotIn('MANIFEST.sha256', names)
        self.assertEqual(names, {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})


if __name__ == '__main__':
    unittest.main()
