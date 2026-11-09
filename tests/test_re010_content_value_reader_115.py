import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_content_value_reader_115 as T  # noqa: E402


class ContentValueReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = T.BINARY.read_bytes()
        cls.img = T.Image(cls.data)
        cls.fns = T.load_fns(cls.img)
        cls.prim = T.Prim(cls.img)

    def run_one(self, kind, buf, peek=None, copy=0, **kw):
        m = T.Machine(self.img, self.fns[kind][copy], self.prim)
        c = T.case(buf, peek, kw.pop('depth', 5), **kw)
        got = m.run(c)
        want = T.reconstructed(kind, c, None, self.fns[kind][copy].eof)
        self.assertEqual(got, want)
        return got

    # identity and layout --------------------------------------------------------
    def test_digest_is_checked(self):
        bad = bytearray(self.data)
        bad[1000] ^= 1
        with self.assertRaises(ValueError):
            T.Image(bytes(bad))

    def test_function_extents_and_copies(self):
        for kind, k in T.KINDS.items():
            self.assertEqual([f.start for f in self.fns[kind]], list(k['funcs']))
            for f in self.fns[kind]:
                self.assertEqual(f.end - f.start, k['size'])
                self.assertTrue(f.lsda)
        self.assertEqual(self.prim.end - self.prim.start, 665)

    def test_call_roles_are_shared_by_copies(self):
        for kind in T.KINDS:
            anchor = self.fns[kind][0]
            for f in self.fns[kind][1:]:
                shifted = {f.start + va - anchor.start: r for va, r in anchor.role.items()}
                self.assertEqual(shifted, f.role)
        roles = set(self.fns['vr'][0].role.values())
        self.assertTrue({'prim', 'map', 'seq', 'ext', 'from_utf8', 'alloc', 'panic_add', 'panic_sub',
                         'drop_content', 'drop_result', 'drop_ext', 'resume', 'terminate'} <= roles)

    def test_jump_tables_stay_inside_the_function(self):
        for f in self.fns['vr']:
            rows = f.table_rows(self.img)
            self.assertEqual(sum(1 for r in rows if r[0] == 'marker'), 225)
            self.assertEqual(sum(1 for r in rows if r[0] == 'ext'), 18)
            self.assertTrue(all(0 <= arm < T.KINDS['vr']['size'] for _, _, arm in rows))
        a = {(n, i): arm for n, i, arm in self.fns['vr'][0].table_rows(self.img)}
        for f in self.fns['vr'][1:]:
            self.assertEqual(a, {(n, i): arm for n, i, arm in f.table_rows(self.img)})

    def test_lsda_pads_exist_only_for_the_panic_sites(self):
        anchor = self.fns['vr'][0]
        pads = [(s - anchor.start, lp - anchor.start) for s, e, lp, a in anchor.sites if lp and a == 0]
        self.assertEqual(len(pads), 6)

    # behaviour of the original bytes, stated without the model --------------------
    def test_scalars(self):
        got = self.run_one('vr', b'\xce\x01\x02\x03\x04')
        self.assertEqual(got[1][8], 3)
        self.assertEqual(struct.unpack_from('<I', got[1], 0xc)[0], 0x01020304)
        got = self.run_one('vr', b'\xd0\xff')
        self.assertEqual((got[1][8], got[1][9]), (5, 0xff))
        got = self.run_one('vr', b'\xcb' + struct.pack('>d', 1.5))
        self.assertEqual(got[1][8], 0xa)
        self.assertEqual(struct.unpack_from('<d', got[1], 0x10)[0], 1.5)
        got = self.run_one('vr', b'\xc0')
        self.assertEqual(got[1][8], 0x12)
        got = self.run_one('vr', b'\xc3')
        self.assertEqual((got[1][8], got[1][9]), (0, 1))
        got = self.run_one('vr', b'\x7f')
        self.assertEqual((got[1][8], got[1][9]), (1, 0x7f))
        got = self.run_one('vr', b'\xe0')
        self.assertEqual((got[1][8], got[1][9]), (5, 0xe0))

    def test_strings_and_bin(self):
        got = self.run_one('vr', b'\xa3abc')
        self.assertEqual(got[1][8], 0xd)
        self.assertEqual(struct.unpack_from('<QQ', got[1], 0x10), (T.IN_BASE + 1, 3))
        self.assertEqual(got[3][:2], (4, 0))
        got = self.run_one('vr', b'\xa3\xff\xfe\xfd')
        self.assertEqual(got[1][8], 0xf)   # invalid UTF-8 is handed over as bytes
        got = self.run_one('vr', b'\xc4\x02ab')
        self.assertEqual(got[1][8], 0xf)
        self.assertEqual(struct.unpack_from('<QQ', got[1], 0x10), (T.IN_BASE + 2, 2))
        got = self.run_one('vr', b'\xa5ab')
        self.assertEqual((got[1][0], got[1][8]), (1, 1))
        self.assertEqual(struct.unpack_from('<Q', got[1], 0x10)[0], T.EOF_SHORT)
        self.assertEqual(got[3][:2], (1, 2))   # nothing consumed after the marker

    def test_eof_forms(self):
        got = self.run_one('vr', b'')
        self.assertEqual((got[1][0], got[1][8]), (1, 0))
        got = self.run_one('vr', b'\xd2\x01')
        self.assertEqual((got[1][0], got[1][8]), (1, 1))
        self.assertEqual(got[3][:2], (2, 0))   # a short fixed read consumes the rest
        got = self.run_one('vr', b'\xc1')
        self.assertEqual(tuple(got[1][8:10]), (2, 0xc1))

    def test_peeked_marker_is_used_and_cleared(self):
        got = self.run_one('vr', b'', (0, 9))
        self.assertEqual((got[1][8], got[1][9]), (1, 9))
        self.assertEqual(got[3][2], 1)
        got = self.run_one('vr', b'', (0xe1 - 1, 0))   # disc 0xe0 (negative fixint) is the last table entry
        self.assertEqual(got[1][8], 5)
        got = self.run_one('vr', b'', (0x21, 0))
        self.assertEqual(got[0], 'ud2')

    def test_depth_budget(self):
        got = self.run_one('vr', b'\x91\x01', depth=1)
        self.assertEqual((got[1][0], got[1][8]), (1, 8))
        self.assertEqual(got[3][4], 0)
        got = self.run_one('vr', b'\x91\x01', depth=0)
        self.assertEqual(got[0], 'escape')
        self.assertEqual(got[2][0][0], 'panic_sub')
        got = self.run_one('vr', b'\x91\x01', depth=7, visit=('ok', 0, 0x14))
        self.assertEqual(got[3][4], 7)   # restored after a successful collector

    def test_collector_leftover_is_a_length_mismatch(self):
        got = self.run_one('vr', b'\x93', depth=4, visit=('ok', 1, 0x14))
        self.assertEqual((got[1][0], got[1][8]), (1, 4))
        self.assertEqual(struct.unpack_from('<I', got[1], 0xc)[0], 2)
        self.assertEqual([c[0] for c in got[2]], ['seq', 'drop_content'])
        got = self.run_one('vr', b'\x91', depth=4, visit=('ok', 3, 0x14))
        self.assertEqual(got[0], 'resume')   # the leftover exceeds the count: the subtraction panics into the drop pad
        self.assertEqual([c[0] for c in got[2]], ['seq', 'panic_sub', 'drop_content', 'resume'])

    def test_ext_is_boxed_as_newtype(self):
        got = self.run_one('vr', b'\xd4\x01\x02', depth=4)
        self.assertEqual((got[1][0], got[1][8]), (0, 0x13))
        self.assertEqual(got[2][0][:2], ('ext', 'sp+8'))
        self.assertEqual(got[2][0][3], 1)
        self.assertEqual(len(self.run_one('vr', b'\xc7\x02xyz', depth=4)[4]), 1)   # one boxed block
        got = self.run_one('vr', b'\xc7\x02xyz', depth=4, alloc_ok=False)
        self.assertEqual(got[0], 'resume')   # alloc_error unwinds into the drop pad

    def test_ext_visitor_pair(self):
        got = self.run_one('ext', b'\x05abc', n=3, state=0, depth=0)
        self.assertEqual(got[1][8], 0x14)
        self.assertEqual(struct.unpack_from('<QQQ', got[1], 0x10)[2], 2)
        self.assertEqual(got[3][:2], (4, 0))
        self.assertEqual(got[3][6], 2)
        got = self.run_one('ext', b'', n=0, state=0, depth=0)
        self.assertEqual(got[1][8], 1)
        got = self.run_one('ext', b'\x01', n=0, state=3, depth=0)
        self.assertEqual(got[1][8], 3)

    def test_bytes_visitor(self):
        for copy in (0, 1):
            m = T.Machine(self.img, self.fns['bytes'][copy], self.prim)
            c = T.case(b'\x01\x02\x03', None, 0, slice=(T.IN_BASE, T.IN_BASE + 3, 0))
            got = m.run(c)
            self.assertEqual(got, T.reconstructed('bytes', c))
            self.assertEqual(struct.unpack_from('<QQQ', got[1], 0x10)[2], 3)
            c = T.case(b'\x01', None, 0, slice=(T.IN_BASE, T.IN_BASE + 1, 2 ** 64 - 1))
            self.assertEqual(m.run(c)[0], 'resume')   # counter overflow panics before the first element

    # the whole case sets ----------------------------------------------------------
    def test_models_match_every_copy(self):
        for kind in T.KINDS:
            for ci, fn in enumerate(self.fns[kind]):
                cases = [c for j, c in enumerate(T.GENS[kind](ci)) if j % 4 == 0]
                self.assertGreater(len(cases), 50)
                self.assertEqual(T.compare(self.img, fn, self.prim, cases), 0, (kind, hex(fn.start)))

    def test_all_input_classes_are_present(self):
        ks = list(T.vr_cases(0))
        self.assertGreater(len(ks), 10000)
        self.assertEqual({c['buf'][0] for c in ks if c['peek'] is None and c['buf']} >= set(range(256)), True)
        self.assertEqual({c['peek'][0] for c in ks if c['peek']}, set(range(0xe1)))

    # negative controls --------------------------------------------------------------
    def test_wrong_models_are_rejected(self):
        for kind, variants in (('vr', T.VR_VARIANTS), ('ext', T.EXT_VARIANTS), ('bytes', T.BYTES_VARIANTS)):
            sample = [c for j, c in enumerate(T.GENS[kind](0)) if j % 5 == 0]
            for v in variants:
                self.assertTrue(T.compare(self.img, self.fns[kind][0], self.prim, sample, variant=v, limit=1), v)

    def test_corrupted_images_are_rejected(self):
        for kind, offs in T.IMAGE_MUTANTS:
            fn = self.fns[kind][0]
            sample = [c for j, c in enumerate(T.GENS[kind](0)) if j % 3 == 0][:1200]
            for off in offs[::6]:
                self.assertTrue(T.run_mutant(self.img, fn, self.prim, kind, off, sample), (kind, off))

    def test_range_controls(self):
        res = T.range_controls(self.img, self.fns, self.prim)
        self.assertGreaterEqual(len(res), 10)
        self.assertTrue(all(ok for _, ok in res), res)

    def test_true_model_is_not_rejected_by_the_control_runner(self):
        fn = self.fns['ext'][0]
        sample = [c for j, c in enumerate(T.GENS['ext'](0)) if j % 5 == 0]
        self.assertEqual(T.compare(self.img, fn, self.prim, sample, variant=None, limit=1), 0)

    def test_machine_rejects_unknown_code(self):
        m = T.Machine(self.img, self.fns['vr'][0], self.prim)
        m.cache.pop(self.fns['vr'][0].insns[8].va)
        with self.assertRaises(T.Fault):
            m.run(T.case(b'\x05'))


if __name__ == '__main__':
    unittest.main()
