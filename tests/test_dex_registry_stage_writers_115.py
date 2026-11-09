import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import dex_registry_stage_writers_115 as tool  # noqa: E402
import fde_extents  # noqa: E402

FOLDER = ROOT / 'research/work-items/dex-registry-stage-writers-115'


class Fixture:
    data = None
    image = None
    by_start = None
    rows = None


def load_fixture():
    cls = Fixture
    if cls.data is None:
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        _, recs, _ = fde_extents.fde_extents(cls.data)
        cls.by_start = dict((r['start'], r) for r in recs)
        tool.derive_stage(cls.image, cls.by_start)
        cls.rows = list(tool.gen_cases())
    return cls


class StageWriterTests(unittest.TestCase):
    def setUp(self):
        self.fx = load_fixture()

    def sample(self, fam, count, step=1):
        out = []
        for n, row in enumerate(r for r in self.fx.rows if r[0] == fam):
            if n % step == 0:
                out.append(row)
                if len(out) >= count:
                    break
        return out

    def check_rows(self, rows, bad=None):
        cover = set()
        for fam, ci, case in rows:
            got, exp, _ = tool.run_case(self.fx.image, cover, ci, case, bad)
            self.assertIsNone(tool.compare2(got, exp), (fam, ci, case))

    def test_every_body_decodes_to_its_unwind_extent(self):
        total = 0
        for cp in tool.COPIES:
            for key in tool.BODY_KEYS:
                ent = cp[key]
                rows = tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'])
                self.assertGreater(len(rows), 20)
                total += len(rows)
        self.assertEqual(total, 5632)

    def test_roles_follow_call_order(self):
        c1, c2, c3 = tool.COPIES
        self.assertEqual((c1['key'], c1['val'], c1['end'], c1['elem']), (0x2296160, 0x2296fa0, 0x22999e0, 0x22927f0))
        self.assertEqual((c1['uint'], c1['binhdr'], c1['tup'], c1['variant'], c1['setw']),
                         (0x25e9f10, 0x25e80c0, 0x2299050, 0x2bc7610, 0x2228ba0))
        self.assertEqual((c3['key'], c3['val']), (0x53206b0, 0x5320130))
        self.assertEqual((c2['uint'], c2['tup']), (0x3d51450, 0x41d3d00))
        self.assertEqual(c3['setw'], 0x52808c0)

    def test_unsigned_integer_wire_table(self):
        table = ((0, b'\x00'), (0x7f, b'\x7f'), (0x80, b'\xcc\x80'), (0xff, b'\xcc\xff'), (0x100, b'\xcd\x01\x00'),
                 (0xffff, b'\xcd\xff\xff'), (0x10000, b'\xce\x00\x01\x00\x00'),
                 (0xffffffff, b'\xce\xff\xff\xff\xff'), (1 << 32, b'\xcf\x00\x00\x00\x01\x00\x00\x00\x00'))
        for v, wire in table:
            vec = tool.Vec(64, b'')
            tool.m_uint(vec, v, [])
            self.assertEqual(bytes(vec.buf), wire)
        for ci in range(3):
            for v, wire in table:
                case = dict(fam='uint', mode='real', seed=1, value=v, writer=(64, b'', 0, 0, 0))
                got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
                self.assertEqual(got['data'], wire)
                self.assertIsNone(tool.compare2(got, exp))

    def test_binary_header_wire_table(self):
        table = ((0, b'\xc4\x00'), (255, b'\xc4\xff'), (256, b'\xc5\x01\x00'), (0xffff, b'\xc5\xff\xff'),
                 (0x10000, b'\xc6\x00\x01\x00\x00'))
        for ci in range(3):
            for n, wire in table:
                case = dict(fam='binhdr', mode='real', seed=1, value=n, writer=(64, b'', 0, 0, 0))
                got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
                self.assertEqual(got['data'], wire)

    def test_buffered_key_flushes_header_bytes_and_free(self):
        for ci in range(3):
            st = dict(cap=8, buf=bytes([1, 0x90]), hint=2)
            case = dict(fam='key', mode='real', seed=1, value=300, writer=(64, b'', 0, 0, 0), state=st)
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertEqual(got['data'], b'\x92\x01\xcc\x90\xcd\x01\x2c')
            self.assertEqual(got['log'], [('dealloc', 8)])
            self.assertEqual(got['stcap'], tool.NICHE)
            self.assertIsNone(tool.compare2(got, exp))

    def test_end_stage_picks_array_or_binary_header(self):
        for ci in range(3):
            for buf, hint, wire in ((b'\x01\x02', 2, b'\x92\x01\x02'), (b'\x01\x80', 2, b'\xc4\x02\x01\x80'),
                                    (b'\x01\x02', 16, b'\xc4\x10\x01\x02')):
                st = dict(cap=4, buf=buf, hint=hint)
                case = dict(fam='end', mode='real', seed=1, writer=(64, b'', 0, 0, 0), state=st)
                got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
                self.assertEqual(got['data'], wire)
                self.assertEqual(got['log'], [('memcpy', 2), ('dealloc', 4)])
                self.assertIsNone(tool.compare2(got, exp))

    def test_map_entries_are_pairs_of_integers(self):
        for ci in range(3):
            case = dict(fam='map', kind='map', mode='real', seed=5, iter=('slices', 2, 1), writer=(64, b'', 1, 0, 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertIsNone(tool.compare2(got, exp))
            self.assertEqual(got['data'][:2], b'\x93\x92')
            self.assertEqual(got['out'][0], tool.OK_WORD)

    def test_integer_writer_matches_reconstruction(self):
        self.check_rows(self.sample('uint', 200, 3) + self.sample('binhdr', 100, 3))

    def test_key_value_tuple_end_match_reconstruction(self):
        rows = self.sample('key', 80, 3) + self.sample('val', 80, 3) + self.sample('tup', 100, 3) + \
            self.sample('end', 120, 3)
        self.check_rows(rows)

    def test_element_writer_and_loops_match_reconstruction(self):
        self.check_rows(self.sample('elem', 150, 3) + self.sample('map', 100, 5) + self.sample('seq', 100, 5))

    def test_wire_decoder_reads_arrays_and_integers(self):
        self.assertEqual(tool.decode_wire(bytes([0x92, 0x05, 0xcc, 0x90])), [5, 0x90])
        self.assertEqual(tool.decode_wire(b'\x91\xcd\x01\x00'), [256])
        self.assertEqual(tool.decode_wire(b'\xdc\x00\x11' + b'\x01' * 17), [1] * 17)
        for bad in (b'\xc1', b'\x92\x01', b'\x01\x02'):
            with self.assertRaises((ValueError, IndexError)):
                tool.decode_wire(bad)

    def test_map_output_decodes_to_the_given_pairs(self):
        for ci in range(3):
            case = dict(fam='map', mode='real', seed=9, iter=('slices', 3, 2), writer=(0, b'', 2, 0, 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertIsNone(tool.compare2(got, exp))
            self.assertEqual(len(got['sem']), 5)
            self.assertTrue(all(len(pair) == 2 for pair in got['sem']))
            self.assertEqual(got['sem'], exp['sem'])

    def test_wrapper_feeds_the_element_loop(self):
        for ci in range(3):
            ring = dict(fam='wseq', seed=3, mode='real', writer=(0, b'', 1, 0, 0),
                        container=dict(kind='ring', cap=4, head=3, len=3))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, ring)
            self.assertIsNone(tool.compare2(got, exp))
            self.assertEqual(got['data'][:1], b'\x93')
            self.assertEqual([ev[0] for ev in got['log'] if ev[0] in ('variant', 'set')], ['variant', 'set'] * 3)
            tree = dict(fam='wseq', seed=4, mode='real', writer=(0, b'', 1, 0, 0),
                        container=dict(kind='tree', height=1, maxlen=3, lenmod=0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, tree)
            self.assertIsNone(tool.compare2(got, exp))

    def test_failing_leaf_writer_words_propagate(self):
        niche = tool.NICHE
        for ci in range(3):
            e = tool.err_words2('uint', 0)
            case = dict(fam='key', mode='stub', seed=1, value=7, writer=(64, b'', 0, 0, 0),
                        state=dict(cap=niche, buf=b'', hint=2), plan=('uint', 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertEqual(got['out'], (niche, e[0], e[1]))
            self.assertEqual(got['log'], [('uint', 7)])
            self.assertIsNone(tool.compare2(got, exp))
            e = tool.err_words2('hdr', 0)
            case = dict(fam='end', mode='stub', seed=1, writer=(64, b'', 0, 0, 0),
                        state=dict(cap=4, buf=b'\x01', hint=3), plan=('hdr', 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertEqual(got['out'], (niche, e[0], e[1]))
            self.assertEqual(got['log'], [('hdr', 3), ('dealloc', 4)])
            self.assertIsNone(tool.compare2(got, exp))

    def test_tuple_and_element_error_paths(self):
        for ci in range(3):
            e = tool.err_words2('set', 0)
            case = dict(fam='tup', mode='real', seed=1, item3=(1, 2, 3), writer=(64, b'', 0, 0, 0),
                        state=dict(cap=tool.NICHE, buf=b'', hint=2), plan=('set', 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertEqual(got['out'], e)
            self.assertIsNone(tool.compare2(got, exp))
            e = tool.err_words2('hdr', 0)
            case = dict(fam='elem', mode='stub', seed=1, tag=5, item3=(1, 2, 3), writer=(64, b'', 2, 0, 0),
                        state=None, plan=('hdr', 0))
            got, exp, _ = tool.run_case(self.fx.image, set(), ci, case)
            self.assertEqual(got['out'], (tool.NICHE, e[0], e[1]))
            self.assertEqual(got['log'], [('hdr', 2)])
            self.assertIsNone(tool.compare2(got, exp))

    def test_wrapper_family_matches_reconstruction(self):
        self.check_rows(self.sample('wseq', 120, 4))

    def test_wrong_reconstructions_are_caught(self):
        for name in ('uint_le', 'flush_reverse', 'end_ascii_any', 'entry_swap', 'elem_flag2_push', 'bin_limit'):
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), None, name), name)

    def test_byte_corruptions_are_caught(self):
        for name, ci, key, mn, pred, from_end, new in tool.BYTE_CONTROLS[::4]:
            patch = tool.find_patch(self.fx.image, self.fx.by_start, tool.COPIES[ci], key, mn, pred, from_end, new)
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), patch), name)

    def test_out_of_range_inputs_are_refused(self):
        with self.assertRaises(tool.Reject):
            tool.check_input(b'not the capture')
        with self.assertRaises(tool.Reject):
            self.fx.image.read(1, 4)
        ent = tool.COPIES[1]['uint']
        with self.assertRaises(tool.Reject):
            tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'] - 2)
        rows = tool.range_controls(self.fx.image, self.fx.by_start)
        self.assertEqual([r[1] for r in rows], [1] * 5)

    def test_committed_evidence_is_consistent(self):
        summary = json.loads((FOLDER / 'summary.json').read_text())
        measure = json.loads((FOLDER / 'measure.json').read_text())
        self.assertEqual(summary['mismatches'], 0)
        self.assertEqual(summary['cases'], measure['cases'])
        self.assertEqual(summary['cases'], len(self.fx.rows))
        self.assertGreaterEqual(measure['cases'], 10000)
        self.assertGreaterEqual(measure['negative_controls'], 30)
        self.assertEqual(measure['negative_detected'], measure['negative_controls'])
        self.assertEqual(sum(summary['case_families'].values()), summary['cases'])
        rows = (FOLDER / 'functions.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), 54)
        self.assertEqual(sum(int(r.split('\t')[5]) for r in rows), summary['instructions'])

    def test_unexecuted_rows_are_listed_and_all_in_new_bodies(self):
        summary = json.loads((FOLDER / 'summary.json').read_text())
        rows = (FOLDER / 'unexecuted.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), summary['unexecuted_new_instructions'])
        self.assertEqual(set(r.split('\t')[0] for r in rows), {'end stage', 'sequence element writer'})


if __name__ == '__main__':
    unittest.main()
