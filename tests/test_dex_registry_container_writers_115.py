import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import dex_registry_container_writers_115 as tool  # noqa: E402
import fde_extents  # noqa: E402

FOLDER = ROOT / 'research/work-items/dex-registry-container-writers-115'


class Fixture:
    data = None
    image = None
    by_start = None


def load_fixture():
    cls = Fixture
    if cls.data is None:
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        _, recs, _ = fde_extents.fde_extents(cls.data)
        cls.by_start = dict((r['start'], r) for r in recs)
        tool.derive_copies(cls.image, cls.by_start)
    return cls


def sample(kind, count, step=1):
    out = []
    for n, row in enumerate(tool.gen_cases()):
        if row[1] == kind and n % step == 0:
            out.append(row)
            if len(out) >= count:
                break
    return out


class ContainerWriterTests(unittest.TestCase):
    def setUp(self):
        self.fx = load_fixture()

    def check_rows(self, rows, bad=None):
        cover = set()
        for fam, kind, ci, case in rows:
            got, exp, _ = tool.run_any(self.fx.image, cover, fam, kind, ci, case, bad)
            self.assertIsNone(tool.compare(kind, got, exp), (fam, kind, ci, case))

    def test_every_body_decodes_to_its_unwind_extent(self):
        total = 0
        for cp in tool.COPIES:
            for key in tool.BODY_KEYS:
                ent = cp[key]
                rows = tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'])
                self.assertGreater(len(rows), 20)
                total += len(rows)
        self.assertEqual(total, 3244)

    def test_stage_roles_follow_call_order(self):
        keys = [(c['key'], c['val'], c['end']) for c in tool.COPIES]
        self.assertEqual(keys[0], (0x2296160, 0x2296fa0, 0x22999e0))
        self.assertEqual(keys[2][0], 0x53206b0)
        for c in tool.COPIES:
            self.assertEqual(tool.calls_in_order(self.fx.image, self.fx.by_start, c['wrap']), [c['seq']])

    def test_map_loop_matches_reconstruction(self):
        self.check_rows(sample('map', 150, 7))

    def test_sequence_loop_matches_reconstruction(self):
        self.check_rows(sample('seq', 120, 7))

    def test_header_and_finish_match_reconstruction(self):
        self.check_rows(sample('header', 120, 3) + sample('finish', 60, 3))

    def test_wrapper_matches_reconstruction(self):
        self.check_rows(sample('wrapper', 120, 5))

    def test_header_marker_table(self):
        vec = tool.Vec(64, b'')
        log = []
        for n, expect in ((0, b'\x90'), (15, b'\x9f'), (16, b'\xdc\x00\x10'), (0xffff, b'\xdc\xff\xff'),
                          (0x10000, b'\xdd\x00\x01\x00\x00')):
            vec = tool.Vec(64, b'')
            tool.m_header(vec, n, log)
            self.assertEqual(bytes(vec.buf), expect)

    def test_reserve_growth_rule(self):
        self.assertEqual(tool.bsl_reserve(0, 0, 1), 8)
        self.assertEqual(tool.bsl_reserve(8, 8, 1), 16)
        self.assertEqual(tool.bsl_reserve(8, 8, 40), 48)

    def test_wrong_reconstructions_are_caught(self):
        subset = tool.control_cases()
        for name in ('hdr_endian', 'flag_skip', 'tree_reverse', 'count_plus1', 'reserve_nodouble'):
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), subset, None, name), name)

    def test_byte_corruptions_are_caught(self):
        subset = tool.control_cases()
        for name, ci, key, mn, pred, from_end, new in tool.BYTE_CONTROLS[:4] + tool.BYTE_CONTROLS[11:14]:
            patch = tool.find_patch(self.fx.image, self.fx.by_start, tool.COPIES[ci], key, mn, pred, from_end, new)
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), subset, patch), name)

    def test_unmodified_bytes_pass_the_control_runner(self):
        self.assertIsNone(tool.run_control(self.fx.image, set(), tool.control_cases()[:120], None, None))

    def test_out_of_range_inputs_are_refused(self):
        with self.assertRaises(tool.Reject):
            tool.check_input(b'not the capture')
        with self.assertRaises(tool.Reject):
            self.fx.image.read(1, 4)
        ent = tool.COPIES[1]['head']
        with self.assertRaises(tool.Reject):
            tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'] - 2)

    def test_committed_evidence_is_consistent(self):
        summary = json.loads((FOLDER / 'summary.json').read_text())
        measure = json.loads((FOLDER / 'measure.json').read_text())
        self.assertEqual(summary['mismatches'], 0)
        self.assertEqual(summary['cases'], measure['cases'])
        self.assertGreaterEqual(measure['cases'], 10000)
        self.assertGreaterEqual(measure['negative_controls'], 30)
        self.assertEqual(measure['negative_detected'], measure['negative_controls'])
        self.assertEqual(sum(summary['case_families'].values()), summary['cases'])
        rows = (FOLDER / 'functions.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), 33)
        self.assertEqual(sum(int(r.split('\t')[5]) for r in rows), summary['instructions'])

    def test_unexecuted_rows_are_listed_not_hidden(self):
        summary = json.loads((FOLDER / 'summary.json').read_text())
        rows = (FOLDER / 'unexecuted.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), summary['unexecuted_instructions'])


if __name__ == '__main__':
    unittest.main()
