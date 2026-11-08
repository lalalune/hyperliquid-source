import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import dex_registry_entry_stages_115 as tool  # noqa: E402
import fde_extents  # noqa: E402

FOLDER = ROOT / 'research/work-items/dex-registry-entry-stages-115'


class Fixture:
    data = None
    image = None
    by_start = None
    cases = None


def load_fixture():
    cls = Fixture
    if cls.data is None:
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        _, recs, _ = fde_extents.fde_extents(cls.data)
        cls.by_start = dict((r['start'], r) for r in recs)
        cls.cases = list(tool.gen_cases())
    return cls


def push_all(fn, *args, bad=None):
    vec, log = tool.Vec(0, b''), []
    fn(vec, *args, log, bad)
    return bytes(vec.buf), log


class EntryStageTests(unittest.TestCase):
    def setUp(self):
        self.fx = load_fixture()

    def check_rows(self, rows, bad=None, patches=None):
        cover = set()
        for case in rows:
            got, exp, _ = tool.run_case(self.fx.image, cover, case, bad, patches)
            self.assertIsNone(tool.compare(got, exp), case)
        return cover

    def sample(self, kind, copy, step):
        return [c for n, c in enumerate(self.fx.cases) if c['kind'] == kind and c['copy'] == copy and n % step == 0]

    def test_every_body_decodes_to_its_unwind_extent(self):
        total = 0
        for cp in tool.COPIES:
            for key in tool.BODY_KEYS:
                ent = cp[key]
                rows = tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'])
                self.assertGreater(len(rows), 20)
                total += len(rows)
        self.assertEqual(total, 2748)

    def test_entry_writer_calls_key_value_end_in_this_order(self):
        for cp in tool.COPIES:
            order = [t for t in tool.calls_in_order(self.fx.image, self.fx.by_start, cp['ent']) if t != cp['res']]
            self.assertEqual(order, [cp['key'], cp['val'], cp['end']])

    def test_key_and_value_stage_writers_have_one_shape(self):
        for cp in tool.COPIES:
            self.assertEqual(tool.shape(self.fx.image, self.fx.by_start, cp['key']),
                             tool.shape(self.fx.image, self.fx.by_start, cp['val']))
        a = tool.shape(self.fx.image, self.fx.by_start, tool.COPIES[0]['key'])
        b = tool.shape(self.fx.image, self.fx.by_start, tool.COPIES[0]['end'])
        self.assertNotEqual(a, b)

    def test_model_unsigned_integer_encoding(self):
        expect = {0: '00', 0x7f: '7f', 0x80: 'cc80', 0xff: 'ccff', 0x100: 'cd0100', 0xffff: 'cdffff',
                  0x10000: 'ce00010000', 0xffffffff: 'ceffffffff', 0x100000000: 'cf0000000100000000',
                  tool.MASK: 'cf' + 'ff' * 8}
        for v, hexed in expect.items():
            self.assertEqual(push_all(tool.m_uint, v)[0].hex(), hexed)

    def test_model_headers(self):
        self.assertEqual(push_all(tool.m_header, 15)[0], b'\x9f')
        self.assertEqual(push_all(tool.m_header, 16)[0], b'\xdc\x00\x10')
        self.assertEqual(push_all(tool.m_header, 0x10000)[0], b'\xdd\x00\x01\x00\x00')
        self.assertEqual(push_all(tool.m_bin_header, 0xff)[0], b'\xc4\xff')
        self.assertEqual(push_all(tool.m_bin_header, 0x100)[0], b'\xc5\x01\x00')
        self.assertEqual(push_all(tool.m_bin_header, 0x10000)[0], b'\xc6\x00\x01\x00\x00')

    def test_map_entry_is_a_pair_in_both_flag_paths(self):
        for flag in (2, 3):
            vec, log = tool.Vec(64, b''), []
            tool.m_entry(flag, 5, 0x1234, vec, log)
            self.assertEqual(bytes(vec.buf), bytes.fromhex('92' '05' 'cd1234'))

    def test_key_stage_all_copies(self):
        for ci in range(3):
            self.check_rows(self.sample('key', ci, 11))

    def test_value_stage_all_copies(self):
        for ci in range(3):
            self.check_rows(self.sample('val', ci, 11))

    def test_end_stage_all_copies(self):
        for ci in range(3):
            self.check_rows(self.sample('end', ci, 11))

    def test_entry_writer_all_copies(self):
        for ci in range(3):
            self.check_rows(self.sample('entry', ci, 7))

    def test_leaf_writers_all_copies(self):
        for kind in ('uint', 'bin', 'head'):
            for ci in range(3):
                rows = self.sample(kind, ci, 9)
                self.assertGreater(len(rows), 20)
                self.check_rows(rows)

    def test_leaf_result_markers(self):
        vec, log = tool.Vec(64, b''), []
        self.assertEqual(tool.m_leaf('uint', 5, vec, log), (0, 5))
        self.assertEqual(tool.m_leaf('uint', 0x80, vec, log)[0], 0xcc)
        self.assertEqual(tool.m_leaf('uint', 1 << 32, vec, log)[0], 0xcf)
        self.assertEqual(tool.m_leaf('bin', 0x10000, vec, log)[0], 0xc6)
        self.assertEqual(tool.m_leaf('head', 16, vec, log)[0], 0xdc)
        bad = [c for c in self.fx.cases if c['kind'] == 'uint' and c['value'] in (0x80, 0x10000)
               and 'alloc_fail' not in c][:6]
        self.assertTrue(bad)
        got, exp, _ = tool.run_case(self.fx.image, set(), bad[0])
        exp['marker'] = (0x00, 0x22)
        self.assertEqual(tool.compare(got, exp), 'result marker bytes differ')

    def test_boundary_counts_and_items_run(self):
        rows = [c for c in self.fx.cases if c['kind'] in ('key', 'val', 'end') and c['state'][0] != tool.NICHE
                and c['state'][2] in (15, 16, 0xffff, 0x10000)][:60]
        self.assertGreater(len(rows), 30)
        self.check_rows(rows)

    def test_coverage_of_hot_paths(self):
        rows = self.sample('key', 0, 5) + self.sample('end', 0, 5) + self.sample('entry', 0, 5)
        cover = self.check_rows(rows)
        for key in ('wu', 'bin', 'head'):
            ent = tool.COPIES[0][key]
            body = tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'])
            hit = sum(1 for r in body if r.va in cover)
            self.assertGreater(hit, len(body) // 2, key)

    def test_wrong_reconstructions_are_caught(self):
        subset = tool.control_cases()
        self.assertGreater(len(subset), 500)
        for name in tool.MODEL_MUTANTS:
            self.assertIsNotNone(tool.run_control(self.fx.image, subset, None, name), name)

    def test_byte_corruption_is_caught(self):
        subset = tool.control_cases()
        done = 0
        for name, ci, key, mn, pred, from_end, new in tool.BYTE_CONTROLS:
            patch = tool.find_patch(self.fx.image, self.fx.by_start, tool.COPIES[ci], key, mn, pred, from_end, new)
            self.assertIsNotNone(tool.run_control(self.fx.image, subset, patch), name)
            done += 1
        self.assertGreaterEqual(done, 20)

    def test_unpatched_subset_has_no_mismatch(self):
        self.assertIsNone(tool.run_control(self.fx.image, tool.control_cases()))

    def test_wrong_input_and_out_of_range_reads_are_rejected(self):
        with self.assertRaises(tool.Reject):
            tool.check_input(b'not the capture')
        with self.assertRaises(tool.Reject):
            self.fx.image.read(0x1, 4)
        rows = tool.range_controls(self.fx.image, self.fx.by_start)
        self.assertEqual([r[1] for r in rows], [1, 1, 1, 1])

    def test_unmodelled_callee_is_refused(self):
        ent = tool.COPIES[1]['end']
        m = tool.Machine(self.fx.image, {ent}, {}, tool.SLOT, set())
        tool.write_writer(m, 8, b'', 0, 0, 0)
        tool.write_state(m, 0, b'ab', 2)
        m.regs[7], m.regs[6] = tool.OUT, tool.ST
        with self.assertRaises(tool.Reject):
            m.run(ent)

    def test_committed_evidence_matches_manifest_and_measure(self):
        manifest = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        self.assertGreater(len(manifest), 8)
        for line in manifest:
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        measure = json.loads((FOLDER / 'measure.json').read_text())
        summary = json.loads((FOLDER / 'summary.json').read_text())
        self.assertEqual(measure['cases'], summary['cases'])
        self.assertEqual(measure['negative_controls'], summary['negative_controls'])
        self.assertEqual(measure['negative_detected'], measure['negative_controls'])
        self.assertEqual(summary['mismatches'], 0)
        self.assertGreaterEqual(summary['cases'], 10000)
        self.assertGreaterEqual(summary['negative_controls'], 30)


if __name__ == '__main__':
    unittest.main()
