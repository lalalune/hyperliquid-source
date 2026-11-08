import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import dex_registry_sub_deployers_115 as tool  # noqa: E402
import fde_extents  # noqa: E402

FOLDER = ROOT / 'research/work-items/dex-registry-sub-deployers-115'


class Fixture:
    data = None
    image = None
    by_start = None


def load_fixture():
    cls = Fixture
    if cls.data is None:
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        rel = cls.image.relative_addends({tool.HEX_SLOT})
        cls.image.reloc[tool.HEX_SLOT] = rel[tool.HEX_SLOT][1]
        _, recs, _ = fde_extents.fde_extents(cls.data)
        cls.by_start = dict((r['start'], r) for r in recs)
        tool.derive_copies(cls.image, cls.by_start)
    return cls


def sample(fam, count, step=1):
    out = []
    for n, row in enumerate(tool.gen_cases()):
        if row[0] == fam and n % step == 0:
            out.append(row)
            if len(out) >= count:
                break
    return out


class SubDeployerTests(unittest.TestCase):
    def setUp(self):
        self.fx = load_fixture()

    def check_rows(self, rows, bad=None):
        cover = set()
        for fam, ci, case in rows:
            got, exp, _ = tool.run_case(self.fx.image, cover, tool.COPIES[ci], case, bad)
            self.assertIsNone(tool.compare(got, exp), (fam, ci, case))

    def test_every_body_decodes_to_its_unwind_extent(self):
        total = 0
        for cp in tool.COPIES:
            for key in tool.NEW_KEYS + tool.DEP_KEYS:
                ent = cp[key]
                rows = tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'])
                self.assertGreater(len(rows), 20)
                total += len(rows)
        self.assertGreater(total, 7000)

    def test_hex_slot_points_at_the_formatter(self):
        rel = self.fx.image.relative_addends({tool.HEX_SLOT})
        self.assertEqual(rel[tool.HEX_SLOT][1], tool.HEXF)
        self.assertIn(tool.HEXF, self.fx.by_start)

    def test_roles_follow_call_order(self):
        c = tool.COPIES[1]
        names = tool.calls_in_order(self.fx.image, self.fx.by_start, c['elem'])
        self.assertEqual([t for t in names if t != c['res']], [c['hdr'], c['name'], c['vaddr'], c['end']])
        tool.derive_copies(self.fx.image, self.fx.by_start)

    def test_jump_table_sizes(self):
        for cp in tool.COPIES:
            _, outer = tool.jump_table(self.fx.image, self.fx.by_start, cp['name'], 16)
            _, inner = tool.jump_table(self.fx.image, self.fx.by_start, cp['inner'], 8)
            self.assertEqual(len(outer), 16)
            self.assertEqual(len(inner), 8)

    def test_name_table_of_every_copy(self):
        for cp in tool.COPIES:
            for tag in tool.TAGS:
                case = dict(seed=tag, family='name', tag=tag, writer=(256, b'', 0, 0, 0))
                got, exp, _ = tool.run_case(self.fx.image, set(), cp, case)
                self.assertIsNone(tool.compare(got, exp))
                text, rest = tool.decode_name(got['data'])
                self.assertEqual(rest, b'')
                want = tool.TABLE_OUTER[tag - 8] if tag >= 8 else 'hip3Star.' + tool.TABLE_INNER[tag]
                self.assertEqual(text, want)

    def test_element_writer_matches_reconstruction(self):
        self.check_rows(sample('elem', 150, 23))

    def test_name_writer_matches_reconstruction(self):
        self.check_rows(sample('name', 200, 5))

    def test_address_writer_matches_reconstruction(self):
        self.check_rows(sample('vaddr', 100, 3))

    def test_header_and_string_rules(self):
        m = tool.Model(0, b'', None, None)
        m.header(m.main, 15)
        m.header(m.main, 16)
        m.string(m.main, b'x' * 32)
        self.assertEqual(bytes(m.main.buf), b'\x9f\xdc\x00\x10\xd9\x20' + b'x' * 32)
        self.assertEqual(m.log[-1], ('memcpy', 32))

    def test_reserve_growth_rule(self):
        self.assertEqual(tool.bsl_reserve(0, 0, 1), 8)
        self.assertEqual(tool.bsl_reserve(8, 8, 1), 16)
        self.assertEqual(tool.bsl_reserve(8, 8, 40), 48)

    def test_wrong_reconstructions_are_caught(self):
        subset = tool.control_cases()
        for name in ('name_swap', 'hex_upper', 'addr_reverse', 'reserve_nodouble', 'no_memcpy_log'):
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), subset, None, name), name)

    def test_byte_corruptions_are_caught(self):
        subset = tool.control_cases()
        for name, ci, key, mn, pred, from_end, new in tool.BYTE_CONTROLS[:3] + tool.BYTE_CONTROLS[11:14]:
            patch = tool.find_patch(self.fx.image, self.fx.by_start, tool.COPIES[ci], key, mn, pred, from_end, new)
            self.assertIsNotNone(tool.run_control(self.fx.image, set(), subset, patch), name)

    def test_unmodified_bytes_pass_the_control_runner(self):
        self.assertIsNone(tool.run_control(self.fx.image, set(), tool.control_cases()[:100], None, None))

    def test_out_of_range_inputs_are_refused(self):
        with self.assertRaises(tool.Reject):
            tool.check_input(b'not the capture')
        flipped = bytearray(self.fx.data[:4096])
        flipped[0] ^= 1
        with self.assertRaises(tool.Reject):
            tool.check_input(bytes(flipped))
        with self.assertRaises(tool.Reject):
            self.fx.image.read(1, 4)
        ent = tool.COPIES[1]['name']
        with self.assertRaises(tool.Reject):
            tool.linear(self.fx.image, ent, self.fx.by_start[ent]['end'] - 2)
        rows = dict((r[0], r[1]) for r in tool.range_controls(self.fx.image, self.fx.by_start))
        self.assertEqual(rows['tag outside the enum'], 1)

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
        self.assertEqual(len(rows), summary['bodies'])
        self.assertEqual(sum(int(r.split('\t')[5]) for r in rows), summary['instructions'])

    def test_committed_name_table(self):
        rows = [r.split('\t') for r in (FOLDER / 'name-table.tsv').read_text().splitlines()[1:]]
        self.assertEqual(len(rows), 3 * len(tool.TAGS))
        for copy, tag, text, _hex, _steps in rows:
            tag = int(tag)
            want = tool.TABLE_OUTER[tag - 8] if tag >= 8 else 'hip3Star.' + tool.TABLE_INNER[tag]
            self.assertEqual(text, want)

    def test_unexecuted_rows_are_listed_not_hidden(self):
        summary = json.loads((FOLDER / 'summary.json').read_text())
        rows = (FOLDER / 'unexecuted.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), summary['unexecuted_new_instructions'])


if __name__ == '__main__':
    unittest.main()
