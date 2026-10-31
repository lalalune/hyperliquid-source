"""Tests of tools/fees_fee_scale.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_fee_scale', ROOT / 'tools' / 'fees_fee_scale.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_fee_scale'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-fee-scale-94'
FIRST_ARM = 0x273f6ee


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def setUp(self):
        tool.GOLD.clear()

    def passes(self, v, ctx=None):
        self.assertIsNone(tool.check(ctx or self.ctx, v))

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got, _ = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        for e in tool.ARMS:
            mcode.update({i.va: i for i in tool.walk_arm(mimg, e)[0]})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked):
            return True


def scale(x, **kw):
    return tool.setter_vec('t', x, **kw)


def arm(**kw):
    return tool.arm_vec(FIRST_ARM, 't', **kw)


OPEN_LAST = tool.stamp(2020, 1, 1)
RECENT = tool.time_add(tool.NOW, -1000.0)


class Digest(Base):
    def test_digest_accepted(self):
        self.assertEqual(tool.check_digest(self.data), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_outside_address_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(0x7fff0000, 8)

    def test_no_fde_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.built[2].range_of(tool.SETTER + 1)

    def test_constants_pinned(self):
        self.assertEqual(tool.pinned(self.built[0])['cooldown_mode_3'], 2592000.0)

    def test_changed_constant_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(tool.Image(self.data, {tool.COOLDOWNS + 6: 0}))

    def test_walk_stops_on_a_return(self):
        with self.assertRaises(tool.EvidenceError):
            tool.walk_arm(self.built[0], tool.SETTER + 0x42)


class Setter(Base):
    def test_range_edges(self):
        self.assertEqual(tool.setter_rule(scale(3.0))['status'], tool.OK)
        self.assertEqual(tool.setter_rule(scale(tool.ABOVE_3))['status'], tool.BAD_SCALE)
        self.assertEqual(tool.setter_rule(scale(tool.BELOW_0))['status'], tool.BAD_SCALE)
        for x in (3.0, tool.ABOVE_3, tool.BELOW_0, 0.0, -0.0):
            self.passes(scale(x))

    def test_nan_passes_the_range_test_and_is_stored(self):
        v = scale(tool.NAN)
        rule = tool.setter_rule(v)
        self.assertEqual((rule['status'], rule['write']), (tool.OK, True))
        self.passes(v)

    def test_range_before_status(self):
        v = scale(4.0, status=3)
        self.assertEqual(tool.setter_rule(v)['status'], tool.BAD_SCALE)
        self.passes(v)

    def test_status_before_wait(self):
        v = scale(0.5, status=3, last=RECENT, mode=3)
        self.assertEqual(tool.setter_rule(v)['status'], tool.GONE)
        self.passes(v)

    def test_mode_3_waits_30_days(self):
        v = scale(0.25, mode=3, last=RECENT)
        self.assertEqual(tool.setter_rule(v)['status'], tool.TOO_SOON)
        self.passes(v)

    def test_other_modes_wait_60_seconds(self):
        for mode in (0, 1, 2, 4, 255):
            v = scale(0.25, mode=mode, last=RECENT)
            self.assertEqual(tool.setter_rule(v)['status'], tool.OK)
            self.passes(v)

    def test_wait_edge_is_inclusive(self):
        last = tool.time_add(tool.NOW, -60.0)
        self.assertEqual(tool.setter_rule(scale(0.25, last=last))['status'], tool.OK)
        late = tool.time_add(tool.NOW, -59.999999999)
        self.assertEqual(tool.setter_rule(scale(0.25, last=late))['status'], tool.TOO_SOON)
        self.passes(scale(0.25, last=last))
        self.passes(scale(0.25, last=late))

    def test_date_word_compares_signed(self):
        v = scale(0.25, last=tool.stamp(-1, 6, 1), now=tool.stamp(1, 6, 1))
        self.assertEqual(tool.setter_rule(v)['status'], tool.OK)
        self.passes(v)

    def test_wait_panics_at_the_end_of_time(self):
        last = tool.stamp(262142, 12, 31, 86399)
        v = scale(0.25, last=last, now=last)
        self.assertEqual(tool.setter_rule(v).get('panic'), 'time')
        self.passes(v)

    def test_wait_before_assets(self):
        v = scale(2.0, mode=3, last=RECENT, flags=(0,))
        self.assertEqual(tool.setter_rule(v)['status'], tool.TOO_SOON)
        self.passes(v)

    def test_assets_only_above_one(self):
        self.assertEqual(tool.setter_rule(scale(1.0, flags=(0,)))['status'], tool.OK)
        self.assertEqual(tool.setter_rule(scale(tool.ABOVE_1, flags=(0,)))['status'], tool.BLOCKED)
        self.passes(scale(1.0, flags=(0,)))
        self.passes(scale(tool.ABOVE_1, flags=(0,)))

    def test_later_asset_blocks(self):
        v = scale(2.0, flags=(1, 1, 0))
        self.assertEqual(tool.setter_rule(v)['status'], tool.BLOCKED)
        self.passes(v)

    def test_multiply_overflow_panics_only_with_assets(self):
        high = tool.U64 // 10000 + 1
        self.assertEqual(tool.setter_rule(scale(2.0, index=high)).get('panic'), 'mul')
        self.assertEqual(tool.setter_rule(scale(2.0, index=high, flags=()))['status'], tool.OK)
        self.passes(scale(2.0, index=high))
        self.passes(scale(2.0, index=high, flags=()))

    def test_add_overflow_panics(self):
        top = tool.U64 // 10000
        room = tool.U64 - top * 10000
        v = scale(2.0, index=top, flags=(1,) * (room + 2))
        self.assertEqual(tool.setter_rule(v).get('panic'), 'add')
        self.passes(v)

    def test_equal_value_keeps_the_time(self):
        v = scale(0.5, old=0.5)
        self.assertEqual(tool.setter_rule(v), dict(status=tool.OK, write=False))
        self.passes(v)

    def test_zero_signs_count_as_equal(self):
        v = scale(-0.0, old=0.0)
        self.assertFalse(tool.setter_rule(v)['write'])
        self.passes(v)


class TimeAdd(Base):
    def test_rules(self):
        t = tool.stamp(2025, 1, 1)
        self.assertEqual(tool.time_add(t, 86400.0), tool.stamp(2025, 1, 2))
        self.assertEqual(tool.time_add(t, -1e-9), tool.stamp(2024, 12, 31, 86399, 999999999))
        self.assertEqual(tool.time_add(t, math.nan), t)
        self.assertEqual(tool.time_add(t, math.inf), t)

    def test_top_input_reaches_the_largest_float(self):
        self.assertEqual(tool.TOP_INPUT * 1e9, sys.float_info.max)

    def test_saturation_runs(self):
        for s in (1e300, -1e300, 1e10, -1e10):
            self.passes(tool.time_vec(s, tool.stamp(2025, 1, 1)))


class Lookup(Base):
    def test_empty_name_takes_row_0_whatever_its_status(self):
        rows = [tool.row(b'a', status=3), tool.row(b'b')]
        self.assertEqual(tool.lookup_rule(rows, b''), 0)
        self.passes(tool.lookup_vec(rows, b''))

    def test_named_skips_status_3(self):
        rows = [tool.row(b'a', status=3), tool.row(b'a', index=2)]
        self.assertEqual(tool.lookup_rule(rows, b'a'), 1)
        self.passes(tool.lookup_vec(rows, b'a'))

    def test_empty_table(self):
        self.passes(tool.lookup_vec([], b''))
        self.passes(tool.lookup_vec([], b'a'))
        self.assertEqual(tool.lookup_rule([], b''), 'panic')
        self.assertEqual(tool.lookup_rule([], b'a'), 'none')


class Arm(Base):
    def test_all_copies_succeed(self):
        for e in tool.ARMS:
            v = tool.arm_vec(e, 't', rows=[tool.row(old=0.25)])
            self.assertEqual(tool.arm_rule(v)['status'], tool.OK)
            self.passes(v)

    def test_text_limit(self):
        for e in tool.ARMS:
            self.passes(tool.arm_vec(e, 't', text=b'0' * 100))
            v = tool.arm_vec(e, 't', text=b'0' * 101)
            self.assertEqual(tool.arm_rule(v)['stage'], 'text')
            self.passes(v)

    def test_name_limit_comes_after_the_parser(self):
        name = b'n' * 101
        v = arm(name=name, parsed=None)
        self.assertEqual(tool.arm_rule(v)['stage'], 'parse')
        self.passes(v)
        v = arm(name=name)
        self.assertEqual(tool.arm_rule(v)['stage'], 'name')
        self.passes(v)

    def test_free_order_differs_by_path(self):
        self.assertEqual(tool.arm_rule(arm(text=b'0' * 101))['frees'], ['text', 'name'])
        self.assertEqual(tool.arm_rule(arm(name=b'n' * 101))['frees'], ['name', 'text'])

    def test_unknown_dex_forwards(self):
        v = arm(name=b'zulu')
        self.assertEqual(tool.arm_rule(v)['status'], tool.UNKNOWN_DEX)
        self.passes(v)

    def test_empty_table_panics(self):
        v = arm(name=b'', rows=[])
        self.assertEqual(tool.arm_rule(v).get('panic'), 'unwrap')
        self.passes(v)

    def test_third_copy_mode_field(self):
        v = tool.arm_vec(0x4d57242, 't', mode=3, rows=[tool.row(old=0.25, last=RECENT)])
        self.assertEqual(tool.arm_rule(v)['status'], tool.TOO_SOON)
        self.passes(v)


class Corrupted(Base):
    def test_sete_flipped(self):
        self.assertTrue(self.broken(scale(0.25, last=RECENT), {0x3718e90: 0x95}))

    def test_mode_compare_changed(self):
        self.assertTrue(self.broken(scale(0.25, mode=3, last=RECENT), {0x3718e8e: 2}))

    def test_limit_constant(self):
        self.assertTrue(self.broken(scale(3.5), {tool.SCALE_MAX + 6: 0x18}))

    def test_free_constant(self):
        self.assertTrue(self.broken(scale(1.5, flags=(0,)), {tool.SCALE_FREE + 6: 0x00, tool.SCALE_FREE + 7: 0x40}))

    def test_cooldown_table(self):
        self.assertTrue(self.broken(scale(0.25, last=RECENT), {tool.COOLDOWNS + 6: 0x90}))

    def test_asset_flag_offset(self):
        self.assertTrue(self.broken(scale(2.0, flags=(0,)), {0x3718ff7: 0x28}))

    def test_asset_multiplier(self):
        self.assertTrue(self.broken(scale(2.0, index=tool.U64 // 10000), {0x3718f0c: 0x11}))

    def test_status_byte_compare(self):
        self.assertTrue(self.broken(scale(0.5, status=3), {0x3718e55: 2}))

    def test_equal_value_branch(self):
        self.assertTrue(self.broken(scale(0.5, old=0.5), {0x3718f2b: 0x74}))

    def test_lookup_status_compare(self):
        rows = [tool.row(b'a', status=3), tool.row(b'a', index=2)]
        self.assertTrue(self.broken(tool.lookup_vec(rows, b'a'), {0x33323d8: 2}))

    def test_arm_text_limit(self):
        self.assertTrue(self.broken(arm(text=b'0' * 101), {0x273f711: 0x66}))

    def test_arm_name_limit(self):
        self.assertTrue(self.broken(arm(name=b'n' * 101, rows=[tool.row(b'n' * 101, old=0.25)]), {0x273f741: 0x66}))

    def test_arm_mode_field(self):
        self.assertTrue(self.broken(arm(mode=3, rows=[tool.row(old=0.25, last=RECENT)]), {0x2741152: 0xfa}))

    def test_every_vector_group_runs_clean(self):
        for v in tool.all_vectors()[::37]:
            self.passes(v)


class Packet(Base):
    evidence = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(x.split('  ')[1] for x in lines), names)
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_counts(self):
        ev = self.evidence
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['vectors'], len(tool.all_vectors()))
        self.assertEqual(ev['killed'] + sum(1 for x in (FOLDER / 'mutations.tsv').read_text().splitlines()[1:] if x.split('\t')[4] == 'equivalent'), ev['mutants'])

    def test_three_call_sites(self):
        users = self.evidence['setter_slot']['users']
        self.assertEqual(sorted(u['site'] for u in users), ['0x27411bc', '0x4d53355', '0x4d58d75'])
        self.assertEqual(self.evidence['setter_slot']['direct_calls'], [])

    def test_files_regenerate(self):
        with tempfile.TemporaryDirectory() as d:
            tool.GOLD.clear()
            tool.generate(self.data, d, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(d) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_no_absolute_paths_in_evidence(self):
        self.assertNotIn(chr(0x2f) + 'home', (FOLDER / 'evidence.json').read_text())


if __name__ == '__main__':
    unittest.main()
