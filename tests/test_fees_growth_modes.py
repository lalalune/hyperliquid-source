"""Tests of tools/fees_growth_modes.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_growth_modes', ROOT / 'tools' / 'fees_growth_modes.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_growth_modes'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-growth-modes-94'
BASE = tool.SETTER


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4], built[6])

    def outcome(self, v):
        self.assertIsNone(tool.check(self.ctx, v))
        return tool.rule(v)

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got, _, callees = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        return (mimg, mcode, slots, got, callees)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked, KeyError):
            return True


def rows_with(byte=0, last=tool.NONE, scale=0.5, status=1):
    rows = tool.fixture()
    rows[0]['assets'][0].update(byte=byte, last=last)
    rows[0].update(scale=scale, scale_bits=tool.bits(scale), status=status)
    return rows


def one(flag, rows=None, mode=0, now=tool.NOW, name=b'BTC'):
    return tool.vec('t', [tool.entry(name, flag)], rows if rows is not None else rows_with(flag), mode, now)


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

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_constants_pinned(self):
        self.assertEqual(tool.pinned(self.built[0])['wait_mode_3'], 2592000.0)
        self.assertEqual(tool.pinned(self.built[0])['factor_byte_0'], 0.1)

    def test_changed_constant_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(tool.Image(self.data, {tool.FACTOR_TABLE + 8: 0}))


class Rules(Base):
    def test_true_stores_zero(self):
        rows = rows_with(1)
        w = self.outcome(one(1, rows))
        self.assertEqual((w['status'], w['writes']), (tool.OK, [(0, 0, 0)]))

    def test_false_stores_one(self):
        w = self.outcome(one(0, rows_with(0)))
        self.assertEqual((w['status'], w['writes']), (tool.OK, [(0, 0, 1)]))

    def test_same_byte_writes_nothing_and_skips_wait(self):
        recent = tool.shift_time(tool.NOW, -1)
        w = self.outcome(one(0, rows_with(1, recent)))
        self.assertEqual((w['status'], w['writes']), (tool.OK, []))

    def test_old_byte_two_refused_for_both_values(self):
        for flag in (0, 1):
            self.assertEqual(self.outcome(one(flag, rows_with(2)))['status'], tool.BAD_BYTE)

    def test_mode_three_waits_30_days(self):
        last = tool.shift_time(tool.NOW, -86400 * 10 ** 9)
        self.assertEqual(self.outcome(one(1, rows_with(1, last), 3))['status'], tool.TOO_SOON)
        self.assertEqual(self.outcome(one(1, rows_with(1, last), 0))['status'], tool.OK)

    def test_wait_edge(self):
        last = tool.shift_time(tool.NOW, -60 * 10 ** 9)
        self.assertEqual(self.outcome(one(1, rows_with(1, last)))['status'], tool.OK)
        self.assertEqual(self.outcome(one(1, rows_with(1, tool.shift_time(last, 1))))['status'], tool.TOO_SOON)

    def test_zero_day_means_no_wait(self):
        self.assertEqual(self.outcome(one(1, rows_with(1, (0, 86399, 9))))['status'], tool.OK)

    def test_scale_gate_only_for_true(self):
        self.assertEqual(self.outcome(one(1, rows_with(1, scale=1.5)))['status'], tool.BLOCKED)
        self.assertEqual(self.outcome(one(0, rows_with(0, scale=1.5)))['status'], tool.OK)
        self.assertEqual(self.outcome(one(1, rows_with(1, scale=1.0)))['status'], tool.OK)

    def test_nan_scale_passes(self):
        self.assertEqual(self.outcome(one(1, rows_with(1, scale=math.nan)))['status'], tool.OK)

    def test_status_three_skips_scale_gate(self):
        self.assertEqual(self.outcome(one(1, rows_with(1, scale=2.0, status=3)))['status'], tool.OK)

    def test_other_asset_blocks_only_true(self):
        for flag, want in ((1, tool.BAD_BYTE), (0, tool.OK)):
            rows = rows_with(flag)
            rows[0]['assets'][1]['byte'] = 2
            self.assertEqual(self.outcome(one(flag, rows))['status'], want)

    def test_failure_at_second_key_writes_nothing(self):
        w = self.outcome(tool.vec('t', [tool.entry(b'BTC', 0), tool.entry(b'zzz:Q', 1)]))
        self.assertEqual((w['status'], w['writes'], len(w['plan'])), (tool.UNKNOWN_DEX, [], 1))

    def test_name_limit(self):
        name = b'n' * 100
        rows = rows_with()
        rows[0]['assets'].append(tool.asset(name))
        self.assertEqual(self.outcome(tool.vec('t', [tool.entry(name, 0)], rows))['status'], tool.OK)
        self.assertEqual(self.outcome(tool.vec('t', [tool.entry(name + b'n', 0)], rows))['status'], tool.TOO_LONG)

    def test_unknown_coin_keeps_full_name(self):
        self.assertEqual(self.outcome(one(0, name=b'abc:Q'))['status'], tool.UNKNOWN_ASSET)

    def test_lost_row_is_dropped_with_success(self):
        rows = [tool.dex(b'', 1, [tool.asset(b'a0')]), tool.dex(b'r', 0, [tool.asset(b'r:x')])]
        w = self.outcome(tool.vec('t', [tool.entry(b'a0', 0)], rows))
        self.assertEqual((w['status'], w['lost'], w['writes']), (tool.OK, [10000], []))

    def test_niche_key_ends_the_tests(self):
        w = self.outcome(tool.vec('t', [tool.entry(b'BTC', 1), tool.entry(b'x', 0, cap=tool.NICHE), tool.entry(b'nope', 1)]))
        self.assertEqual((w['status'], len(w['plan'])), (tool.OK, 1))

    def test_copies_agree(self):
        for c in (tool.SETTER_B, tool.SETTER_C):
            v = one(0, rows_with(0), 3)
            v['copy'] = c
            self.assertEqual(self.outcome(v)['writes'], [(0, 0, 1)])


class Corrupted(Base):
    def flip(self, va, off=0, x=1):
        return {va + off: self.data[self.built[0].off(va + off)] ^ x}

    def test_flipped_old_byte_test(self):
        self.assertTrue(self.broken(one(0, rows_with(2)), self.flip(0x273b70b, 1)))

    def test_new_byte_not_inverted(self):
        self.assertTrue(self.broken(one(0, rows_with(0)), self.flip(0x273b714, 3)))

    def test_wait_table_swapped(self):
        last = tool.shift_time(tool.NOW, -86400 * 10 ** 9)
        self.assertTrue(self.broken(one(1, rows_with(1, last), 3), self.flip(0x273b5f1, 1)))

    def test_time_compare_flipped(self):
        last = tool.shift_time(tool.NOW, 1 - 60 * 10 ** 9)
        self.assertTrue(self.broken(one(1, rows_with(1, last)), self.flip(0x273b778, 0)))

    def test_scale_gate_flipped(self):
        self.assertTrue(self.broken(one(1, rows_with(1, scale=1.5)), self.flip(0x273b7a9, 1)))

    def test_scale_constant_changed(self):
        patch = {tool.SCALE_FREE + 6: 0xe0}
        self.assertTrue(self.broken(one(1, rows_with(1, scale=0.75)), patch))

    def test_limit_changed(self):
        rows = rows_with()
        name = b'n' * 100
        rows[0]['assets'].append(tool.asset(name))
        self.assertTrue(self.broken(tool.vec('t', [tool.entry(name, 0)], rows), {0x273b658: 0x63}))

    def test_store_of_time_moved(self):
        self.assertTrue(self.broken(one(1, rows_with(1)), self.flip(0x273b9f7, 2, 4)))

    def test_store_of_byte_moved(self):
        self.assertTrue(self.broken(one(1, rows_with(1)), self.flip(0x273b9ef, 3, 1)))

    def test_scan_byte_limit(self):
        rows = rows_with(1)
        rows[0]['assets'][1]['byte'] = 2
        self.assertTrue(self.broken(one(1, rows), {0x273b86b: 3}))

    def test_clean_image_passes_the_same_vectors(self):
        self.assertIsNone(tool.check(self.patched({}), one(1, rows_with(1))))


class Packet(Base):
    def evidence(self):
        return json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(x.split('  ')[1] for x in lines), names)
        for x in lines:
            digest, name = x.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_counts(self):
        e = self.evidence()
        self.assertEqual(e['mismatches'], 0)
        self.assertEqual(e['mutants'], e['killed'] + sum(1 for x in (FOLDER / 'mutations.tsv').read_text().splitlines() if '\tequivalent\t' in x))
        self.assertEqual(len((FOLDER / 'vectors.tsv').read_text().splitlines()) - 1, e['vectors'])

    def test_vector_file_matches_a_fresh_list(self):
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        want = [f"{v['copy']:#x}\t{v['group']}\t{tool.digest_of(v)}\t{tool.outcome_name(v)}" for v in tool.all_vectors()]
        self.assertEqual(rows, want)

    def test_copies_differ_only_in_two_offsets(self):
        e = self.evidence()['copies']
        self.assertEqual(e[hex(tool.SETTER_B)], [])
        self.assertEqual(len(e[hex(tool.SETTER_C)]), 4)

    def test_status_texts(self):
        e = self.evidence()['status']
        self.assertEqual(e[hex(tool.BAD_BYTE)]['text'], 'Growth mode blocked by validators')
        self.assertEqual(e[hex(tool.BLOCKED)]['text'], 'Growth mode cannot be set when deployer fee scale is more than 1')

    def test_no_external_program(self):
        body = (ROOT / 'tools' / 'fees_growth_modes.py').read_text()
        for word in ('sub' + 'process', 'obj' + 'dump', 'read' + 'elf'):
            if word == 'obj' + 'dump' or word == 'read' + 'elf':
                self.assertEqual(body.count(word), 1)
            else:
                self.assertNotIn(word, body)


if __name__ == '__main__':
    unittest.main()
