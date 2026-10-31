"""Tests of tools/fees_user_view.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_user_view', ROOT / 'tools' / 'fees_user_view.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_user_view'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-user-view-94'
f2b, packed, vec, row_ = tool.f2b, tool.packed, tool.vec, tool.row_
TIERS = tool.TIERS


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def clean(self, v):
        self.assertIsNone(tool.check(self.ctx, v))
        return tool.expected(v)

    def field(self, v, off):
        return dict((o, x) for o, _, x in self.clean(v))[off]

    def patched(self, patch):
        img, code, _, slots, got, _ = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        mcode.update({i.va: i for i in tool.decode_subject(mimg, tool.ENTRY)})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked, KeyError):
            return True


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
            self.built[2].range_of(tool.ENTRY + 1)

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_decoder_lands_on_the_fde_end(self):
        rows = self.built[5][tool.ENTRY]
        self.assertEqual(rows[-1].va + rows[-1].size, 0x27d8ada)

    def test_pin_change_refused(self):
        img = tool.Image(self.data, {0x27d8634: 0x5b})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_user_view.py').read_text()
        self.assertNotIn('import subprocess', text)
        self.assertIn('from fde_extents import eh_frame_records', text)


class Dates(Base):
    def test_epoch(self):
        self.assertEqual(tool.millis(packed(1970, 1)), 0)

    def test_second_day(self):
        self.assertEqual(tool.millis(packed(1970, 2)), 86400000)

    def test_known_date(self):
        self.assertEqual(tool.millis(packed(2026, 1)), 1767225600000)

    def test_before_1970_floors(self):
        self.assertEqual(tool.millis(packed(1969, 365)), 0)
        self.assertEqual(tool.millis(packed(-400, 1)), 0)

    def test_flags_ignored(self):
        self.assertEqual(tool.millis(packed(2026, 9, 0)), tool.millis(packed(2026, 9, 15)))


class Outcomes(Base):
    def test_no_row_reads_nothing(self):
        got = self.clean(vec('t'))
        self.assertEqual(dict((o, x) for o, _, x in got)[0x30], 0)
        self.assertEqual(dict((o, x) for o, _, x in got)[0xf0], 0)

    def test_trial_tag_follows_the_date(self):
        self.assertEqual(self.field(vec('t', row=row_(end=packed(2026, 301))), 0), 1)
        self.assertEqual(self.field(vec('t'), 0), 0)

    def test_next_trial_is_date_plus_90(self):
        v = vec('t', value=dict(date=packed(2026, 1)), after90=packed(2026, 91))
        self.assertEqual(self.field(v, 0x38), tool.millis(packed(2026, 91)))
        self.assertEqual(self.field(v, 0x30), 1)

    def test_date_panic(self):
        v = vec('t', value=dict(date=packed(262142, 300)), after90=0)
        self.assertEqual(self.clean(v), 'date')

    def test_escrow_uses_first_token_decimals(self):
        v = vec('t', value=dict(escrow=5000000000), tokens=(8, 2))
        self.assertEqual(self.field(v, 0xf0), f2b(50.0))

    def test_escrow_without_token_panics(self):
        self.assertEqual(self.clean(vec('t', value=dict(escrow=1), tokens=())), 'list')

    def test_no_escrow_needs_no_token(self):
        self.assertEqual(self.field(vec('t', value=dict(), tokens=()), 0xf0), 0)

    def test_ladder_below_first(self):
        rows = TIERS[1:]
        self.assertEqual(self.field(vec('t', ladder=rows, row=row_(share=f2b(0.0))), 0x100), 0)

    def test_ladder_cutoff_is_inclusive(self):
        self.assertEqual(self.field(vec('t', ladder=TIERS, row=row_(share=f2b(0.01))), 0x100), f2b(0.1))

    def test_ladder_top(self):
        self.assertEqual(self.field(vec('t', ladder=TIERS, row=row_(share=f2b(1e9))), 0x100), f2b(0.4))

    def test_ladder_nan_cutoff_is_passed(self):
        rows = ((f2b(0.0), f2b(0.1)), (tool.NAN, f2b(0.2)), (f2b(1.0), f2b(0.3)))
        self.assertEqual(self.field(vec('t', ladder=rows, row=row_(share=f2b(0.5))), 0x100), f2b(0.2))

    def test_share_passes_through_without_a_ladder(self):
        self.assertEqual(self.field(vec('t', ladder=(), row=row_(share=f2b(9.0))), 0xf8), f2b(9.0))

    def test_link_hit(self):
        v = vec('t', links=[(tool.U, 2, tool.user(9))])
        self.assertEqual(self.field(v, 0x108), 2)

    def test_link_miss_gives_3(self):
        self.assertEqual(self.field(vec('t', links=[(tool.user(8), 2, tool.user(9))]), 0x108), 3)

    def test_clock_error_gives_zero(self):
        v = vec('t', gaps=((1, 0, 0), (0, 2, 500000000)))
        self.assertEqual(self.field(v, 0x120), 0)
        self.assertEqual(self.field(v, 0x128), f2b(2.5))

    def test_stack_flag_calls_with_50(self):
        self.assertIsNone(tool.check(self.ctx, vec('t', sleep=1)))

    def test_every_vector_matches(self):
        for v in tool.all_vectors():
            self.assertIsNone(tool.check(self.ctx, v), v['group'])


class Corrupted(Base):
    ESCROW = vec('t', value=dict(escrow=5000000000, date=packed(2026, 1)), tokens=(8,), after90=packed(2026, 91), ladder=TIERS, row=row_(end=packed(2026, 300)))

    def test_clean_image_passes(self):
        self.assertFalse(self.broken(self.ESCROW, {}))

    def test_90_days(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d8634: 0x5b}))

    def test_14_days(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d8128: 0x0f}))

    def test_date_field(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d8626: 0xb8}))

    def test_powers_table(self):
        self.assertTrue(self.broken(self.ESCROW, {tool.POWERS + 8 * 8 + 6: 0x97 ^ 0x10}))

    def test_nanos_divisor(self):
        self.assertTrue(self.broken(self.ESCROW, {tool.ONE_E9 + 6: 0xcd ^ 0x10}))

    def test_ladder_compare(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d8727: 0x77}))

    def test_days_per_month_word(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d84d4: 0xb4}))

    def test_tree_stride(self):
        self.assertTrue(self.broken(self.ESCROW, {0x27d8588: 0x31}))


class Packet(Base):
    evidence = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text().split('\n')
        seen = set()
        for line in rows:
            if line:
                digest, name = line.split('  ')
                self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
                seen.add(name)
        self.assertEqual(seen, {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'})

    def test_sha(self):
        self.assertEqual(self.evidence['sha256'], tool.SHA256)

    def test_vector_rows(self):
        vecs = tool.all_vectors()
        rows = (FOLDER / 'vectors.tsv').read_text().split('\n')[1:-1]
        self.assertEqual(len(rows), len(vecs))
        self.assertEqual(self.evidence['vectors'], len(vecs))
        self.assertEqual(self.evidence['mismatches'], 0)
        for v, line in zip(vecs, rows):
            self.assertEqual(line.split('\t')[1], tool.digest_of(v))

    def test_mutation_rows(self):
        rows = [x.split('\t') for x in (FOLDER / 'mutations.tsv').read_text().split('\n')[1:-1]]
        self.assertEqual(len(rows), self.evidence['mutants'])
        self.assertEqual(sum(r[3] == 'killed' for r in rows), self.evidence['killed'])
        self.assertEqual({int(r[1], 16) for r in rows if r[3] == 'equivalent'}, set(tool.EQUIVALENT))

    def test_sites_match_the_decoder(self):
        self.assertEqual(self.evidence['mutants'], len(tool.all_sites(self.built[5], self.built[0])))

    def test_serializer_names(self):
        got = {r['text']: r['offset'] for r in self.evidence['serializer_fields']}
        self.assertEqual(got['trial'], 0)
        self.assertEqual(got['nextTrialAvailableTimestamp'], 0x30)
        self.assertEqual(got['feeTrialEscrow'], 0xf0)
        self.assertEqual(got['activeStakingDiscount'], 0xf8)
        self.assertEqual(got['stakingLink'], 0x108)

    def test_no_unlisted_gap(self):
        rows = self.built[5][tool.ENTRY]
        self.assertEqual(self.evidence['function']['instructions'], len(rows))


if __name__ == '__main__':
    unittest.main()
