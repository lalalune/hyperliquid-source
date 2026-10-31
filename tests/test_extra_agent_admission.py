import contextlib
import filecmp
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import extra_agent_admission as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'l1-shared-extra-agent-admission-94'
GENERATED = ['evidence.json', 'callers.tsv', 'windows.txt']
M64 = (1 << 64) - 1


class ExtraAgentAdmissionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / tool.BINARY).read_bytes()
        cls.result, cls.windows = tool.analyse(cls.data)

    def test_rejects_wrong_digest(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:4096])
        corrupted = bytearray(self.data)
        corrupted[0x59ce33] ^= 0x01
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted))

    def test_summary(self):
        s = self.result['summary']
        self.assertEqual(s['message_leas'], 1)
        self.assertEqual(s['arm_tags'], [83])
        self.assertEqual(s['display_entries'], 390)
        self.assertEqual(s['tag_stores'], 1)
        self.assertEqual(s['admitted_name_bytes'], [1, 16])
        self.assertEqual((s['cap_base'], s['cap_per_tier'], s['cap_error_tag']), (3, 2, 87))
        self.assertEqual(s['bypass_addresses'], 3)
        self.assertTrue(s['cap_matches_reference_formula'])
        self.assertEqual((s['got_slots'], s['callers'], s['caller_forms']), (1, 3, 1))
        self.assertEqual(s['callers_ok_tag_equals_display_entries'], 3)
        self.assertEqual((s['equity_gate'], s['tier_divisor'], s['tier_clamp'], s['tier_offset']),
                         (10_000_000, 10_000_000_000, 40, 10))

    def test_structural_flags(self):
        g, cc = self.result['name_guard'], self.result['count_cap']
        self.assertEqual(g['input'], 'r13 = [r8+0x10]')
        self.assertEqual(g['error_drop']['free_fn'], '0x54c8cb0')
        self.assertTrue(cc['rejoin_after_doubling'])
        self.assertEqual(cc['record_stride'], 0x38)
        self.assertEqual(cc['loop_stride'], 0x38)
        self.assertEqual(cc['empty_exit_va'], cc['cap_va'])
        self.assertEqual(cc['loop_exit_va'], cc['cap_va'])
        self.assertEqual({b['skip_va'] for b in cc['bypass']}, {cc['bypass_skip_target_va']})
        for c in self.result['callers']:
            self.assertTrue(c['r8_is_rsp_0xc0'], c['call_va'])
            self.assertTrue(c['big_branch_lands_on_movabs'], c['call_va'])
            self.assertEqual(c['fixed_tier_10_stores'], 1, c['call_va'])

    def test_guard_model_and_controls(self):
        self.assertEqual(tool.guard_interval(-17, -17, 'ja'), (1, 16))
        for n, want in ((0, False), (1, True), (16, True), (17, False), (M64, False)):
            self.assertEqual(tool.guard_admits(n, -17, -17, 'ja'), want, n)
        # Off-by-one constants or the other unsigned jcc change the admitted set.
        self.assertEqual(tool.guard_interval(-17, -17, 'jae'), (0, 16))
        self.assertEqual(tool.guard_interval(-16, -17, 'ja'), (0, 15))
        self.assertEqual(tool.guard_interval(-17, -16, 'ja'), (2, 16))
        self.assertIsNone(tool.guard_interval(0, -1, 'ja'))

    def test_cap_model_and_controls(self):
        for t, want in ((-1, M64), (-(1 << 63), M64), (0, 3), (10, 23), (50, 103), ((1 << 63) - 1, M64)):
            self.assertEqual(tool.cap_limit(t, 3), want, t)
            self.assertEqual(tool.reference_limit(t), want, t)
        self.assertNotEqual(tool.cap_limit(0, 4), tool.reference_limit(0))

    def test_tier_model_and_divisor(self):
        m, sh = 0xdbe6fecebdedd5bf, 0x21
        self.assertEqual(tool.divisor_from_magic(m, sh), 10_000_000_000)
        self.assertIsNone(tool.divisor_from_magic(m ^ 0x100, sh))
        self.assertIsNone(tool.divisor_from_magic(m - (1 << 20), sh))
        self.assertEqual(tool.divisor_from_magic(m, sh + 1), 20_000_000_000)
        for x in (0, 9_999_999_999, 10_000_000_000, 399_999_999_999, 400_000_000_000, M64):
            self.assertEqual((x * m) >> (64 + sh), x // 10_000_000_000, x)
        tiers = [tool.tier_of(e, 10_000_000, 10_000_000_000, 40, 10)
                 for e in (0, 9_999_999, 10_000_000, 9_999_999_999, 10_000_000_000, 400_000_000_000, M64)]
        self.assertEqual(tiers, [0, 0, 10, 10, 11, 50, 50])

    def test_decoder_rejects_corrupted_guard(self):
        start = int(self.result['name_guard']['entry_va'], 16)
        img = tool.Image(self.data)
        raw = bytearray(img.read(start, 0x40))
        self.assertTrue(tool.GUARD.match(bytes(raw)))
        jcc = raw.index(b'\x77\x26')
        for patch in (b'\x76', b'\x72'):  # jbe / jb
            bad = bytearray(raw)
            bad[jcc:jcc + 1] = patch
            self.assertIsNone(tool.GUARD.match(bytes(bad)))
        bad = bytearray(raw)
        bad[bad.index(b'\x4d\x8b\x68\x10') + 1] = 0x89  # load becomes a store
        self.assertIsNone(tool.GUARD.match(bytes(bad)))

    def test_corrupted_tag_store_fails_closed(self):
        corrupted = bytearray(self.data)
        img = tool.Image(self.data)
        corrupted[img.off(int(self.result['name_guard']['tag_store_va'], 16)) + 4] = 0x54
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted), skip_digest=True)

    def test_out_of_range_addresses(self):
        img = tool.Image(self.data)
        with self.assertRaises(tool.EvidenceError):
            img.read(0x10, 4)
        with self.assertRaises(tool.EvidenceError):
            tool.Fdes(img).range_of(0x1000)

    def test_generated_files_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(['--out', tmp]), 0)
            for name in GENERATED:
                self.assertTrue(filecmp.cmp(Path(tmp) / name, PACKET / name, shallow=False), name)


if __name__ == '__main__':
    unittest.main()
