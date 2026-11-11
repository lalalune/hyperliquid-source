import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_error_display_115 as awed  # noqa: E402

PACKET = ROOT / 'research/work-items/action-wire-error-display-115'
DATA = awed.TARGET.read_bytes()


class ActionWireErrorDisplay115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = awed.build(DATA)
        (cls.img, cls.rows, cls.targets, cls.start, cls.end, cls.cases, cls.bad, cls.ctl) = cls.built
        cls.files = awed.render(*cls.built[0:1], *cls.built[1:])

    def test_digest_gate(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), awed.DIGEST)
        with self.assertRaises(SystemExit):
            awed.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_body_extent(self):
        self.assertEqual((self.start, self.end), (0x46ef710, 0x46f312f))
        self.assertEqual(self.end - self.start, 14879)

    def test_every_tag_agrees(self):
        self.assertEqual(self.bad, 0)
        self.assertEqual(self.cases, awed.SLOTS * awed.VARIANTS)
        self.assertGreaterEqual(self.cases, 10000)

    def test_arm_kinds(self):
        kinds = [r[2] for r in self.rows]
        self.assertEqual((kinds.count('S'), kinds.count('T')), (337, 81))
        self.assertEqual(len({r[1] for r in self.rows}), 418)

    def test_table_targets_inside_body(self):
        for t in self.targets:
            self.assertTrue(self.start <= t < self.end)

    def test_known_arms(self):
        text = {r[0]: r for r in self.rows}
        self.assertEqual(self.img.read(text[3][3], text[3][4]), b'Vault name is shorter than 3 characters.')
        pieces, n = awed.parse_template(self.img, text[0][3])
        self.assertEqual(pieces, [('L', b'Duplicate vault address '), ('A',)])
        self.assertEqual(n, 27)
        self.assertEqual(len(text[0][4]), 1)

    def test_unjail_arm_constant(self):
        arm = [r for r in self.rows if r[2] == 'T' and self.img.read(r[3], 8) == b'$Can onl']
        self.assertEqual(len(arm), 1)
        self.assertEqual(arm[0][4][0][1], ('si', 0x4072c00000000000))

    def test_template_grammar(self):
        for r in self.rows:
            if r[2] == 'T':
                pieces, _ = awed.parse_template(self.img, r[3])
                self.assertEqual(sum(1 for p in pieces if p[0] == 'A'), len(r[4]))
        img = awed.Image(DATA)
        img.patch = {r[3]: 0xc1 for r in self.rows[:1]}
        with self.assertRaises(awed.Reject):
            awed.parse_template(img, self.rows[0][3])

    def test_long_literal_form(self):
        pieces, n = awed.parse_template(self.img, self.rows[82][3])
        self.assertEqual([p[0] for p in pieces], ['L', 'A', 'L'])
        self.assertEqual(len(pieces[2][1]), 166)
        self.assertEqual(self.img.read(self.rows[82][3] + 49, 4), b'\xc0\x80\xa6\x00')
        self.assertEqual(awed.grammar_violations(self.img, self.rows), 0)
        self.assertGreater(awed.grammar_violations(self.img, self.rows, 'short-80'), 0)

    def test_display_text_matches_evidence(self):
        lines = self.files['arms.tsv'].split('\n')[1:419]
        for line in lines:
            f = line.split('\t')
            got = awed.display_text(self.img, self.rows, int(f[0]))
            self.assertEqual(awed.esc(got), f[7])

    def test_display_segments_shape(self):
        seg = awed.display_segments(self.img, self.rows, 205)
        self.assertEqual([x[0] for x in seg], ['text', 'arg'])
        self.assertEqual(seg[0][1], b'Invalid nonce: duplicate nonce ')
        seg = awed.display_segments(self.img, self.rows, 203)
        self.assertEqual([x[0] for x in seg], ['text', 'arg', 'text', 'arg'])
        self.assertEqual(awed.display_text(self.img, self.rows, 203), b'Invalid nonce: nonce too low {} < {}')
        with self.assertRaises(IndexError):
            awed.display_segments(self.img, self.rows, 418)

    def test_entry_references(self):
        refs = awed.entry_references(self.img, DATA)
        self.assertEqual(len(refs), 19)
        self.assertEqual(len({r[2] for r in refs}), 13)
        self.assertEqual(refs, sorted(refs))
        saved = awed.GOT_ENTRY_SLOT
        awed.GOT_ENTRY_SLOT = saved + 8
        try:
            self.assertNotEqual(len(awed.entry_references(self.img, DATA)), 19)
        finally:
            awed.GOT_ENTRY_SLOT = saved

    def test_single_interpreter(self):
        self.assertEqual(json.loads(self.files['summary.json'])['template_interpreter_target'], '0x1680500')
        targets = set()
        for r in self.rows:
            if r[2] == 'T':
                targets.add(awed.emulate(self.img, r[0], awed.payload_for(r[0], 0))[1])
        self.assertEqual(targets, {awed.INTERP[0]})

    def test_emulator_rejects_unknown_opcode(self):
        img = awed.Image(DATA)
        img.patch = {0x46ef710: 0x90}
        with self.assertRaises(awed.Reject):
            awed.emulate(img, 3, awed.payload_for(3, 0))

    def test_emulator_rejects_store_outside_stack(self):
        m = awed.Machine(self.img, awed.payload_for(0, 0))
        with self.assertRaises(awed.Reject):
            m.write(awed.PB, b'x')

    def test_wrong_model_is_caught(self):
        rows = list(self.rows)
        r = rows[3]
        rows[3] = r[:4] + (r[4] + 1,)
        cases, bad = awed.check(self.img, rows, [3], 4)
        self.assertEqual((cases, bad), (4, 4))

    def test_tag_outside_table_is_undefined(self):
        cases, bad = awed.check(self.img, self.rows, [418], 2)
        self.assertEqual(bad, 2)

    def test_corrupt_table_byte_is_caught(self):
        self.img.patch = {awed.TABLE_VA + 4 * 5: self.img.byte(awed.TABLE_VA + 4 * 5) ^ 4}
        try:
            cases, bad = awed.check(self.img, self.rows, [5], 3)
        finally:
            self.img.patch = {}
        self.assertEqual(bad, 3)

    def test_all_controls_detected(self):
        self.assertGreaterEqual(len(self.ctl), 30)
        self.assertTrue(all(c[3] for c in self.ctl))

    def test_measure_matches_summary(self):
        m = json.loads(self.files['measure.json'])
        s = json.loads(self.files['summary.json'])
        self.assertEqual(m['cases'], s['cases'])
        self.assertEqual(m['negative_detected'], m['negative_controls'])

    def test_packet_files_match_regeneration(self):
        self.assertTrue(PACKET.exists())
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_text(), text, name)


if __name__ == '__main__':
    unittest.main()
