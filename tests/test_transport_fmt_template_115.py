import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import transport_fmt_template_115 as tool  # noqa: E402

PACKET = ROOT / 'research/work-items/transport-fmt-template-115'
DATA = (ROOT / tool.BINARY).read_bytes()
BINARY = tool.Binary(DATA)


class Identity(unittest.TestCase):
    def test_target_hash_is_enforced(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), tool.SHA256)
        with self.assertRaises(ValueError):
            tool.Binary(DATA[:-1])
        flipped = bytearray(DATA[:200])
        flipped[100] ^= 1
        with self.assertRaises(ValueError):
            tool.Binary(bytes(flipped) + DATA[200:])

    def test_extents_come_from_fde_records(self):
        self.assertEqual((tool.FMT_VA, BINARY.fmt_end), (0x1680500, 0x16806c0))
        self.assertEqual((tool.DISP_VA, BINARY.disp_end), (0x564ad60, 0x564b1f9))
        with self.assertRaises(ValueError):
            tool.fde_end(DATA, tool.FMT_VA + 1)

    def test_decoder_partitions_both_bodies_exactly(self):
        self.assertEqual(len(BINARY.fmt_code), 138)
        self.assertEqual(len(BINARY.disp_code), 261)
        self.assertEqual(BINARY.fmt_code[0][1:3], ('push', [('r', 5, 8)]))
        # last executable instruction of each body is a return, tail-jump or call-to-nowhere
        self.assertIn(BINARY.fmt_code[-1][1], ('ret', 'jmp'))
        self.assertIn(BINARY.disp_code[-1][1], ('ret', 'jmp'))

    def test_decoder_rejects_unknown_opcode(self):
        with self.assertRaises(ValueError):
            tool.Decoder(b'\x06\x00', 0).decode(0)

    def test_slot_resolves_to_interpreter(self):
        self.assertEqual(BINARY.slots[tool.SLOT_FMT], tool.FMT_VA)

    def test_jump_table_targets_are_the_22_arm_starts(self):
        table = tool.jump_table(BINARY)
        self.assertEqual(len(set(table)), 22)
        self.assertTrue(all(tool.DISP_VA < t < BINARY.disp_end for t in table))


class Interpreter(unittest.TestCase):
    def test_short_literal_then_default_argument(self):
        tmpl = b'\x03abc\xc0\x00'
        args = tool.synthetic_args(1)
        got = tool.emu_format(BINARY, BINARY.fmt_code, tmpl, args, None)
        self.assertEqual(got, tool.model_run(tmpl, args, None))
        self.assertEqual(got[0], 0)
        self.assertEqual(got[1][0], ('w', b'abc'))
        self.assertEqual(got[1][1], ('a', (0,), tool.DEFAULT_FLAGS, 0, 0))

    def test_long_literal_uses_little_endian_u16(self):
        body = bytes(range(200))
        tmpl = b'\x80' + (200).to_bytes(2, 'little') + body + b'\x00'
        got = tool.emu_format(BINARY, BINARY.fmt_code, tmpl, [], None)
        self.assertEqual(got, (0, [('w', body)]))

    def test_spec_byte_fields_and_count_references(self):
        # bits: flags, width-from-arg, precision, explicit index
        spec = bytes([0xc0 | 1 | 2 | 4 | 8 | 0x10]) + (0x1234).to_bytes(4, 'little') + \
            (1).to_bytes(2, 'little') + (7).to_bytes(2, 'little') + (1).to_bytes(2, 'little')
        tmpl = spec + b'\x00'
        args = tool.synthetic_args(2)
        got = tool.emu_format(BINARY, BINARY.fmt_code, tmpl, args, None)
        self.assertEqual(got, tool.model_run(tmpl, args, None))
        self.assertEqual(got[1][0], ('a', (1,), 0x1234, args[1]['count'], 7))

    def test_sink_failure_stops_and_returns_one(self):
        tmpl = b'\x01a\xc0\x01b\x00'
        args = tool.synthetic_args(1)
        for fail, writes in ((1, 1), (2, 2), (3, 3), (None, 3)):
            got = tool.emu_format(BINARY, BINARY.fmt_code, tmpl, args, fail)
            self.assertEqual(got, tool.model_run(tmpl, args, fail))
            self.assertEqual(sum(1 for e in got[1] if e[0] == 'w'), writes)
            self.assertEqual(got[0], 0 if fail is None else 1)

    def test_plain_string_fast_path(self):
        got = tool.emu_format(BINARY, BINARY.fmt_code, None, [], None, plain=b'hello')
        self.assertEqual(got, (0, [('w', b'hello')]))
        self.assertEqual(tool.emu_format(BINARY, BINARY.fmt_code, None, [], 1, plain=b'hello')[0], 1)

    def test_random_cases_agree(self):
        for i, (tmpl, args, fail) in enumerate(tool.random_cases(300, seed=99)):
            same, got, want = tool.check_format(BINARY, BINARY.fmt_code, tmpl, args, fail)
            self.assertTrue(same, (i, got, want))

    def test_census_templates_agree(self):
        sites, templates = tool.census(BINARY)
        self.assertEqual(len(sites), 1143)
        self.assertEqual(len(templates), 337)
        for va in sorted(templates)[::8]:
            info = templates[va]
            args = tool.synthetic_args(info['nargs'])
            for fail in (None, 1, 2):
                same, got, want = tool.check_format(BINARY, BINARY.fmt_code, info['bytes'], args, fail)
                self.assertTrue(same, (hex(va), fail, got, want))

    def test_parse_template_rejects_non_rodata_and_runaway(self):
        self.assertIsNone(tool.parse_template(BINARY, tool.FMT_VA))
        self.assertIsNone(tool.parse_template(BINARY, 0x10, limit=8))


class DisplayBody(unittest.TestCase):
    def test_every_tag_matches_model(self):
        for tag in range(0, tool.MAX_TAG + 1):
            for fail in (None, 1, 2):
                self.assertEqual(tool.display_emu(BINARY, BINARY.fmt_code, BINARY.disp_code, tag, fail),
                                 tool.display_model(BINARY, tag, fail), (tag, fail))

    def test_arm_selection(self):
        self.assertEqual([tool.arm_for_tag(t) for t in (0, 0x2d, 0x2e, 0x2f, 0x43)], [3, 3, 0, 1, 21])

    def test_known_messages(self):
        _, ev = tool.display_emu(BINARY, BINARY.fmt_code, BINARY.disp_code, 0x2e + 6, None)
        self.assertEqual(ev, [('w', b'Timed out connecting to peer')])
        _, ev = tool.display_emu(BINARY, BINARY.fmt_code, BINARY.disp_code, 0x2e + 19, None)
        self.assertEqual(ev[0], ('w', b'Invalid config file ('))
        self.assertEqual(ev[3], ('w', b'): '))

    def test_tags_past_the_jump_table_are_not_modelled(self):
        with self.assertRaises(Exception):
            tool.display_emu(BINARY, BINARY.fmt_code, BINARY.disp_code, tool.MAX_TAG + 1, None)


class Printers(unittest.TestCase):
    def test_u64_decimal_boundaries(self):
        for v in tool.interesting_u64():
            self.assertEqual(tool.u64_emu(BINARY, v), tool.u64_model(v), v)

    def test_u64_pad_integral_arguments(self):
        status, log = tool.u64_emu(BINARY, 18446744073709551615)
        self.assertEqual(status, 0)
        self.assertEqual(log[0][1:], (tool.FMTOBJ_BASE, 1, 1, 0, b'18446744073709551615'))

    def test_string_forward_reads_pointer_and_length(self):
        self.assertEqual(tool.string_emu(BINARY, 0x1234, 0x56), tool.string_model(0x1234, 0x56))

    def test_reference_forward_dereferences_once(self):
        self.assertEqual(tool.ref_emu(BINARY, 0xabcdef), tool.ref_model(0xabcdef))

    def test_wrapper_runs_interpreter_on_lone_default_argument(self):
        for fail in (None, 1):
            self.assertEqual(tool.wrap_emu(BINARY, 77, fail), tool.wrap_model(BINARY, 77, fail))
        status, log = tool.wrap_emu(BINARY, 77, 1)
        self.assertEqual(status, 1)

    def test_printer_mutations_are_caught(self):
        for mut in tool.printer_mutations():
            self.assertTrue(tool.printer_detects(BINARY, mut, count=3), mut[0])


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_caught(self):
        cases = tool.control_set(BINARY)
        emu = [tool.emu_format(BINARY, BINARY.fmt_code, t, a, f) for t, a, f in cases]
        for mut in tool.MODEL_MUTANTS:
            self.assertTrue(any(tool.model_differs(lambda: tool.model_run(t, a, f, mut=mut), emu[i])
                                for i, (t, a, f) in enumerate(cases)), mut)

    def test_byte_corruptions_are_caught(self):
        cases = tool.control_set(BINARY)[:60]
        tags = list(range(0, tool.MAX_TAG + 1))
        muts = tool.byte_mutations(BINARY)
        self.assertGreaterEqual(len(muts), 25)
        for mut in muts[::3]:
            self.assertTrue(tool.detects(BINARY, mut, cases, tags), mut[0])

    def test_unmutated_bytes_are_not_flagged(self):
        cases = tool.control_set(BINARY)[:40]
        same = ('noop', 'fmt', 0, BINARY.fmt_bytes()[:1])
        self.assertFalse(tool.detects(BINARY, same, cases, [0x2e, 0x40]))


class Reproduction(unittest.TestCase):
    def test_committed_evidence_regenerates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            tool.build(BINARY, out)
            names = sorted(p.name for p in out.iterdir())
            committed = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
            self.assertEqual(names, committed)
            for name in names:
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)
            measure = json.loads((out / 'measure.json').read_text())
            self.assertEqual(measure['negative_controls'], measure['negative_detected'])
            self.assertGreaterEqual(measure['cases'], 10000)


if __name__ == '__main__':
    unittest.main()
