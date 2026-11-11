import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import risk_outcome_enum_entry_115 as tool  # noqa: E402

PACKET = ROOT / 'research/work-items/risk-outcome-enum-entry-115'
DATA = tool.TARGET.read_bytes()
IMAGE = tool.base.Image(DATA)
_, RECS, _ = tool.fde_extents.fde_extents(DATA)
RIG = tool.Rig(IMAGE, RECS)
FAM1, FAM2 = tool.ENTRIES


def run(text, flag=0, rem=128, spec=FAM1, rig=RIG):
    return tool.run_enum(rig, spec, text, flag, rem)


class EnumEntry115(unittest.TestCase):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), tool.SHA115)

    def test_bare_identifier_unit_variant(self):
        for spec in tool.ENTRIES:
            outcome, idx, rem, seq = run(b' "Question"', spec=spec)
            self.assertEqual((outcome, idx, rem, seq), (('unit',), 11, 128, ['ident']))

    def test_bare_identifier_struct_variants_are_invalid_type(self):
        for name in (b'StandaloneOutcome', b'QuestionOutcome'):
            for spec in tool.ENTRIES:
                outcome, idx, rem, seq = run(b'"' + name + b'"', spec=spec)
                self.assertEqual(outcome, ('err', ('invalid_unit', 0xd)))
                self.assertEqual(seq, ['ident', 'invalid_unit'])

    def test_unit_variant_in_map_needs_null(self):
        outcome, idx, rem, seq = run(b'{"Question":null}')
        self.assertEqual((outcome, idx, rem, seq), (('unit',), 17, 128, ['key', 'null']))
        outcome, idx, _, _ = run(b'{"Question":nul')
        self.assertEqual((outcome, idx), (('err', ('error_at', 5, 15)), 15))
        outcome, idx, _, _ = run(b'{"Question":nulx}')
        self.assertEqual((outcome, idx), (('err', ('error_at', 9, 16)), 16))
        outcome, idx, _, _ = run(b'{"Question":{}}')
        self.assertEqual(outcome, ('err', ('fix_position', ('peek_invalid_type', 12, tool.NULL_EXPECTED[1]))))

    def test_struct_variants_consume_one_value_then_close(self):
        outcome, idx, rem, seq = run(b'{"StandaloneOutcome":{"side_names":[]}}')
        self.assertEqual(outcome[0], 'words')
        self.assertEqual((idx, rem, seq), (39, 128, ['key', 'payload0']))
        self.assertEqual(outcome[1][0] >> 32 & 0xffff, 0)
        outcome, idx, rem, seq = run(b'{"QuestionOutcome":{"parent":1}}')
        self.assertEqual(outcome[1][0] >> 32 & 0xffff, 2)
        self.assertEqual(seq, ['key', 'payload2'])
        for spec in tool.ENTRIES:
            outcome, idx, rem, seq = run(b'{"QuestionOutcome":{"parent":1}} ', spec=spec)
            self.assertEqual((outcome[0], idx), ('words', 32))

    def test_trailing_exits_drop_the_payload(self):
        outcome, idx, rem, seq = run(b'{"StandaloneOutcome":{}')
        self.assertEqual((outcome, idx, seq), (('err', ('error_at', 3, 23)), 23, ['key', 'payload0', 'error_at', 'drop']))
        outcome, idx, rem, seq = run(b'{"StandaloneOutcome":{}x}')
        self.assertEqual((outcome, idx, seq[-2:]), (('err', ('error_at', 10, 23)), 23, ['error_at', 'drop']))

    def test_recursion_budget(self):
        self.assertEqual(run(b'{"Question":null}', 0, 128)[2], 128)      # charged and refunded
        self.assertEqual(run(b'{"Question":null}', 1, 0)[0], ('unit',))   # disabled flag: budget untouched
        outcome, idx, rem, _ = run(b'{"Question":null}', 0, 1)           # last unit charged: limit error
        self.assertEqual((outcome, idx, rem), (('err', ('peek_error', 0x18, 0)), 0, 0))
        outcome, idx, rem, seq = run(b'{"Question":null}', 0, 2)
        self.assertEqual((outcome, rem), (('unit',), 2))
        self.assertEqual(run(b'{"Question":null}', 0, 0)[0], ('panic', 'sub'))
        outcome, idx, rem, _ = run(b'{"Other":1}', 0, 5)                 # error exits refund too
        self.assertEqual(rem, 5)

    def test_error_codes(self):
        self.assertEqual(run(b'')[0], ('err', ('peek_error', 5, 0)))
        self.assertEqual(run(b'  ')[0], ('err', ('peek_error', 5, 2)))
        self.assertEqual(run(b'[1]')[0], ('err', ('peek_error', 10, 0)))
        self.assertEqual(run(b'\x0b"Question"')[0], ('err', ('peek_error', 10, 0)))

    def test_both_copies_agree_on_every_probe(self):
        for text in tool.BASES:
            a = tool.norm(run(text, spec=FAM1))
            b = tool.norm(run(text, spec=FAM2))
            self.assertEqual(a[0][0], b[0][0])
            self.assertEqual(a[1:], b[1:])

    def test_reconstruction_matches_interpreter_on_probes(self):
        for spec in tool.ENTRIES:
            for text in tool.BASES:
                for flag, rem in tool.DEPTH_STATES:
                    self.assertTrue(tool.compare(RIG, spec, text, flag, rem), (spec[1], text, flag, rem))

    def test_wrong_reconstructions_disagree(self):
        probes = [(t, st) for t in tool.BASES for st in tool.DEPTH_STATES]
        for name, M in tool.RECON_MUTANTS:
            lost = 0
            for spec in tool.ENTRIES:
                for text, (flag, rem) in probes:
                    if not tool.compare(RIG, spec, text, flag, rem, M):
                        lost += 1
            self.assertGreater(lost, 0, name)

    def test_code_corruptions_are_caught(self):
        probes = [(t, st) for t in tool.BASES for st in tool.DEPTH_STATES]
        for name, off, old, new in tool.BYTE_MUTANTS:
            for spec in tool.ENTRIES:
                fo = tool.file_offset(IMAGE, spec[0] + off)
                self.assertEqual(DATA[fo], old, name)
                mimage = tool.base.Image(tool.patch_copy(DATA, [(fo, bytes([new]))]))
                mrig = tool.Rig(mimage, RECS)
                lost = sum(tool.mutant_lost(mrig, spec, t, f, r) for t, (f, r) in probes)
                self.assertGreater(lost, 0, (name, spec[1]))

    def test_jump_table_corruptions_are_caught(self):
        probes = [(t, st) for t in tool.BASES for st in tool.DEPTH_STATES]
        for name, table, i, j in tool.TABLE_MUTANTS:
            fo = tool.file_offset(IMAGE, table)
            ei, ej = DATA[fo + 4 * i:fo + 4 * i + 4], DATA[fo + 4 * j:fo + 4 * j + 4]
            mimage = tool.base.Image(tool.patch_copy(DATA, [(fo + 4 * i, ej), (fo + 4 * j, ei)]))
            mrig = tool.Rig(mimage, RECS)
            lost = sum(tool.mutant_lost(mrig, FAM1, t, f, r) for t, (f, r) in probes)
            self.assertGreater(lost, 0, name)

    def test_ud2_at_entry_is_rejected(self):
        fo = tool.file_offset(IMAGE, FAM1[0])
        mimage = tool.base.Image(tool.patch_copy(DATA, [(fo, b'\x0f\x0b')]))
        mrig = tool.Rig(mimage, RECS)
        with self.assertRaises(tool.Reject):
            run(b'"Question"', rig=mrig)

    def test_unmodelled_call_and_wrong_input_are_rejected(self):
        with self.assertRaises(tool.Reject):
            tool.build(b'not the node')
        with self.assertRaises(tool.Reject):
            IMAGE.read(0x20, 4)                      # below the first section
        with self.assertRaises(tool.Reject):
            tool.base.Machine(IMAGE, {}).load(0x2000_0000, 1)   # unset scratch byte
        m = tool.base.Machine(IMAGE, {})
        m.regs[7], m.regs[6] = tool.base.OUT_BASE, tool.base.DE_BASE
        for k in range(0x30):
            m.store(tool.base.DE_BASE + k, 0, 1)
        m.store(tool.base.DE_BASE + 0x20, 1, 8)
        m.store(tool.base.DATA_BASE, 0x22, 1)
        m.store(tool.base.DE_BASE + 0x18, tool.base.DATA_BASE, 8)
        with self.assertRaises(tool.Reject):
            m.run(FAM1[0])

    def test_main_rejects_a_wrong_binary(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / 'a.bin'
            bad.write_bytes(b'x' * 64)
            self.assertEqual(tool.main(['--out', str(Path(d) / 'o'), '--binary', str(bad)]), 1)

    def test_inputs_are_deterministic_and_cover_all_paths(self):
        a, b = list(tool.case_list()), list(tool.case_list())
        self.assertEqual(a, b)
        self.assertGreaterEqual(len(a) * 2, 10000)

    def test_packet_matches_generator(self):
        self.assertTrue(PACKET.exists())
        result = tool.build(DATA)
        files, summary = tool.render(result)
        self.assertEqual(summary['mismatches'], 0)
        self.assertEqual(summary['negative_detected'], summary['negative_controls'])
        self.assertGreaterEqual(summary['negative_controls'], 30)
        for name, text in files.items():
            self.assertEqual((PACKET / name).read_text(encoding='ascii'), text, name)
        measure = json.loads((PACKET / 'measure.json').read_text())
        self.assertEqual(measure['cases'], summary['cases'])


if __name__ == '__main__':
    unittest.main()
