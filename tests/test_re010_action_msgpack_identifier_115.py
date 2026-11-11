import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    're010_action_msgpack_identifier_115', ROOT / 'tools' / 're010_action_msgpack_identifier_115.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / 'research' / 'work-items' / 'RE-010-action-msgpack-identifier-115'


class MsgpackIdentifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.img = tool.Image(cls.data)
        cls.copies = [tool.Copy(cls.img, label, start) for label, start in tool.COPIES]
        for c in cls.copies:
            c.bind_consts(cls.copies[0])
        cls.cases = tool.build_cases()

    def test_digest_is_checked(self):
        bad = bytearray(self.data)
        bad[-1] ^= 0xff
        with self.assertRaises(ValueError):
            tool.Image(bytes(bad))

    def test_copies_share_shape_and_tables(self):
        base = self.copies[0]
        for c in self.copies:
            self.assertEqual(c.end - c.start, tool.FUNC_SIZE)
            self.assertEqual([tool.shape(i) for i in c.insns], [tool.shape(i) for i in base.insns])
            self.assertEqual([a - c.start for a in c.marker_arms], [a - base.start for a in base.marker_arms])
            self.assertEqual([a - c.start for a in c.ext_arms], [a - base.start for a in base.ext_arms])
        self.assertEqual(len(base.insns), 454)
        ud2 = {i.va for i in base.insns if i.op == 'ud2'}
        live = [t for t, a in enumerate(base.marker_arms) if a not in ud2]
        self.assertEqual(sorted(live), sorted(tool.VALID_TAGS))

    def test_model_matches_bytes_on_every_copy(self):
        for c in self.copies:
            m = tool.Machine(self.img, c)
            for case in self.cases[::7]:
                self.assertEqual(m.run(case), tool.reconstructed_decode(*case, consts=c.consts), (c.label, case))

    def test_key_rules(self):
        c1 = tool.C1_CONSTS
        run = tool.reconstructed_decode
        knob = (('err', 5), None)
        self.assertEqual(run(b'', None, 2, 0, knob)[0], ('io', 0, c1['static_eof']))
        self.assertEqual(run(b'\xda\x00', None, 2, 0, knob)[2][0], 2)  # short length read consumes the rest
        self.assertEqual(run(b'\xa3ab', None, 2, 0, knob)[0], ('io', 1, tool.SIMPLE_EOF))
        self.assertEqual(run(b'\x81', None, 2, 0, (('ok', 3), None))[0], ('length_mismatch', 0))
        self.assertEqual(run(b'\x80', None, 1, 0, knob)[0], ('depth',))
        self.assertEqual(run(b'\x80', None, 0, 0, knob)[0], ('panic_sub', c1['map']))
        self.assertEqual(run(b'\x90', None, 3, 0, knob)[2][2], 2)  # depth stays decremented on error
        self.assertEqual(run(b'\xc1', None, 2, 0, knob)[0], ('type_mismatch', 0xc1))
        self.assertEqual(run(b'\xa4ord\xff', None, 2, 0, (('ok', 7), None))[0], ('ok', 7))

    def test_wrong_reconstructions_are_rejected(self):
        for variant in tool.MODEL_MUTANTS:
            self.assertTrue(any(tool.reconstructed_decode(*case, variant=variant)
                                != tool.reconstructed_decode(*case) for case in self.cases), variant)

    def test_corrupted_table_entry_is_detected(self):
        base = self.copies[0]
        mut = bytearray(self.data)
        mut[self.img.off(base.marker_va + 4 * 0xc4)] ^= 0x01
        mimg = tool.Image(bytes(mut), check=False)
        mc = tool.Copy(mimg, 'C1', base.start)
        mc.consts = base.consts
        m = tool.Machine(mimg, mc)
        case = (b'\xc4\x01a', None, 2, 1, (('err', 5), None))
        try:
            got = m.run(case)
        except tool.Fault:
            got = None
        self.assertNotEqual(got, tool.reconstructed_decode(*case))

    def test_non_marker_tag_and_out_of_range(self):
        m = tool.Machine(self.img, self.copies[0])
        with self.assertRaises(tool.Fault):  # tag 0x05 is not a Marker value: its table entry is ud2
            m.run((b'', (0x05, 0), 2, 0, (('err', 5), None)))
        # tag 1 is the "no peeked marker" niche: the copy reads a fresh marker instead
        self.assertEqual(m.run((b'', (0x01, 0), 2, 0, (('err', 5), None)))[0][0], 'io')
        with self.assertRaises(ValueError):
            tool.reconstructed_decode(b'', (0x05, 0), 2, 0, (('err', 5), None))
        with self.assertRaises(tool.Fault):
            tool.Copy(self.img, 'X', self.copies[0].start + 1)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp, self.data)
            self.assertEqual(summary['mismatches'], 0)
            for name in ('copies.tsv', 'tables.tsv', 'insns.tsv', 'cases.tsv', 'coverage.tsv', 'mutants.tsv',
                         'summary.json'):
                self.assertEqual(hashlib.sha256((Path(tmp) / name).read_bytes()).hexdigest(),
                                 hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), name)


if __name__ == '__main__':
    unittest.main()
