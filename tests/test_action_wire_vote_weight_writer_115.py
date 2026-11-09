import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_vote_weight_writer_115 as w  # noqa: E402

DATA = w.TARGET.read_bytes()
IMAGE = w.Image(DATA)
FAM = w.FAMILIES[0]


class Reconstruction(unittest.TestCase):
    """The pure-Python reconstruction on its own, against hand-computed encodings."""

    def test_uint_forms(self):
        cases = {0: '00', 127: '7f', 128: 'cc80', 255: 'ccff', 256: 'cd0100', 65535: 'cdffff',
                 65536: 'ce00010000', (1 << 32) - 1: 'ceffffffff', 1 << 32: 'cf0000000100000000',
                 w.MASK: 'cfffffffffffffffff'}
        for value, expected in cases.items():
            got = w.recon_writer(value, 64, 0)
            self.assertEqual(got[0], 'ok')
            self.assertEqual(got[1], expected, value)
            self.assertEqual(got[2], len(expected) // 2)

    def test_record_forms(self):
        got = w.recon_record(1, 0, 5, 64, 0)
        self.assertEqual(bytes.fromhex(got[1]), b'\x82\xa6choice\xa3yes\xa6weight\x05')
        got = w.recon_record(0, 1, 300, 64, 0)
        self.assertEqual(bytes.fromhex(got[1]), b'\x92\xa2no\xcd\x01\x2c')
        got = w.recon_record(2, 0, 5, 64, 0)
        self.assertEqual(bytes.fromhex(got[1]), b'\xb2\xa6choice\xa3yes\x05')
        got = w.recon_record(3, 1, 5, 64, 0)
        self.assertEqual(bytes.fromhex(got[1]), b'\xa2\xa6choice\xa2no\x05')
        got = w.recon_record(0, 77, 1 << 40, 64, 0)
        self.assertEqual(bytes.fromhex(got[1]), b'\x92\xa7abstain\xcf\x00\x00\x01\x00\x00\x00\x00\x00')

    def test_reserve_edges(self):
        # one-byte reserve only when the buffer is exactly full; wider ones when fewer than n bytes are spare
        self.assertEqual(w.recon_writer(5, 3, 3)[6], ((3, 1),))
        self.assertEqual(w.recon_writer(5, 4, 3)[6], ())
        self.assertEqual(w.recon_writer(300, 7, 5)[6], ((6, 2),))
        self.assertEqual(w.recon_writer(300, 8, 5)[6], ())

    def test_grow_rules(self):
        self.assertEqual(w.recon_reserve_call(0, 0x100, 0, 1, 1, 1)[1], 8)
        self.assertEqual(w.recon_reserve_call(0, 0x100, 0, 1, 1, 2)[1], 4)
        self.assertEqual(w.recon_reserve_call(0, 0x100, 0, 1, 1, 0x401)[1], 1)
        self.assertEqual(w.recon_reserve_call(100, 0x100, 0, 1, 1, 1)[1], 200)
        self.assertEqual(w.recon_reserve_call(3, 0x100, 90, 10, 1, 1)[1], 100)
        self.assertEqual(w.recon_reserve_call(1 << 63, 0x100, 0, 1, 1, 1)[1], 8)
        self.assertEqual(w.recon_reserve_call(8, 0x100, w.MASK, 1, 1, 1), ('abort', 0, w.MASK))
        self.assertEqual(w.recon_reserve_call(8, 0x100, 0, 1, 1, 0), ('abort', 0, 0))
        self.assertEqual(w.recon_reserve_call(8, 0x100, 8, 1, 1, 1, fail=True), ('abort', w.ERR1, w.ERR2))

    def test_status_branch(self):
        got = w.recon_record(0, 0, 9, 64, 0, status=(1, 0x55))
        self.assertEqual(got[5][:48], (w.BORROWED.to_bytes(8, 'little') + (1).to_bytes(8, 'little')
                                       + (0x55).to_bytes(8, 'little')).hex())

    def test_out_of_range_inputs(self):
        with self.assertRaises(ValueError):
            w.recon_writer(1 << 64, 8, 0)
        with self.assertRaises(ValueError):
            w.recon_record(0, 256, 1, 8, 0)
        with self.assertRaises(ValueError):
            w.recon_record(0, 0, -1, 8, 0)


class Machinery(unittest.TestCase):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), w.SHA115)

    def test_bodies_are_fde_extents(self):
        _, recs, _ = w.fde_extents.fde_extents(DATA)
        starts = {r['start']: r for r in recs}
        for fam in w.FAMILIES:
            for va in fam[:3]:
                self.assertIn(va, starts)
        self.assertEqual(starts[0x231e050]['end'] - 0x231e050, 142)
        self.assertEqual(starts[0x25e9f10]['end'] - 0x25e9f10, 901)
        self.assertEqual(starts[0x241cb90]['end'] - 0x241cb90, 1048)

    def test_every_body_decodes_to_its_fde_end(self):
        _, recs, _ = w.fde_extents.fde_extents(DATA)
        starts = {r['start']: r for r in recs}
        for fam in w.FAMILIES:
            for va in fam[:3]:
                rows = w.linear_rows(IMAGE, va, starts[va]['end'])
                self.assertEqual(sum(r.length for r in rows), starts[va]['end'] - va)

    def test_reject_unknown_start(self):
        _, recs, _ = w.fde_extents.fde_extents(DATA)
        with self.assertRaises(w.Reject):
            w.require_start({r['start']: r for r in recs}, 0x241cba5)

    def test_reject_wrong_digest(self):
        bad = bytearray(DATA)
        bad[12345] ^= 1
        with self.assertRaises(w.Reject):
            w.build_guard(bad)

    def test_decoder_new_forms(self):
        cases = {0x241cba9: ('shl', 4), 0x25e9f21: ('test', None), 0x25e9fd4: ('bswap', None),
                 0x25e9f78: ('rol', 8), 0x231e079: ('cmov', 7), 0x231e086: ('setcc', 2)}
        for va, (op, imm) in cases.items():
            ins = w.decode(IMAGE, va)
            self.assertEqual(ins.op, op, hex(va))
            if imm is not None:
                self.assertEqual(ins.imm, imm, hex(va))


class Interpreter(unittest.TestCase):
    """Original machine code against the reconstruction, spot checks on every family."""

    def test_writer_all_families(self):
        for fam in w.FAMILIES:
            for value in (0, 127, 128, 255, 256, 65535, 65536, 1 << 32, w.MASK):
                for cap, length in ((16, 0), (3, 3), (7, 5)):
                    got, _ = w.run_writer(IMAGE, fam, value, cap, length)
                    self.assertEqual(got, w.recon_writer(value, cap, length), (hex(fam[1]), value, cap, length))

    def test_record_all_families(self):
        for fam in w.FAMILIES:
            for flag in (0, 1, 2, 3, 255):
                for tag in (0, 1, 2, 200):
                    for cap, length in ((64, 0), (1, 1), (8, 5), (12, 6)):
                        p = (flag, tag, 70000, cap, length, False, None)
                        got, _ = w.run_record(IMAGE, fam, *p)
                        self.assertEqual(got, w.recon_record(*p), (hex(fam[0]), p))

    def test_record_writer_error_passthrough(self):
        for fam in w.FAMILIES:
            p = (1, 1, 5, 40, 0, False, (3, 0x99))
            got, _ = w.run_record(IMAGE, fam, *p)
            self.assertEqual(got, w.recon_record(*p))
            self.assertEqual(bytes.fromhex(got[5][:48])[:8], w.BORROWED.to_bytes(8, 'little'))

    def test_allocation_failure_aborts(self):
        for fam in w.FAMILIES:
            got, _ = w.run_writer(IMAGE, fam, 300, 3, 3, True)
            self.assertEqual(got, ('abort', w.ERR1, w.ERR2))
            got, _ = w.run_reserve(IMAGE, fam, 8, 0x4444_0000, 8, 1, 1, 1, True)
            self.assertEqual(got, ('abort', w.ERR1, w.ERR2))

    def test_reserve_overflow_and_zero_element(self):
        for fam in w.FAMILIES:
            got, _ = w.run_reserve(IMAGE, fam, 8, 0x4444_0000, w.MASK, 2, 1, 1)
            self.assertEqual(got, ('abort', 0, w.MASK))
            got, _ = w.run_reserve(IMAGE, fam, 8, 0x4444_0000, 4, 2, 1, 0)
            self.assertEqual(got, ('abort', 0, 4))

    def test_three_copies_agree(self):
        outs = {tuple(w.run_record(IMAGE, fam, 1, 1, 77777, 11, 3)[0] for fam in [f]) for f in w.FAMILIES}
        self.assertEqual(len(outs), 1)


class Controls(unittest.TestCase):
    """The comparison must notice a wrong reconstruction, a damaged code byte and bad input."""

    def test_wrong_threshold_caught(self):
        bad = w.recon_writer(127, 16, 0, plan=lambda v: w.uint_plan(v, th=(0x7f, 0x100, 0x10000, 1 << 32)))
        got, _ = w.run_writer(IMAGE, FAM, 127, 16, 0)
        self.assertNotEqual(bad, got)

    def test_wrong_endianness_caught(self):
        bad = w.recon_writer(0x1234, 16, 0, plan=lambda v: w.uint_plan(v, big=False))
        got, _ = w.run_writer(IMAGE, FAM, 0x1234, 16, 0)
        self.assertNotEqual(bad, got)

    def test_wrong_header_caught(self):
        bad = w.recon_record(1, 0, 1, 16, 0, header=lambda f: 0x92 if f else 0x82)
        got, _ = w.run_record(IMAGE, FAM, 1, 0, 1, 16, 0)
        self.assertNotEqual(bad, got)

    def test_corrupted_code_byte_caught(self):
        patched = w.PatchedImage(IMAGE, {0x25e9f18 + 4: 0x03})   # cmp $0x100 -> cmp $0x300
        good, _ = w.run_writer(IMAGE, FAM, 0x200, 16, 0)
        bad, _ = w.run_writer(patched, FAM, 0x200, 16, 0)
        self.assertEqual(good[1], 'cd0200')
        self.assertNotEqual(good, bad)

    def test_corrupted_reserve_byte_caught(self):
        patched = w.PatchedImage(IMAGE, {0x231e092 + 1: 0x0c})   # minimum capacity 8 -> 12
        good, _ = w.run_reserve(IMAGE, FAM, 0, 0x4444_0000, 0, 1, 1, 1)
        bad, _ = w.run_reserve(patched, FAM, 0, 0x4444_0000, 0, 1, 1, 1)
        self.assertEqual(good[1], 8)
        self.assertEqual(bad[1], 12)

    def test_patched_image_is_local(self):
        w.PatchedImage(IMAGE, {0x25e9f18 + 4: 0x03}).read(0x25e9f18, 8)
        self.assertEqual(IMAGE.read(0x25e9f18 + 4, 1), b'\x01')

    def test_unmodelled_instruction_rejected(self):
        with self.assertRaises(w.Reject):
            w.decode(IMAGE, 0x241cfa8)


class Packet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = w.build(DATA)
        cls.files = w.render(cls.result)

    def test_all_cases_match_and_all_controls_caught(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertTrue(s['all_negative_controls_caught'])
        self.assertGreaterEqual(s['cases'], 10000)
        self.assertGreaterEqual(s['negative_controls'], 30)
        self.assertEqual(s['instructions_covered'], s['instructions_total'])

    def test_every_negative_control_differs(self):
        for family, kind, name, differing, total in self.result['negatives']:
            self.assertGreater(differing, 0, name)
            self.assertGreater(total, 0, name)

    def test_measure_matches_summary(self):
        measure = json.loads(self.files['measure.json'])
        s = self.result['summary']
        self.assertEqual(measure, dict(cases=s['cases'], negative_controls=s['negative_controls'],
                                       negative_detected=s['negative_detected']))

    def test_render_is_deterministic_and_ascii(self):
        again = w.render(self.result)
        self.assertEqual(again, self.files)
        for name, text in self.files.items():
            text.encode('ascii')

    def test_main_writes_every_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'o'
            self.assertEqual(w.main(['--out', str(out)]), 0)
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, sorted(self.files))
            for name, text in self.files.items():
                self.assertEqual((out / name).read_text(), text)

    def test_committed_packet_matches_if_present(self):
        packet = ROOT / 'research/work-items/action-wire-vote-weight-writer-115'
        if not packet.exists():
            return
        for name, text in self.files.items():
            self.assertEqual((packet / name).read_text(), text, name)
        manifest = (packet / 'MANIFEST.sha256').read_text().splitlines()
        listed = {line.split('  ')[1]: line.split('  ')[0] for line in manifest}
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((packet / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
