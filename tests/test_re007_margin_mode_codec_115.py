import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re007_margin_mode_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-007-margin-mode-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'grow': codec.grow_stub, 'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_result': codec.unknown_ptr_stub, 'unknown_tagged': codec.unknown_fill_stub}


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class MarginModeCodec115(unittest.TestCase):
    def _setup(cls):
        cls.result = codec.build(DATA)
        cls.files = codec.render(cls.result)
        cls.stubs, cls.roles = {}, {}
        for callee, role in cls.result['callees']:
            if role not in STUB_FOR_ROLE:
                continue
            key = ('slot', int(callee[5:], 16)) if callee.startswith('slot:') else int(callee, 16)
            cls.stubs[key] = STUB_FOR_ROLE[role]
            cls.roles[key] = role
    setUpClass = classmethod(_setup)

    def mutated_image(self, va, data, expect=None):
        off = file_offset(va)
        if expect is not None:
            self.assertEqual(DATA[off:off + len(expect)], expect)
        raw = bytearray(DATA)
        raw[off:off + len(data)] = data
        return codec.Image(bytes(raw))

    def visit(self, va, text, image=IMAGE, stubs=None, pool=0x643e188):
        _, _, kind, form = visitor(va)
        got, _ = codec.run_visitor(image, va, kind, form, self.stubs if stubs is None else stubs, self.roles,
                                   text, pool)
        return got

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (2274, 2274))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (12640, 12640))
        self.assertEqual(s['visitor_inputs'], 1580)
        self.assertEqual(s['accepted_inputs'], 3)
        self.assertEqual(s['invalid_utf8_inputs'], 127)
        self.assertEqual(s['owned_copy_frees'], 635)
        self.assertEqual(s['functions'], 11)
        self.assertEqual(s['decoded_instructions'], 1091)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'grow'),
                         ['0x231e050', '0x43bd910', '0x5963a10'])

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 12)
        for family, name, mismatches, cases in self.result['negatives']:
            self.assertGreater(mismatches, 0, name)
            self.assertLessEqual(mismatches, cases)

    def test_packet_files_are_byte_identical(self):
        on_disk = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
        self.assertEqual(on_disk, sorted(self.files))
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_bytes(), text.encode('ascii'), name)

    def test_manifest(self):
        rows = [line.split('  ', 1) for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines()]
        names = sorted(n for _, n in rows)
        self.assertEqual(names, sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_main_writes_reproducible_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(codec.main(['--out', tmp]), 0)
            for name, text in self.files.items():
                self.assertEqual((Path(tmp) / name).read_text(encoding='ascii'), text)

    def test_wrong_digest_rejected(self):
        raw = bytearray(DATA)
        raw[-1] ^= 1
        with self.assertRaises(codec.Reject):
            codec.build(bytes(raw))

    def test_known_visitor_outputs(self):
        for tag, name in enumerate(codec.NAMES):
            for va in (0x2868990, 0x28687f0, 0x3bcf9e0, 0x59fdd20):
                pool = {1: 0x643e188, 2: 0x6475de0, 3: 0x64b7d28}[visitor(va)[1]]
                self.assertEqual(self.visit(va, name, pool=pool), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(0x2868660, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(0x3bcf850, name, pool=0x6475de0), ('ok', tag, None, False))
        for bad in (b'Normal', b'nocross', b'strictIsolate', b'normal ', b'noCrosS', b''):
            self.assertEqual(self.visit(0x2868990, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(0x2868660, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'no\xff'
        self.assertEqual(self.visit(0x2868660, bad), ('err', None, b'no\xef\xbf\xbd', True))
        self.assertEqual(self.visit(0x28687f0, bad), ('err', None, b'no\xef\xbf\xbd', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(0x2868990, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(0x2868660, b'no\xc3\xa9'), ('err', None, b'no\xc3\xa9', False))

    def test_known_serializer_outputs(self):
        for va in codec.SERIALIZERS:
            for tag in (2, 3, 0x80, 0xff):
                got = codec.run_serializer(IMAGE, va, self.stubs, tag, 64, 0)
                self.assertEqual(got[0], b'\xaestrictIsolated')
                self.assertEqual(got[1], [])
                self.assertEqual(got[3], codec.OK_WORD)
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 0, 64, 0)[0], b'\xa6normal')
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 1, 64, 0)[0], b'\xa7noCross')
            # empty vector: grow for the marker, then again for the 14 name bytes
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 2, 0, 0)[1], [(0, 1), (1, 14)])

    def test_dispatch_rows_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 15)
        for ser, va, op, imm, target, raw in rows:
            self.assertEqual(IMAGE.read(int(va, 16), len(raw) // 2).hex(), raw)
        self.assertEqual([r[2] for r in rows[:5]], ['movzx8', 'test', 'je', 'cmp', 'jne'])

    def test_mutated_dispatch_compare_is_detected(self):
        # 0x2924dce: cmp $0x1,%ecx; make it cmp $0x2 so tag 1 falls to strictIsolated.
        img = self.mutated_image(0x2924dd0, b'\x02', expect=b'\x01')
        got = codec.run_serializer(img, 0x2924dc0, self.stubs, 1, 64, 0)
        self.assertEqual(got[0], b'\xaestrictIsolated')
        self.assertNotEqual(got[0], codec.recon_serialize(1, 64, 0)[0])

    def test_mutated_name_byte_is_detected(self):
        # 0x286868d: cmpb $0x43,0x2(%rsi) ('C' of noCross); make it 'c'.
        img = self.mutated_image(0x2868690, b'c', expect=b'C')
        self.assertEqual(self.visit(0x2868660, b'noCross', image=img)[0], 'err')
        self.assertEqual(self.visit(0x2868660, b'noCross')[0], 'ok')

    def test_mutated_xor_constant_is_detected(self):
        # 0x286899c: mov $0x72436f6e,%eax ("noCr" for the xor compare); make 'C' 'c'.
        img = self.mutated_image(0x286899f, b'c', expect=b'C')
        self.assertEqual(self.visit(0x2868990, b'noCross', image=img)[0], 'err')
        self.assertEqual(self.visit(0x2868990, b'noCross')[0], 'ok')

    def test_mutated_reserve_bound_is_detected(self):
        # 0x2924df9: cmp $0x6,%rcx / jbe on the noCross arm; make the bound 5.
        self.assertEqual(DATA[file_offset(0x2924df9):file_offset(0x2924df9) + 4], bytes.fromhex('4883f906'))
        img = self.mutated_image(0x2924dfc, b'\x05', expect=b'\x06')
        got = codec.run_serializer(img, 0x2924dc0, self.stubs, 1, 7, 0)
        self.assertNotEqual(got[1], codec.recon_serialize(1, 7, 0)[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(0x2868990, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(0x2868990, b'normal', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x2868990, b'normax', stubs={})

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x2868990, b'normax', pool=0x6475de0)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x643e188, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_variant_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 9)
        self.assertEqual([r[6] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        self.assertEqual(codec.wrong_prefix(b'normalx'), 0)
        self.assertIsNone(codec.recon_classify(b'normalx'))
        self.assertEqual(codec.wrong_casefold(b'NOCROSS'), 1)
        self.assertNotEqual(codec.wrong_swap(b'normal'), codec.recon_classify(b'normal'))
        self.assertEqual(codec.wrong_first8(b'strictIsXXXXXX'), 2)
        self.assertEqual(codec.wrong_first4(b'normXX'), 0)
        self.assertEqual(codec.wrong_length_only(b'abcdef'), 0)
        self.assertNotEqual(codec.wrong_serialize_mod3(3, 64, 0), codec.recon_serialize(3, 64, 0))
        self.assertNotEqual(codec.wrong_serialize_order(1, 64, 0), codec.recon_serialize(1, 64, 0))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'result', b'\xff'),
                            codec.recon_visitor('bytes', 'result', b'\xff'))


if __name__ == '__main__':
    unittest.main()
