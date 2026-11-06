import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re006_tif_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-006-tif-codec-115'
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


class TifCodec115(unittest.TestCase):
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

    def visit(self, va, text, image=IMAGE, stubs=None, pool=0x6432898):
        _, _, kind, form = visitor(va)
        got, _ = codec.run_visitor(image, va, kind, form, self.stubs if stubs is None else stubs, self.roles,
                                   text, pool)
        return got

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (1260, 1260))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (23520, 23520))
        self.assertEqual(s['visitor_inputs'], 2352)
        self.assertEqual(s['accepted_inputs'], 5)
        self.assertEqual(s['invalid_utf8_inputs'], 179)
        self.assertEqual(s['owned_copy_frees'], 895)
        self.assertEqual(s['functions'], 13)
        self.assertEqual(s['decoded_instructions'], 1720)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'grow'),
                         ['0x231e050', '0x43bd910', '0x5963a10'])

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 10)
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
            self.assertEqual(self.visit(0x25ced60, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(0x25cee60, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(0x25ce8d0, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(0x25ceb10, name), ('ok', 9 | tag << 8, None, False))
        for bad in (b'alo', b'ALO', b'Gtcx', b'Liquidation', b'FrontendMarke', b''):
            self.assertEqual(self.visit(0x25ced60, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'Al\xff'
        self.assertEqual(self.visit(0x25ce8d0, bad), ('err', None, b'Al\xef\xbf\xbd', True))
        self.assertEqual(self.visit(0x25ceb10, bad), ('err', None, b'Al\xef\xbf\xbd', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(0x25ced60, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(0x25ce8d0, b'Al\xc3\xa9'), ('err', None, b'Al\xc3\xa9', False))

    def test_known_serializer_outputs(self):
        for va in codec.SERIALIZERS:
            got = codec.run_serializer(IMAGE, va, self.stubs, 4, 64, 0)
            self.assertEqual(got[0], b'\xb1LiquidationMarket')
            self.assertEqual(got[1], [])
            self.assertEqual(got[3], codec.OK_WORD)
            # empty vector: grow for the marker, then again for the 14 name bytes
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 3, 0, 0)[1], [(0, 1), (1, 14)])

    def test_jump_tables_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 15)
        for ser, table, tag, row_va, rel, arm, name in rows:
            got = struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0]
            self.assertEqual(got, rel)
            self.assertEqual(int(table, 16) + rel, int(arm, 16))
            self.assertEqual(name, codec.NAMES[tag].decode())

    def test_mutated_jump_table_is_detected(self):
        rows = [r for r in self.result['jump_tables'] if r[0] == '0x25da5c0']
        row0, row2 = int(rows[0][3], 16), int(rows[2][3], 16)
        img = self.mutated_image(row0, IMAGE.read(row2, 4))
        got = codec.run_serializer(img, 0x25da5c0, self.stubs, 0, 64, 0)
        self.assertEqual(got[0], b'\xa3Gtc')
        self.assertNotEqual(got[0], codec.recon_serialize(0, 64, 0)[0])

    def test_mutated_name_byte_is_detected(self):
        # 0x25ce8ee: cmpb $0x46,(%rsi) ('F' of FrontendMarket); make it 'f'.
        img = self.mutated_image(0x25ce8f0, b'f', expect=b'F')
        self.assertEqual(self.visit(0x25ce8d0, b'FrontendMarket', image=img)[0], 'err')

    def test_mutated_sse_constant_is_detected(self):
        # 0x4566f0: 't' compared against byte 16 of LiquidationMarket by pcmpeqb.
        img = self.mutated_image(0x4566f0, b'u', expect=b't')
        self.assertEqual(self.visit(0x25ced60, b'LiquidationMarket', image=img)[0], 'err')
        self.assertEqual(self.visit(0x25ced60, b'LiquidationMarket')[0], 'ok')

    def test_mutated_reserve_bound_is_detected(self):
        # 0x25da5fc: cmp $0x2,%rcx / jbe on the Alo arm; make the bound 1.
        img = self.mutated_image(0x25da5ff, b'\x01', expect=b'\x02')
        self.assertEqual(DATA[file_offset(0x25da5fc):file_offset(0x25da5fc) + 4], bytes.fromhex('4883f902'))
        got = codec.run_serializer(img, 0x25da5c0, self.stubs, 0, 3, 0)
        self.assertNotEqual(got[1], codec.recon_serialize(0, 3, 0)[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(0x25ced60, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(0x25ced60, b'Alo', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x25ced60, b'Alx', stubs={})

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x25ced60, b'Alx', pool=0x648a608)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x6432898, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_variant_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 15)
        self.assertEqual([r[6] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        self.assertEqual(codec.wrong_prefix(b'Alox'), 0)
        self.assertIsNone(codec.recon_classify(b'Alox'))
        self.assertEqual(codec.wrong_casefold(b'GTC'), 2)
        self.assertNotEqual(codec.wrong_swap(b'Alo'), codec.recon_classify(b'Alo'))
        self.assertEqual(codec.wrong_first16(b'LiquidationMarkex'), 4)
        self.assertEqual(codec.wrong_first_byte(b'Axx'), 0)
        self.assertNotEqual(codec.wrong_serialize_order(1, 64, 0), codec.recon_serialize(1, 64, 0))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'result', b'\xff'),
                            codec.recon_visitor('bytes', 'result', b'\xff'))


if __name__ == '__main__':
    unittest.main()
