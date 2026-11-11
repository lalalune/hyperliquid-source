import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re007_borrow_lend_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-007-borrow-lend-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'grow': codec.grow_stub, 'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub, 'unknown_variant_tagged': codec.unknown_fill_stub,
                 'unknown_field_result': codec.unknown_ptr_stub, 'unknown_field_tagged': codec.unknown_fill_stub}


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class BorrowLendCodec115(unittest.TestCase):
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

    def visit(self, va, text, image=IMAGE, stubs=None, pool=None):
        _, fam, kind, form, kind_of_codec = visitor(va)
        if pool is None:
            pool = codec.CODEC_POOLS[kind_of_codec][fam - 1]
        got, _ = codec.run_visitor(image, va, kind, form, kind_of_codec, self.stubs if stubs is None else stubs,
                                   self.roles, text, pool)
        return got

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (1008, 1008))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (48276, 48276))
        self.assertEqual(s['visitor_inputs'], 2682)
        self.assertEqual(s['accepted_inputs'], 7)
        self.assertEqual(s['functions'], 21)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'grow'),
                         ['0x231e050', '0x43bd910', '0x5963a10'])
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v.startswith('unknown_field')),
                         ['0x17fbab0', '0x2cf1270', '0x2f7fe00', '0x45a8ef0', '0x47d2c90'])
        self.assertEqual(len(s['unchecked_dispatch_heads']), 3)

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

    def test_known_operation_visitor_outputs(self):
        for tag, name in enumerate(codec.NAMES):
            self.assertEqual(self.visit(0x2691150, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(0x2691210, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(0x2690e20, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(0x2690fb0, name), ('ok', 9 | tag << 8, None, False))
        for bad in (b'Borrow', b'SUPPLY', b'repays', b'withdra', b'operation', b''):
            self.assertEqual(self.visit(0x2691150, bad), ('err', None, bad, False))

    def test_known_field_visitor_outputs(self):
        for tag, name in enumerate(codec.FIELD_NAMES):
            self.assertEqual(self.visit(0x2869450, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(0x28691a0, name), ('ok', tag, None, False))
        # an unknown key is an error (deny_unknown_fields), not an ignored field
        for bad in (b'borrow', b'Token', b'amounts', b'operatio', b'asset', b''):
            self.assertEqual(self.visit(0x2869450, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(0x28691a0, bad)[0], 'err')

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'rep\xff'
        self.assertEqual(self.visit(0x2690e20, bad), ('err', None, b'rep\xef\xbf\xbd', True))
        self.assertEqual(self.visit(0x2690fb0, bad), ('err', None, b'rep\xef\xbf\xbd', True))
        self.assertEqual(self.visit(0x28692f0, bad), ('err', None, b'rep\xef\xbf\xbd', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(0x2691150, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(0x2690e20, b'rep\xc3\xa9'), ('err', None, b'rep\xc3\xa9', False))

    def test_known_serializer_outputs(self):
        for va in codec.SERIALIZERS:
            got = codec.run_serializer(IMAGE, va, self.stubs, 3, 64, 0)
            self.assertEqual(got[0], b'\xa8withdraw')
            self.assertEqual(got[1], [])
            self.assertEqual(got[3], codec.OK_WORD)
            # empty vector: the marker grow leaves capacity 8 (stub doubling, minimum 8), so the
            # 6-byte borrow fits and the 8-byte withdraw needs a second reserve
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 0, 0, 0)[1], [(0, 1)])
            self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 3, 0, 0)[1], [(0, 1), (1, 8)])

    def test_jump_tables_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 12)
        for ser, table, tag, row_va, rel, arm, name in rows:
            got = struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0]
            self.assertEqual(got, rel)
            self.assertEqual(int(table, 16) + rel, int(arm, 16))
            self.assertEqual(name, codec.NAMES[tag].decode())

    def test_mutated_jump_table_is_detected(self):
        rows = [r for r in self.result['jump_tables'] if r[0] == '0x269b7b0']
        row0, row2 = int(rows[0][3], 16), int(rows[2][3], 16)
        img = self.mutated_image(row0, IMAGE.read(row2, 4))
        got = codec.run_serializer(img, 0x269b7b0, self.stubs, 0, 64, 0)
        self.assertEqual(got[0], b'\xa5repay')
        self.assertNotEqual(got[0], codec.recon_serialize(0, 64, 0)[0])

    def test_checked_dispatch_head_is_rejected(self):
        rows = codec.linear(IMAGE, 0x269b7b0, 0x269ba62)
        self.assertEqual([r.op for r in codec.dispatch_head(rows, 0x269b7b0)][-4:], ['lea', 'movsxd', 'add', 'jmpind'])
        # Turn the table load into a compare: the head rule must refuse it.
        movsxd = [r for r in rows[:8] if r.op == 'movsxd'][0]
        img = self.mutated_image(movsxd.va, bytes.fromhex('483b0c8e'), expect=movsxd.raw)
        with self.assertRaises(codec.Reject):
            codec.dispatch_head(codec.linear(img, 0x269b7b0, 0x269ba62), 0x269b7b0)

    def test_mutated_name_byte_is_detected(self):
        # 0x269115f: mov $0x72726f62 ('borr'); make the 'b' a 'B'.
        img = self.mutated_image(0x2691160, b'B', expect=b'b')
        self.assertEqual(self.visit(0x2691150, b'borrow', image=img)[0], 'err')
        self.assertEqual(self.visit(0x2691150, b'Borrow', image=img), ('ok', 0, None, False))

    def test_mutated_field_name_is_detected(self):
        # 0x286945c: movabs 'operatio'; make the 'o' an 'O'.
        img = self.mutated_image(0x286945e, b'O', expect=b'o')
        self.assertEqual(self.visit(0x2869450, b'operation', image=img)[0], 'err')
        self.assertEqual(self.visit(0x2869450, b'operation')[0], 'ok')

    def test_mutated_reserve_bound_is_detected(self):
        # 0x269b7ec: cmp $0x5,%rcx / jbe on the borrow arm; make the bound 4.
        self.assertEqual(DATA[file_offset(0x269b7ec):file_offset(0x269b7ec) + 4], bytes.fromhex('4883f905'))
        img = self.mutated_image(0x269b7ef, b'\x04', expect=b'\x05')
        got = codec.run_serializer(img, 0x269b7b0, self.stubs, 0, 6, 0)
        self.assertNotEqual(got[1], codec.recon_serialize(0, 6, 0)[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(0x2691150, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(0x2691150, b'borrow', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x2691150, b'borrox', stubs={})

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(0x2691150, b'borrox', pool=0x6479b90)
        with self.assertRaises(codec.Reject):
            self.visit(0x2869450, b'tokens', pool=0x6437378)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x6437378, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_name_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 21)
        want = [n.decode() for n in codec.NAMES] * 3 + [n.decode() for n in codec.FIELD_NAMES] * 3
        self.assertEqual([r[7] for r in rows], want)
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'borrowx', names), 0)
        self.assertIsNone(codec.recon_classify(b'borrowx'))
        self.assertEqual(codec.wrong_casefold(b'REPAY', names), 2)
        self.assertNotEqual(codec.wrong_swap(b'borrow', names), codec.recon_classify(b'borrow'))
        self.assertEqual(codec.wrong_first4(b'borrxx', names), 0)
        self.assertEqual(codec.wrong_length_only(b'supply', names), 0)
        self.assertEqual(codec.wrong_first_byte(b'bxxxxx', names), 0)
        self.assertEqual(codec.wrong_field_ignored('str', 'tagged', b'asset', codec.FIELD_NAMES),
                         ('ok', 9 | 3 << 8, None, False))
        self.assertNotEqual(codec.wrong_serialize_order(1, 64, 0), codec.recon_serialize(1, 64, 0))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'result', b'\xff', names),
                            codec.recon_visitor('bytes', 'result', b'\xff'))


if __name__ == '__main__':
    unittest.main()
