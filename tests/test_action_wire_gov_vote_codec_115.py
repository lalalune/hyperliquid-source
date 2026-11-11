import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_gov_vote_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/action-wire-gov-vote-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'grow': codec.grow_stub, 'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub, 'unknown_variant_tagged': codec.unknown_fill_stub}

VOTE_SER, VOTE_SER_END = 0x3c32d70, 0x3c32f73
CAT_SER, CAT_SER_END = 0x3c31230, 0x3c31505
VOTE_STR, VOTE_BYTES_RESULT, VOTE_BYTES_TAGGED = 0x23c18b0, 0x23c1690, 0x23c17a0
CAT_STR_TAGGED, CAT_STR_RESULT, CAT_BYTES_TAGGED, CAT_BYTES_RESULT = 0x23c2fb0, 0x23c2ed0, 0x23c2a40, 0x23c2c90


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class GovVoteCodec115(unittest.TestCase):
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
        _, fam, kind, form, which = visitor(va)
        if pool is None:
            pool = codec.CODEC_POOLS[which][fam - 1]
        got, _ = codec.run_visitor(image, va, kind, form, which, self.stubs if stubs is None else stubs,
                                   self.roles, text, pool)
        return got

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (2188, 2188))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (58536, 58536))
        self.assertEqual(s['visitor_inputs'], 3252)
        self.assertEqual(s['accepted_inputs'], 7)
        self.assertEqual(s['functions'], 22)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'grow'), ['0x43bd910', '0x5963a10'])
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v.startswith('unknown_variant')),
                         ['0x17fbba0', '0x2cf1360', '0x2f7fef0', '0x45a8fe0', '0x47d2d80'])
        self.assertEqual(sorted(s['unchecked_dispatch_heads']), ['0x3c31230', '0x4d96fd0'])

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 13)
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

    def test_known_vote_visitor_outputs(self):
        for tag, name in enumerate(codec.NAMES):
            self.assertEqual(self.visit(VOTE_STR, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(VOTE_BYTES_RESULT, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(VOTE_BYTES_TAGGED, name), ('ok', 9 | tag << 8, None, False))
        for bad in (b'Yes', b'NO', b'abstai', b'abstains', b'y', b'', b'electoral'):
            self.assertEqual(self.visit(VOTE_STR, bad), ('err', None, bad, False))

    def test_known_category_visitor_outputs(self):
        for tag, name in enumerate(codec.FIELD_NAMES):
            self.assertEqual(self.visit(CAT_STR_TAGGED, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(CAT_STR_RESULT, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(CAT_BYTES_TAGGED, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(CAT_BYTES_RESULT, name), ('ok', tag, None, False))
        for bad in (b'Accelerated', b'constitution', b'ecosystems', b'electora', b'yes', b''):
            self.assertEqual(self.visit(CAT_STR_TAGGED, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(CAT_STR_RESULT, bad)[0], 'err')

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'ye\xff'
        self.assertEqual(self.visit(VOTE_BYTES_RESULT, bad), ('err', None, b'ye\xef\xbf\xbd', True))
        self.assertEqual(self.visit(VOTE_BYTES_TAGGED, bad), ('err', None, b'ye\xef\xbf\xbd', True))
        self.assertEqual(self.visit(CAT_BYTES_TAGGED, bad), ('err', None, b'ye\xef\xbf\xbd', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(VOTE_STR, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(VOTE_BYTES_RESULT, b'n\xc3\xa9'), ('err', None, b'n\xc3\xa9', False))

    def test_known_serializer_outputs(self):
        for va, which, how in codec.SERIALIZERS:
            names = codec.CODEC_NAMES[which]
            for tag, name in enumerate(names):
                got = codec.run_serializer(IMAGE, va, self.stubs, tag, 64, 0)
                self.assertEqual(got[0], bytes([0xa0 | len(name)]) + name)
                self.assertEqual(got[1], [])
                self.assertEqual(got[3], codec.OK_WORD)
            if which == 'vote':
                # every tag byte above 1 takes the abstain arm
                for tag in (2, 3, 0x80, 0xff):
                    self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, tag, 64, 0)[0], b'\xa7abstain')
                # empty vector: the marker grow leaves capacity 8, so every vote name fits
                self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 2, 0, 0)[1], [(0, 1)])
            else:
                # 11..14-byte category names need a second reserve after the marker grow
                self.assertEqual(codec.run_serializer(IMAGE, va, self.stubs, 1, 0, 0)[1], [(0, 1), (1, 14)])

    def test_dispatch_rows_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 18)
        table = [r for r in rows if r[2].startswith('table_row_')]
        self.assertEqual(len(table), 8)
        for ser, which, step, row_va, op, rel, arm, name in table:
            got = struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0]
            self.assertEqual(got, int(rel))
            self.assertEqual(name, codec.FIELD_NAMES[int(step[10:])].decode())
        chain = [r for r in rows if r[2] == 'chain']
        self.assertEqual(sorted(set(r[0] for r in chain)), ['0x3c32d70', '0x4d98860'])
        for ser, which, step, va, op, imm, target, raw in chain:
            self.assertEqual(IMAGE.read(int(va, 16), len(raw) // 2).hex(), raw)

    def test_mutated_jump_table_is_detected(self):
        rows = [r for r in self.result['jump_tables'] if r[0] == '0x3c31230']
        row0, row2 = int(rows[0][3], 16), int(rows[2][3], 16)
        img = self.mutated_image(row0, IMAGE.read(row2, 4))
        got = codec.run_serializer(img, CAT_SER, self.stubs, 0, 64, 0)
        self.assertNotEqual(got[0], codec.recon_serialize('category', 0, 64, 0)[0])

    def test_mutated_chain_compare_is_detected(self):
        # 0x3c32d7e: cmp $0x1,%ecx; make it 2 so tag 1 falls through to abstain.
        img = self.mutated_image(0x3c32d80, b'\x02', expect=b'\x01')
        got = codec.run_serializer(img, VOTE_SER, self.stubs, 1, 64, 0)
        self.assertEqual(got[0], b'\xa7abstain')
        self.assertNotEqual(got[0], codec.recon_serialize('vote', 1, 64, 0)[0])

    def test_checked_dispatch_head_is_rejected(self):
        rows = codec.linear(IMAGE, CAT_SER, CAT_SER_END)
        self.assertEqual([r.op for r in codec.dispatch_head(rows, CAT_SER)][-4:], ['lea', 'movsxd', 'add', 'jmpind'])
        # Turn the table load into a compare: the unchecked-head rule must refuse it.
        movsxd = [r for r in rows[:8] if r.op == 'movsxd'][0]
        img = self.mutated_image(movsxd.va, bytes.fromhex('483b0c8e'), expect=movsxd.raw)
        with self.assertRaises(codec.Reject):
            codec.dispatch_head(codec.linear(img, CAT_SER, CAT_SER_END), CAT_SER)
        # The vote chain is not a table, and the chain rule refuses a table head.
        with self.assertRaises(codec.Reject):
            codec.dispatch_head(codec.linear(IMAGE, VOTE_SER, VOTE_SER_END), VOTE_SER)
        with self.assertRaises(codec.Reject):
            codec.chain_head(rows, CAT_SER)

    def test_mutated_name_byte_is_detected(self):
        # 0x23c18ef: mov $0x74736261 ('abst'); make the 'a' an 'A'.
        img = self.mutated_image(0x23c18f0, b'A', expect=b'a')
        self.assertEqual(self.visit(VOTE_STR, b'abstain', image=img)[0], 'err')
        self.assertEqual(self.visit(VOTE_STR, b'Abstain', image=img), ('ok', 0x209, None, False))

    def test_mutated_category_name_is_detected(self):
        # 0x23c2fc6: movabs 'accelera'; make the first 'c' a 'C'.
        img = self.mutated_image(0x23c2fc9, b'C', expect=b'c')
        self.assertEqual(self.visit(CAT_STR_TAGGED, b'accelerated', image=img)[0], 'err')
        self.assertEqual(self.visit(CAT_STR_TAGGED, b'accelerated')[0], 'ok')

    def test_mutated_reserve_bound_is_detected(self):
        # 0x3c3126c: cmp $0xa,%rcx / jbe on the accelerated arm; make the bound 9.
        img = self.mutated_image(0x3c3126f, b'\x09', expect=b'\x0a')
        got = codec.run_serializer(img, CAT_SER, self.stubs, 0, 11, 0)
        self.assertNotEqual(got[1], codec.recon_serialize('category', 0, 11, 0)[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(VOTE_STR, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(VOTE_STR, b'yes', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(VOTE_STR, b'yex', stubs={})

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(VOTE_STR, b'yex', pool=0x6475fe0)
        with self.assertRaises(codec.Reject):
            self.visit(CAT_STR_TAGGED, b'ecosystemx', pool=0x642f0c0)

    def test_category_tag_outside_table_is_undefined(self):
        with self.assertRaises(ValueError):
            codec.recon_serialize('category', 4, 64, 0)
        self.assertEqual(codec.arm('vote', 0xff), 2)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x642f0c0, 0, 1)

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
        self.assertEqual(codec.wrong_prefix(b'yesx', names), 0)
        self.assertIsNone(codec.recon_classify(b'yesx'))
        self.assertEqual(codec.wrong_casefold(b'ABSTAIN', names), 2)
        self.assertNotEqual(codec.wrong_swap(b'yes', names), codec.recon_classify(b'yes'))
        self.assertEqual(codec.wrong_first4(b'abstxxx', names), 2)
        self.assertEqual(codec.wrong_length_only(b'xyz', names), 0)
        self.assertEqual(codec.wrong_first_byte(b'nx', names), 1)
        self.assertNotEqual(codec.wrong_serialize_order('vote', 0, 64, 0), codec.recon_serialize('vote', 0, 64, 0))
        self.assertNotEqual(codec.wrong_serialize_mod3('vote', 4, 64, 0), codec.recon_serialize('vote', 4, 64, 0))
        self.assertNotEqual(codec.wrong_serialize_checked_table('vote', 3, 64, 0),
                            codec.recon_serialize('vote', 3, 64, 0))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'result', b'\xff', names),
                            codec.recon_visitor('bytes', 'result', b'\xff'))


if __name__ == '__main__':
    unittest.main()
