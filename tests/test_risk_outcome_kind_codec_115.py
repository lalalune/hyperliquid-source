import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import risk_outcome_kind_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/risk-outcome-kind-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_tagged': codec.unknown_fill_stub}

STR1, BYTES1 = 0x25d3ca0, 0x25d3a80
KEY1, IDENT1, KEY2, IDENT2 = 0x1debf40, 0x1e21040, 0x3f7ea60, 0x3fba720


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class RiskOutcomeKindCodec115(unittest.TestCase):
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
        cls.ends = {int(f['entry'], 16): int(f['fde_end'], 16) for f in cls.result['functions']}
        cls.codes = {int(k, 16): v for k, v in cls.result['summary']['reader_error_codes'].items()}
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

    def read(self, va, text, image=IMAGE):
        rows = codec.linear(image, va, self.ends[va])
        roles = codec.bind_reader_roles(image, rows, va)
        return codec.run_reader(image, va, roles, text)[0]

    def recon(self, va, text):
        fam, kind = [(f, k) for v, f, k in codec.READERS if v == va][0]
        expected = {IDENT1: 0x6423c60, IDENT2: 0x647f038}.get(va)
        return codec.recon_reader(kind, text, codec.VARIANT_POOLS[fam - 1], expected, self.codes[va])

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['reader_matches'], s['reader_cases']), (20920, 20920))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (13998, 13998))
        self.assertEqual(s['reader_inputs'], 5230)
        self.assertEqual(s['visitor_inputs'], 2333)
        self.assertEqual(s['accepted_inputs'], 3)
        self.assertEqual(s['functions'], 10)
        self.assertEqual(s['reader_ok_inputs'], {'0x1debf40': 36, '0x1e21040': 110, '0x3f7ea60': 36, '0x3fba720': 110})
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'unknown_variant_tagged'),
                         ['0x17fbba0', '0x2f7fef0', '0x47d2d80'])
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'reader_parse_str'), ['slot:0x64e08f8'])

    def test_reader_error_codes_read_from_bytes(self):
        for va in (KEY1, KEY2):
            self.assertEqual(self.codes[va], {'eof': 3, 'close': 10, 'other': 17, 'colon': 6})
        for va in (IDENT1, IDENT2):
            self.assertEqual(self.codes[va], {'eof': 5})
        for va, fam, kind, exit_name, at, value in self.result['reader_codes']:
            if exit_name in codec.READER_EXITS[kind]:
                # 48 c7 04 24 imm32 / 48 c7 44 24 disp8 imm32: the immediate is the last four bytes
                raw = codec.decode(IMAGE, int(at, 16)).raw
                self.assertEqual(struct.unpack('<I', raw[-4:])[0], int(value))

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 16)
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
        for va in [v[0] for v in codec.VISITORS]:
            for tag, name in enumerate(codec.NAMES):
                self.assertEqual(self.visit(va, name), ('ok', 9 | tag << 8, None, False))
            for bad in (b'question', b'Questio', b'Questionx', b'StandaloneOutcomE', b'QuestionOutcomes',
                        b'Standalone', b'', b'QuestionOutcom\x00'):
                self.assertEqual(self.visit(va, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'Quest\xffon'
        self.assertEqual(self.visit(BYTES1, bad), ('err', None, b'Quest\xef\xbf\xbdon', True))
        self.assertEqual(self.visit(STR1, bad), ('err', None, bad, False))

    def test_known_reader_outputs(self):
        for va in (KEY1, KEY2):
            self.assertEqual(self.read(va, b' "Question" : 7'), ('ok', 1, 13))
            self.assertEqual(self.read(va, b'"StandaloneOutcome":'), ('ok', 0, 20))
            self.assertEqual(self.read(va, b'"QuestionOutcome"'), ('err', ('peek_error', 3, 17), 17))
            self.assertEqual(self.read(va, b'"QuestionOutcome";'), ('err', ('peek_error', 6, 17), 17))
            self.assertEqual(self.read(va, b'  }'), ('err', ('peek_error', 10, 2), 2))
            self.assertEqual(self.read(va, b'\x0b"Question":'), ('err', ('peek_error', 17, 0), 0))
            self.assertEqual(self.read(va, b''), ('err', ('peek_error', 3, 0), 0))
            self.assertEqual(self.read(va, b'"Quest\\ion":')[1], ('fix_position', ('scan', 6)))
        for va in (IDENT1, IDENT2):
            self.assertEqual(self.read(va, b'\t"QuestionOutcome" x'), ('ok', 2, 18))
            self.assertEqual(self.read(va, b'   '), ('err', ('peek_error', 5, 3), 3))
            self.assertEqual(self.read(va, b'"Quest\\ion"')[1], ('scan', 6))
            self.assertEqual(self.read(va, b' x')[1][0], 'fix_position')
            self.assertEqual(self.read(va, b' x')[1][1][:2], ('invalid_type', 1))
            got = self.read(va, b'"Questions"')
            self.assertEqual(got[1][1][:2], ('unknown_variant', b'Questions'))

    def test_mutated_name_byte_is_detected(self):
        # str visitor 0x25d3ce0: movabs $"Question"; make the 'Q' a 'q'.
        img = self.mutated_image(0x25d3ce2, b'q', expect=b'Q')
        self.assertEqual(self.visit(STR1, b'Question', image=img)[0], 'err')
        self.assertEqual(self.visit(STR1, b'question', image=img), ('ok', 0x109, None, False))

    def test_mutated_reader_rodata_name_is_detected(self):
        # 0x4596a8 holds "Question" for the 8-byte arm of both key readers.
        img = self.mutated_image(0x4596a8, b'K', expect=b'Q')
        got = self.read(KEY1, b'"Question":', image=img)
        self.assertEqual(got[0], 'err')
        self.assertNotEqual(got, self.recon(KEY1, b'"Question":'))

    def test_mutated_reader_code_is_detected(self):
        # 0x1dec10e: movq $0x6, (%rsp) is the ExpectedColon exit; make it 7.
        img = self.mutated_image(0x1dec112, b'\x07', expect=b'\x06')
        got = self.read(KEY1, b'"Question";', image=img)
        self.assertEqual(got, ('err', ('peek_error', 7, 10), 10))
        self.assertNotEqual(got, self.recon(KEY1, b'"Question";'))

    def test_mutated_whitespace_mask_is_detected(self):
        # 0x1debf70: movabs $0x100002600; clear the tab bit (bit 9).
        img = self.mutated_image(0x1debf73, b'\x24', expect=b'\x26')
        got = self.read(KEY1, b'\t"Question":', image=img)
        self.assertNotEqual(got, self.recon(KEY1, b'\t"Question":'))
        rows = codec.linear(img, KEY1, self.ends[KEY1])
        self.assertEqual([r for r in rows if r.op == 'movimm' and r.size == 8 and r.imm == 0x100002600], [])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(STR1, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Question', image=img)
        with self.assertRaises(codec.Reject):
            codec.decode(img, STR1)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Questiox', stubs={})
        with self.assertRaises(codec.Reject):
            codec.run_reader(IMAGE, KEY1, {}, b'"Question":')

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Questiox', pool=0x648b648)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x6432d68, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_bss_is_not_readable(self):
        # .bss by name: .tbss is NOBITS too but shares its VA with file-backed TLS data
        bss = [s for s in codec.elf_index.sections(DATA) if s['type'] == 8 and s['name'] == '.bss']
        self.assertEqual(len(bss), 1)
        with self.assertRaises(codec.Reject):
            IMAGE.read(bss[0]['address'], 1)

    def test_name_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 9)
        self.assertEqual([r[7] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_reader_literals_are_name_pieces(self):
        rows = self.result['reader_literals']
        self.assertEqual(len(rows), 20)
        for va, at, op, addr, hexraw, text in rows:
            self.assertEqual(IMAGE.read(int(addr, 16), len(hexraw) // 2).hex(), hexraw)
            self.assertTrue(any(text.encode() in n for n in codec.NAMES))

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'Questionx', names), 1)
        self.assertIsNone(codec.recon_classify(b'Questionx'))
        self.assertEqual(codec.wrong_casefold(b'QUESTION', names), 1)
        self.assertNotEqual(codec.wrong_swap(b'Question', names), codec.recon_classify(b'Question'))
        self.assertEqual(codec.wrong_length_only(b'xxxxxxxx', names), 1)
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'tagged', b'\xff', names),
                            codec.recon_visitor('bytes', 'tagged', b'\xff'))
        good = self.recon(KEY1, b'\t"Question":')
        info = dict(codes=self.codes[KEY1], pool=codec.VARIANT_POOLS[0], expected=None)
        bad = codec.READER_NEGATIVES['no_tab_whitespace']('key', info)
        self.assertNotEqual(codec.recon_reader('key', b'\t"Question":', codec.VARIANT_POOLS[0], None,
                                               **dict(dict(codes=self.codes[KEY1]), **bad)), good)


if __name__ == '__main__':
    unittest.main()
