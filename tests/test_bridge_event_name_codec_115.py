import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_event_name_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/bridge-event-name-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub, 'unknown_variant_tagged': codec.unknown_fill_stub}

BYTES_TAGGED, BYTES_RESULT, STR_TAGGED, STR_RESULT = 0x28641d0, 0x2864770, 0x2864d00, 0x2864e60
STR_TAGGED_TABLE = 0x5f7f3c


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class BridgeEventNameCodec115(unittest.TestCase):
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
            pool = codec.VARIANT_POOLS[fam - 1]
        got, _ = codec.run_visitor(image, va, kind, form, which, self.stubs if stubs is None else stubs,
                                   self.roles, text, pool)
        return got

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual(s['visitor_matches'], s['visitor_cases'])
        self.assertEqual(s['visitor_cases'], 10 * s['visitor_inputs'])
        self.assertEqual(s['accepted_inputs'], 6)
        self.assertEqual(s['functions'], 10)
        self.assertEqual((s['length_table_compare_rows'], s['length_table_miss_rows']), (50, 210))
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v.startswith('unknown_variant')),
                         ['0x17fbba0', '0x2cf1360', '0x2f7fef0', '0x45a8fe0', '0x47d2d80'])

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
            self.assertEqual(self.visit(STR_TAGGED, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(STR_RESULT, name), ('ok', tag, None, False))
            self.assertEqual(self.visit(BYTES_TAGGED, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(BYTES_RESULT, name), ('ok', tag, None, False))
        for bad in (b'deposit', b'Deposits', b'FinalizedWithdrawaL', b'RequestedValidatorSetUpdate',
                    b'RequestedValidatorSetUpdateEvent!', b'', b'Withdrawal'):
            self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(STR_RESULT, bad)[0], 'err')
            self.assertEqual(self.visit(BYTES_RESULT, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'Depos\xffit'
        self.assertEqual(self.visit(BYTES_RESULT, bad), ('err', None, b'Depos\xef\xbf\xbdit', True))
        self.assertEqual(self.visit(BYTES_TAGGED, bad), ('err', None, b'Depos\xef\xbf\xbdit', True))
        self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
        self.assertEqual(self.visit(BYTES_RESULT, b'D\xc3\xa9posit'), ('err', None, b'D\xc3\xa9posit', False))

    def test_length_tables_read_from_bytes(self):
        rows = self.result['length_tables']
        self.assertEqual(len(rows), 10 * codec.LENGTH_ROWS)
        compare = sorted(set((r[3], r[8]) for r in rows if r[7] == 'compare'))
        self.assertEqual(compare, [(7, 'Deposit'), (19, 'RequestedWithdrawal+FinalizedWithdrawal'),
                                   (21, 'InvalidatedWithdrawal'), (27, 'FinalizedValidatorSetUpdate'),
                                   (32, 'RequestedValidatorSetUpdateEvent')])
        for va, base, row, length, row_va, rel, target, kind, names in rows:
            self.assertEqual(struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0], rel)
            self.assertEqual(int(base, 16) + rel, int(target, 16))

    def test_mutated_length_row_is_detected(self):
        # Row 14 (length 21) of the str tagged visitor's table gets row 1
        # (length 8, a miss); targets are table base + rel32.
        row1 = IMAGE.read(STR_TAGGED_TABLE + 4, 4)
        img = self.mutated_image(STR_TAGGED_TABLE + 4 * 14, row1)
        self.assertEqual(self.visit(STR_TAGGED, b'InvalidatedWithdrawal', image=img)[0], 'err')
        self.assertEqual(self.visit(STR_TAGGED, b'InvalidatedWithdrawal')[0], 'ok')

    def test_mutated_length_bound_is_detected(self):
        # 0x2864d04: cmp $0x19,%rax; make the bound 0x18 so length 32 misses.
        img = self.mutated_image(0x2864d07, b'\x18', expect=b'\x19')
        self.assertEqual(self.visit(STR_TAGGED, b'RequestedValidatorSetUpdateEvent', image=img)[0], 'err')
        self.assertEqual(self.visit(STR_TAGGED, b'FinalizedValidatorSetUpdate', image=img)[0], 'ok')

    def test_mutated_name_dword_is_detected(self):
        # 0x2864d1e: mov $0x6f706544 ('Depo'); make the 'D' a 'd'.
        img = self.mutated_image(0x2864d1f, b'd', expect=b'D')
        self.assertEqual(self.visit(STR_TAGGED, b'Deposit', image=img)[0], 'err')
        self.assertEqual(self.visit(STR_TAGGED, b'deposit', image=img), ('ok', 0x09, None, False))

    def test_mutated_name_byte_is_detected(self):
        # 0x2864201: cmpb $0x65,0x1(%rsi) in the bytes visitor; make it 'E'.
        img = self.mutated_image(0x2864204, b'E', expect=b'e')
        self.assertEqual(self.visit(BYTES_TAGGED, b'Deposit', image=img)[0], 'err')
        self.assertEqual(self.visit(BYTES_TAGGED, b'DEposit', image=img), ('ok', 0x09, None, False))

    def test_mutated_tag_store_is_detected(self):
        # 0x2864d6a: movw $0x409,(%rdi); make the tag 3.
        img = self.mutated_image(0x2864d6e, b'\x03', expect=b'\x04')
        self.assertEqual(self.visit(STR_TAGGED, b'FinalizedValidatorSetUpdate', image=img), ('ok', 0x309, None, False))

    def test_mutated_sse_literal_is_detected(self):
        lits = [r for r in self.result['literals'] if r[0] == '0x2864d00' and r[2].startswith('pcmpeqb_rip_')]
        self.assertEqual(len(lits), 10)
        va = int(lits[0][2][12:], 16)
        img = self.mutated_image(va, b'\x00')
        names = [n for n in codec.NAMES if len(n) > 8]
        self.assertTrue(any(self.visit(STR_TAGGED, n, image=img)[0] == 'err' for n in names))

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(STR_TAGGED, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Deposit', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Depositx', stubs={})

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Depositx', pool=0x648a528)
        with self.assertRaises(codec.Reject):
            self.visit(BYTES_RESULT, b'\xff', pool=0x64bc6c0)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x643e050, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_name_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 18)
        self.assertEqual([r[7] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'Depositx', names), 0)
        self.assertIsNone(codec.recon_classify(b'Depositx'))
        self.assertEqual(codec.wrong_casefold(b'DEPOSIT', names), 0)
        self.assertEqual(codec.wrong_swap(b'RequestedWithdrawal', names), 3)
        self.assertEqual(codec.wrong_alphabetical(b'Deposit', names), 0)
        self.assertEqual(codec.wrong_alphabetical(b'FinalizedWithdrawal', names), 2)
        self.assertEqual(codec.wrong_first4(b'Depoxxx', names), 0)
        self.assertEqual(codec.wrong_last16(b'XXXXXidatedWithdrawal', names), 1)
        self.assertEqual(codec.wrong_length_only(b'x' * 19, names), 2)
        self.assertIsNone(codec.wrong_short_table(b'RequestedValidatorSetUpdateEvent', names))
        self.assertEqual(codec.recon_classify(b'RequestedValidatorSetUpdateEvent'), 5)
        self.assertIsNone(codec.length_row(6))
        self.assertIsNone(codec.length_row(33))
        self.assertEqual(codec.length_row(32), 25)
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'result', b'\xff', names),
                            codec.recon_visitor('bytes', 'result', b'\xff'))


if __name__ == '__main__':
    unittest.main()
