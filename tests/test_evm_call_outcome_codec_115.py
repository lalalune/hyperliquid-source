import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_call_outcome_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/evm-call-outcome-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub, 'unknown_variant_tagged': codec.unknown_fill_stub}

STR_TAGGED, BYTES_TAGGED = 0x2692a20, 0x2692850
SER = 0x5af5570
GAS = codec.GAS_MARK + codec.GAS_VALUE.to_bytes(8, 'little')


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


def expected_ok(flag):
    out = b'\x81\xa2Ok' + bytes([0x82 if flag else 0x92])
    if flag:
        out += b'\xa8gas_used'
    out += GAS
    if flag == 1:
        out += b'\xa5bytes'
    return out + codec.BYTES_MARK


class EvmCallOutcomeCodec115(unittest.TestCase):
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
        cls.ser_roles = {int(k, 16): v for k, v in cls.result['summary']['serializer_callees'].items()}
        cls.ends = {int(f['entry'], 16): int(f['fde_end'], 16) for f in cls.result['functions']}
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

    def serialize(self, tag, flag, cap, length, fail=None, image=IMAGE):
        return codec.run_envelope(image, SER, self.ser_roles, tag, flag, cap, length, fail)[:-1]

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (2112, 2112))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (3584, 3584))
        self.assertEqual(s['visitor_inputs'], 1792)
        self.assertEqual(s['accepted_inputs'], 4)
        self.assertEqual(s['functions'], 3)
        self.assertEqual(s['serializer_callees'], {'0x531cd60': 'bytes', '0x57cfd20': 'gas', '0x5963a10': 'grow'})
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v.startswith('unknown_variant')), ['0x17fbba0'])
        self.assertEqual(len(s['unchecked_dispatch_heads']), 1)
        self.assertEqual(s['visitor_length_tables'], 28)

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
        for tag, name in enumerate(codec.NAMES):
            self.assertEqual(self.visit(STR_TAGGED, name), ('ok', 9 | tag << 8, None, False))
            self.assertEqual(self.visit(BYTES_TAGGED, name), ('ok', 9 | tag << 8, None, False))
        for bad in (b'ok', b'OK', b'Okk', b'O', b'', b'OutOfGaz', b'error', b'Errors', b'UnexpectedErro',
                    b'UnexpectedErrorx', b'unexpectedError'):
            self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(BYTES_TAGGED, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'Err\xffr'
        self.assertEqual(self.visit(BYTES_TAGGED, bad), ('err', None, b'Err\xef\xbf\xbdr', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(BYTES_TAGGED, b'\xc3\x89rror'), ('err', None, b'\xc3\x89rror', False))

    def test_known_serializer_outputs(self):
        for tag in (1, 2, 3):
            for flag in (0, 1):
                name = codec.NAMES[tag]
                data, grows, end, words, calls = self.serialize(tag, flag, 256, 0)
                self.assertEqual(data, bytes([0xa0 | len(name)]) + name)
                self.assertEqual((grows, words, calls), ([], (codec.OK_WORD,), []))
        for flag in (0, 1):
            data, grows, end, words, calls = self.serialize(0, flag, 256, 0)
            self.assertEqual(data, expected_ok(flag))
            self.assertEqual(words, (codec.OK_WORD,))
            self.assertEqual(calls, [('gas', codec.GAS_VALUE), ('bytes', codec.BYTES_OFFSET)])

    def test_serializer_failures(self):
        data, grows, end, words, calls = self.serialize(0, 1, 256, 0, 'gas')
        self.assertEqual(words, (codec.GAS_ERR_TAG,) + codec.GAS_ERR)
        self.assertEqual(data, b'\x81\xa2Ok\x82\xa8gas_used')
        self.assertEqual(calls, [('gas', codec.GAS_VALUE)])
        data, grows, end, words, calls = self.serialize(0, 0, 256, 0, 'bytes')
        self.assertEqual(words, codec.BYTES_ERR)
        self.assertEqual(data, b'\x81\xa2Ok\x92' + GAS)

    def test_serializer_grows_on_empty_vector(self):
        got = self.serialize(3, 0, 0, 0)
        self.assertEqual(got[1], [(0, 1), (1, 15)])
        self.assertEqual(got, codec.recon_envelope(3, 0, 0, 0, None))

    def test_jump_table_rows_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 4)
        for ser, fam, tag, row_va, rel, arm, adv_va, adv, name in rows:
            got = struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0]
            self.assertEqual(got, int(rel))
            self.assertEqual(name, codec.NAMES[int(tag)].decode())
            self.assertEqual(int(adv), len(codec.NAMES[int(tag)]))

    def test_visitor_length_tables(self):
        rows = self.result['length_tables']
        self.assertEqual(len(rows), 28)
        for va in (STR_TAGGED, BYTES_TAGGED):
            mine = [r for r in rows if r[0] == '0x%x' % va]
            self.assertEqual([r[4] for r in mine], list(range(2, 16)))
            self.assertEqual({r[4]: r[8] for r in mine if r[8] != 'reject'},
                             {2: 'Ok', 5: 'Error', 8: 'OutOfGas', 15: 'UnexpectedError'})

    def test_mutated_serializer_jump_table_is_detected(self):
        rows = self.result['jump_tables']
        row1, row2 = int(rows[1][3], 16), int(rows[2][3], 16)
        # point row 1 (OutOfGas) at the Error arm: rel32 is relative to the table base
        base = int(rows[0][3], 16)
        rel = struct.unpack('<i', IMAGE.read(row2, 4))[0]
        img = self.mutated_image(row1, struct.pack('<i', rel))
        self.assertEqual(base, row1 - 4)
        got = self.serialize(1, 0, 256, 0, image=img)
        self.assertEqual(got[0], b'\xa5Error')
        self.assertNotEqual(got, codec.recon_envelope(1, 0, 256, 0, None))

    def test_mutated_serializer_reserve_bound_is_detected(self):
        # 0x5af5680: cmp $0x4,%rcx / jbe on the Error arm; make the bound 3.
        img = self.mutated_image(0x5af5683, b'\x03', expect=b'\x04')
        diffs = [cap for cap in range(0, 16)
                 if self.serialize(2, 0, cap, 0, image=img) != codec.recon_envelope(2, 0, cap, 0, None)]
        self.assertTrue(diffs)

    def test_checked_dispatch_head_is_rejected(self):
        rows = codec.linear(IMAGE, SER, self.ends[SER])
        heads = codec.dispatch_heads(rows, SER)
        self.assertEqual(len(heads), 1)
        movsxd = heads[0][0][2]
        self.assertEqual(movsxd.op, 'movsxd')
        # Turn the table load into a compare: the unchecked-head rule must refuse it.
        img = self.mutated_image(movsxd.va, b'\x48\x3b' + movsxd.raw[2:], expect=movsxd.raw)
        with self.assertRaises(codec.Reject):
            codec.dispatch_heads(codec.linear(img, SER, self.ends[SER]), SER)
        # A visitor has no tag dispatch of that shape.
        with self.assertRaises(codec.Reject):
            codec.dispatch_heads(codec.linear(IMAGE, STR_TAGGED, self.ends[STR_TAGGED]), STR_TAGGED)

    def test_mutated_name_byte_is_detected(self):
        # 0x2692a3a: cmpw $0x6b4f,(%rsi) ('Ok'); make the 'O' an 'o'.
        img = self.mutated_image(0x2692a3d, b'o', expect=b'O')
        self.assertEqual(self.visit(STR_TAGGED, b'Ok', image=img)[0], 'err')
        self.assertEqual(self.visit(STR_TAGGED, b'ok', image=img), ('ok', 0x09, None, False))

    def test_mutated_visitor_length_table_is_detected(self):
        # bytes visitor: copy the reject row (length 3) over the Ok row (length 2).
        rows = [r for r in self.result['length_tables'] if r[0] == '0x%x' % BYTES_TAGGED]
        base = int(rows[0][2], 16)
        img = self.mutated_image(base, IMAGE.read(base + 4, 4))
        self.assertEqual(self.visit(BYTES_TAGGED, b'Ok', image=img)[0], 'err')
        self.assertEqual(self.visit(BYTES_TAGGED, b'Ok')[0], 'ok')

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(STR_TAGGED, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Ok', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Ox', stubs={})
        with self.assertRaises(codec.Reject):
            codec.run_envelope(IMAGE, SER, {}, 0, 1, 64, 0, None)

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Ox', pool=0x642d068)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x64373c8, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_enum_name_from_access_call(self):
        self.assertEqual(self.result['summary']['enum_name'], 'ReadPrecompileResult')
        self.assertEqual(self.result['enum_access'][0][7], '0x64373c8')
        by_start = {int(f['entry'], 16): {'end': int(f['fde_end'], 16)} for f in self.result['functions']}
        by_start[0x27b4150] = {'end': 0x27b45c6}
        self.assertEqual(codec.enum_access(IMAGE, by_start)[0], 'ReadPrecompileResult')
        # 0x27b428e: mov $0x4,%r9d (variant count); make it 5.
        img = self.mutated_image(0x27b4290, b'\x05', expect=b'\x04')
        with self.assertRaises(codec.Reject):
            codec.enum_access(img, by_start)
        # a site outside its FDE is refused
        with self.assertRaises(codec.Reject):
            codec.enum_access(IMAGE, {0x27b4150: {'end': 0x27b4200}})

    def test_name_pool_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 4)
        self.assertEqual([r[7] for r in rows], [n.decode() for n in codec.NAMES])
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'Okay', names), 0)
        self.assertIsNone(codec.recon_classify(b'Okay'))
        self.assertEqual(codec.wrong_casefold(b'ERROR', names), 2)
        self.assertNotEqual(codec.wrong_swap(b'Ok', names), codec.recon_classify(b'Ok'))
        self.assertEqual(codec.wrong_first4(b'Errxx', names), None)
        self.assertEqual(codec.wrong_first4(b'Erroz', names), 2)
        self.assertEqual(codec.wrong_length_only(b'xxxxx', names), 2)
        self.assertEqual(codec.wrong_first_byte(b'Exxxx', names), 2)
        good = codec.recon_envelope(0, 0, 64, 0, None)
        for name, kw in codec.ENVELOPE_NEGATIVES.items():
            if name in ('error_swallowed', 'reserve_on_equal', 'units_as_map_with_nil', 'alphabetical_tags',
                        'gas_error_not_retagged'):
                continue
            self.assertNotEqual(codec.recon_envelope(0, 0, 64, 0, None, **kw), good, name)
        self.assertNotEqual(codec.recon_envelope(0, 1, 64, 0, 'gas', keep_going=True),
                            codec.recon_envelope(0, 1, 64, 0, 'gas'))
        self.assertNotEqual(codec.recon_envelope(0, 1, 64, 0, 'gas', raw_gas_error=True),
                            codec.recon_envelope(0, 1, 64, 0, 'gas'))
        self.assertNotEqual(codec.recon_envelope(1, 1, 64, 0, None, wrap_units=True),
                            codec.recon_envelope(1, 1, 64, 0, None))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'tagged', b'\xff', names),
                            codec.recon_visitor('bytes', 'tagged', b'\xff'))


if __name__ == '__main__':
    unittest.main()
