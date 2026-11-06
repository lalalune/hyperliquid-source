import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_tx_type_name_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/evm-tx-type-name-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub, 'unknown_variant_tagged': codec.unknown_fill_stub}

STR_TAGGED, STR_RESULT, BYTES_TAGGED = 0x22dc290, 0x22dde20, 0x22dc0f0
ENV1, ENV2 = 0x2336410, 0x44f1bd0


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


def expected_envelope(tag, flag):
    name = codec.NAMES[tag]
    out = bytes([0x82 if flag else 0x92])
    if flag:
        out += b'\xa9signature'
    out += codec.SIG_MARK
    if flag:
        out += b'\xabtransaction'
    return out + b'\x81' + bytes([0xa0 | len(name)]) + name + codec.PAYLOAD_MARK


class EvmTxTypeNameCodec115(unittest.TestCase):
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
        cls.env_roles = {int(k, 16): v for k, v in cls.result['summary']['envelope_callees'].items()}
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

    def envelope(self, va, tag, flag, cap, length, fail=None, image=IMAGE):
        return codec.run_envelope(image, va, self.env_roles, tag, flag, cap, length, fail)[:-1]

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['envelope_matches'], s['envelope_cases']), (1880, 1880))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (16184, 16184))
        self.assertEqual(s['visitor_inputs'], 2023)
        self.assertEqual(s['accepted_inputs'], 5)
        self.assertEqual(s['functions'], 10)
        self.assertEqual(sorted(k for k, v in s['envelope_callees'].items() if v == 'grow'), ['0x231e050', '0x43bd910'])
        self.assertEqual(sorted(k for k, v in s['envelope_callees'].items() if v == 'signature'),
                         ['0x298e9f0', '0x3d42d10'])
        self.assertEqual(sum(1 for v in s['envelope_callees'].values() if v == 'payload'), 10)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v.startswith('unknown_variant')),
                         ['0x17fbba0', '0x2cf1360', '0x2f7fef0', '0x45a8fe0', '0x47d2d80'])
        self.assertEqual(len(s['unchecked_dispatch_heads']), 4)

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 14)
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
        for bad in (b'legacy', b'EIP1559', b'Eip155', b'Eip15599', b'Eip0559', b'Eip8559', b'Eip1', b'', b'Eip2931'):
            self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
            self.assertEqual(self.visit(STR_RESULT, bad)[0], 'err')
            self.assertEqual(self.visit(BYTES_TAGGED, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'Eip\xff559'
        self.assertEqual(self.visit(BYTES_TAGGED, bad), ('err', None, b'Eip\xef\xbf\xbd559', True))
        # the str visitor reports the bytes as given and frees nothing
        self.assertEqual(self.visit(STR_TAGGED, bad), ('err', None, bad, False))
        # valid UTF-8 that is not a name: borrowed text, no free
        self.assertEqual(self.visit(BYTES_TAGGED, b'L\xc3\xa9gacy'), ('err', None, b'L\xc3\xa9gacy', False))

    def test_known_envelope_outputs(self):
        for va in (ENV1, ENV2):
            for tag in range(len(codec.NAMES)):
                for flag in (0, 1):
                    data, grows, end, words, calls = self.envelope(va, tag, flag, 256, 0)
                    self.assertEqual(data, expected_envelope(tag, flag))
                    self.assertEqual(grows, [])
                    self.assertEqual(words, (codec.OK_WORD,))
                    self.assertEqual(calls, [('signature', 0xe0), ('payload', 0x10)])

    def test_envelope_failures_propagate(self):
        for va in (ENV1, ENV2):
            data, grows, end, words, calls = self.envelope(va, 2, 1, 256, 0, 'signature')
            self.assertEqual(words, codec.SIG_ERR)
            self.assertEqual(data, b'\x82\xa9signature')
            self.assertEqual(calls, [('signature', 0xe0)])
            data, grows, end, words, calls = self.envelope(va, 2, 0, 256, 0, 'payload')
            self.assertEqual(words, codec.PAYLOAD_ERR)
            self.assertEqual(data, b'\x92' + codec.SIG_MARK + b'\x81\xa7Eip1559')

    def test_envelope_grows_on_empty_vector(self):
        # empty vector, map form: header grow, then the 9-byte key reserve on capacity 8
        got = self.envelope(ENV1, 0, 1, 0, 0)
        self.assertEqual(got[1][:2], [(0, 1), (2, 9)])
        self.assertEqual(got, codec.recon_envelope(0, 1, 0, 0, None))

    def test_jump_table_rows_read_from_bytes(self):
        rows = self.result['jump_tables']
        self.assertEqual(len(rows), 10)
        for env, fam, tag, row_va, rel, arm, callee, name in rows:
            got = struct.unpack('<i', IMAGE.read(int(row_va, 16), 4))[0]
            self.assertEqual(got, int(rel))
            self.assertEqual(name, codec.NAMES[int(tag)].decode())
        self.assertEqual(len(set(r[6] for r in rows)), 10)

    def test_mutated_envelope_jump_table_is_detected(self):
        rows = [r for r in self.result['jump_tables'] if r[0] == '0x%x' % ENV1]
        row0, row2 = int(rows[0][3], 16), int(rows[2][3], 16)
        img = self.mutated_image(row0, IMAGE.read(row2, 4))
        got = self.envelope(ENV1, 0, 1, 256, 0, image=img)
        self.assertIn(b'Eip1559', got[0])
        self.assertNotEqual(got, codec.recon_envelope(0, 1, 256, 0, None))

    def test_mutated_envelope_reserve_bound_is_detected(self):
        # 0x233657f: cmp $0x5,%rax / jbe on the Legacy arm; make the bound 4.
        img = self.mutated_image(0x2336582, b'\x04', expect=b'\x05')
        diffs = [cap for cap in range(0, 16)
                 if self.envelope(ENV1, 0, 0, cap, 0, image=img) != codec.recon_envelope(0, 0, cap, 0, None)]
        self.assertTrue(diffs)

    def test_checked_dispatch_head_is_rejected(self):
        rows = codec.linear(IMAGE, ENV1, self.ends[ENV1])
        heads = codec.dispatch_heads(rows, ENV1)
        self.assertEqual(len(heads), 2)
        movsxd = heads[0][0][3]
        self.assertEqual(movsxd.op, 'movsxd')
        # Turn the table load into a compare: the unchecked-head rule must refuse it.
        img = self.mutated_image(movsxd.va, b'\x48\x3b' + movsxd.raw[2:], expect=movsxd.raw)
        with self.assertRaises(codec.Reject):
            codec.dispatch_heads(codec.linear(img, ENV1, self.ends[ENV1]), ENV1)
        # A visitor has no envelope dispatch.
        with self.assertRaises(codec.Reject):
            codec.dispatch_heads(codec.linear(IMAGE, STR_TAGGED, self.ends[STR_TAGGED]), STR_TAGGED)

    def test_mutated_name_byte_is_detected(self):
        # 0x22dc29c: mov $0x6167654c ('Lega'); make the 'L' an 'l'.
        img = self.mutated_image(0x22dc29d, b'l', expect=b'L')
        self.assertEqual(self.visit(STR_TAGGED, b'Legacy', image=img)[0], 'err')
        self.assertEqual(self.visit(STR_TAGGED, b'legacy', image=img), ('ok', 0x09, None, False))

    def test_mutated_visitor_digit_table_is_detected(self):
        # bytes visitor: the jump table on the fourth byte ('1'..'7'); copy row '2' over row '1'.
        rows = codec.linear(IMAGE, BYTES_TAGGED, self.ends[BYTES_TAGGED])
        base = [r for r in rows if r.op == 'lea' and r.rm[5] and IMAGE.section_of(r.rm[4])['name'] == '.rodata'][0].rm[4]
        img = self.mutated_image(base, IMAGE.read(base + 4, 4))
        self.assertEqual(self.visit(BYTES_TAGGED, b'Eip1559', image=img)[0], 'err')
        self.assertEqual(self.visit(BYTES_TAGGED, b'Eip1559')[0], 'ok')

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(STR_TAGGED, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Legacy', image=img)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Legacx', stubs={})
        with self.assertRaises(codec.Reject):
            codec.run_envelope(IMAGE, ENV1, {}, 0, 1, 64, 0, None)

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR_TAGGED, b'Legacx', pool=0x648a4c8)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x642d068, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_name_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 15)
        self.assertEqual([r[7] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'Legacyx', names), 0)
        self.assertIsNone(codec.recon_classify(b'Legacyx'))
        self.assertEqual(codec.wrong_casefold(b'EIP4844', names), 3)
        self.assertNotEqual(codec.wrong_swap(b'Legacy', names), codec.recon_classify(b'Legacy'))
        self.assertEqual(codec.wrong_first4(b'Eip7xxx', names), 4)
        self.assertEqual(codec.wrong_length_only(b'xxxxxxx', names), 1)
        self.assertEqual(codec.wrong_first_byte(b'Exxxxxx', names), 1)
        good = codec.recon_envelope(0, 0, 64, 0, None)
        for name, kw in codec.ENVELOPE_NEGATIVES.items():
            if name in ('error_swallowed', 'reserve_on_equal'):
                continue
            self.assertNotEqual(codec.recon_envelope(0, 0, 64, 0, None, **kw), good, name)
        self.assertNotEqual(codec.recon_envelope(0, 1, 64, 0, 'signature', keep_going=True),
                            codec.recon_envelope(0, 1, 64, 0, 'signature'))
        self.assertNotEqual(codec.wrong_raw_error('bytes', 'tagged', b'\xff', names),
                            codec.recon_visitor('bytes', 'tagged', b'\xff'))


if __name__ == '__main__':
    unittest.main()
