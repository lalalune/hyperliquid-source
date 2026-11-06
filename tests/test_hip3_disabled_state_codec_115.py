import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import hip3_disabled_state_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-007-hip3-disabled-state-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)
STUB_FOR_ROLE = {'lossy': codec.lossy_stub, 'free': codec.free_stub,
                 'unknown_variant_tagged': codec.unknown_fill_stub,
                 'unknown_variant_result': codec.unknown_ptr_stub}

STR1, RESULT1, BYTES1 = 0x2b955c0, 0x2b954f0, 0x2b95310
WRITER1, RECORD1 = 0x2bc4310, 0x2bc06a0


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


def visitor(va):
    for row in codec.VISITORS:
        if row[0] == va:
            return row
    raise KeyError(va)


class Hip3DisabledStateCodec115(unittest.TestCase):
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

    def write(self, va, tag, cap, prefix, image=IMAGE):
        rows = codec.linear(image, va, self.ends[va])
        roles = {}
        for k, r in enumerate(rows):
            if r.op == 'call':
                prev = rows[max(0, k - 5):k]
                roles[r.target] = 'reserve' if any(x.op == 'movimm' and x.reg == 8 for x in prev) else 'escape_str'
        return codec.run_writer(image, va, roles, tag, cap, prefix)[0]

    def record(self, va, flag, tag, n, m, fail_at, image=IMAGE):
        rows = codec.linear(image, va, self.ends[va])
        roles = codec.bind_record_roles(image, rows, va)
        return codec.run_record(image, va, roles, flag, tag, n, m, fail_at)[0]

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (15224, 15224))
        self.assertEqual((s['writer_matches'], s['writer_cases']), (3567, 3567))
        self.assertEqual((s['record_matches'], s['record_cases']), (1260, 1260))
        self.assertEqual(s['visitor_inputs'], 1903)
        self.assertEqual(s['accepted_inputs'], 4)
        self.assertEqual(s['functions'], 14)
        self.assertEqual(s['record_error_cases'], 1116)
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'record_str'),
                         ['0x25e8750', '0x41c6110', '0x57cf860'])
        self.assertEqual(sorted(k for k, v in s['callees'].items() if v == 'writer_escape_str'),
                         ['0x25bf330', '0x46708b0', '0x50a3510'])

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 17)
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
        for va, fam, kind, form, _ in codec.VISITORS:
            for tag, name in enumerate(codec.NAMES):
                want = tag if form == 'result' else 9 | tag << 8
                self.assertEqual(self.visit(va, name), ('ok', want, None, False))
            for bad in (b'na', b'NA', b'M', b'mm', b'UserDisable', b'UserDisabledx', b'userDisabled',
                        b'ValidatorDisablet', b'ValidatorDisabled\x00', b'', b'N'):
                self.assertEqual(self.visit(va, bad), ('err', None, bad, False))

    def test_bytes_visitor_reports_lossy_text_and_frees_it(self):
        bad = b'User\xffisabled'
        self.assertEqual(self.visit(BYTES1, bad), ('err', None, b'User\xef\xbf\xbdisabled', True))
        self.assertEqual(self.visit(STR1, bad), ('err', None, bad, False))

    def test_length_jump_tables_cover_lengths_1_to_17(self):
        rows = [r for r in self.result['jump_tables'] if r[1] == 'visitor_length']
        self.assertEqual(len(rows), 17 * len(codec.VISITORS))
        for va, _, _, _, _ in codec.VISITORS:
            mine = [r for r in rows if r[0] == '0x%x' % va]
            self.assertEqual([r[3] for r in mine], list(range(1, 18)))
            # the four name lengths go to four distinct arms; every other
            # length shares one unknown-variant target
            named = {r[3]: r[4] for r in mine if r[5] != '-'}
            other = {r[4] for r in mine if r[5] == '-'}
            self.assertEqual(sorted(named), [1, 2, 12, 17])
            self.assertEqual(len(set(named.values())), 4)
            self.assertEqual(len(other), 1)
            self.assertNotIn(other.pop(), named.values())

    def test_known_writer_outputs(self):
        for va, _ in codec.WRITERS:
            for tag, name in enumerate(codec.NAMES):
                got = self.write(va, tag, 0, b'')
                self.assertEqual(got[0], b'"' + name + b'"')
                self.assertEqual(got[1][0], ('reserve', 0))
                self.assertEqual(got, codec.recon_writer(tag, 0, b''))
                roomy = self.write(va, tag, 64, b'xy')
                self.assertEqual(roomy, (b'xy"' + name + b'"', (('escape', name),), 64))

    def test_known_record_outputs(self):
        for va, _ in codec.RECORDS:
            ok, log = self.record(va, 1, 2, 5, 1, None)
            self.assertEqual(ok, (codec.OK_NICHE,))
            self.assertEqual(log, (('header_flag_nonzero', 5),
                                   ('str', b'last_settlement_time'), ('time', 8),
                                   ('str', b'deploy_time'), ('time', 0x14),
                                   ('str', b'n_reserve_deployments_used'), ('u64', 5),
                                   ('str', b'disabled_state'), ('str', b'ValidatorDisabled'),
                                   ('str', b'm'), ('u8', 1)))
            self.assertEqual(self.record(va, 0, 1, 0, 0, None)[1],
                             (('header_flag_zero', 5), ('time', 8), ('time', 0x14), ('u64', 0),
                              ('str', b'UserDisabled'), ('u8', 0)))
            # flag 2: map-side header, but only the disabled_state key
            self.assertEqual(self.record(va, 2, 3, 0, 0, None)[1],
                             (('header_flag_nonzero', 5), ('time', 8), ('time', 0x14), ('u64', 0),
                              ('str', b'disabled_state'), ('str', b'm'), ('u8', 0)))
            e = codec.record_err(3)
            self.assertEqual(self.record(va, 1, 0, 0, 0, 3)[0], (codec.ERR_NICHE, e[0], e[1]))
            e = codec.record_err(2)
            self.assertEqual(self.record(va, 1, 0, 0, 0, 2)[0], e)

    def test_mutated_name_byte_is_detected(self):
        # str visitor 0x2b955ee: movabs $"UserDisa"; make the 'U' a 'u'.
        img = self.mutated_image(0x2b955f0, b'u', expect=b'U')
        self.assertEqual(self.visit(STR1, b'UserDisabled', image=img)[0], 'err')
        self.assertEqual(self.visit(STR1, b'userDisabled', image=img), ('ok', 0x109, None, False))

    def test_mutated_writer_jump_table_is_detected(self):
        # writer 0x2bc4310 tag table 0x60924c: swap the UserDisabled and
        # ValidatorDisabled entries.
        raw = IMAGE.read(0x60924c, 16)
        swapped = raw[:4] + raw[8:12] + raw[4:8] + raw[12:]
        img = self.mutated_image(0x60924c, swapped, expect=raw)
        got = self.write(WRITER1, 1, 64, b'', image=img)
        self.assertEqual(got[0], b'"ValidatorDisabled"')
        self.assertNotEqual(got, codec.recon_writer(1, 64, b''))

    def test_mutated_record_flag_compare_is_detected(self):
        # 0x2bc07ed: cmpb $0x0, 0xb(%r14) gates the disabled_state key; make it $0x1.
        # With `je` kept, the key is now skipped exactly when the flag is 1.
        img = self.mutated_image(0x2bc07f1, b'\x01', expect=b'\x00')
        got = self.record(RECORD1, 1, 0, 0, 0, None, image=img)
        self.assertNotIn(('str', b'disabled_state'), got[1])
        self.assertNotEqual(got, codec.recon_record(1, 0, 0, 0, None))
        self.assertEqual(self.record(RECORD1, 1, 0, 0, 0, None), codec.recon_record(1, 0, 0, 0, None))

    def test_mutated_record_field_count_is_detected(self):
        # 0x2bc06cd: mov $0x5, %edx before the flag-nonzero header; make it 6.
        img = self.mutated_image(0x2bc06ce, b'\x06', expect=b'\x05')
        rows = codec.linear(img, RECORD1, self.ends[RECORD1])
        with self.assertRaises(codec.Reject):
            codec.bind_record_roles(img, rows, RECORD1)
        roles = codec.bind_record_roles(IMAGE, codec.linear(IMAGE, RECORD1, self.ends[RECORD1]), RECORD1)
        got = codec.run_record(img, RECORD1, roles, 1, 0, 0, 0, None)[0]
        self.assertEqual(got[1][0], ('header_flag_nonzero', 6))
        self.assertNotEqual(got, codec.recon_record(1, 0, 0, 0, None))

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(STR1, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Na', image=img)
        with self.assertRaises(codec.Reject):
            codec.decode(img, STR1)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Nx', stubs={})
        with self.assertRaises(codec.Reject):
            codec.run_record(IMAGE, RECORD1, {}, 1, 0, 0, 0, None)

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            self.visit(STR1, b'Nx', pool=0x648a5b8)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(IMAGE, {})
        with self.assertRaises(codec.Reject):
            m.store(0x644cbe8, 0, 1)

    def test_out_of_range_address_rejected(self):
        with self.assertRaises(codec.Reject):
            IMAGE.read(0xffff_ffff_0000, 1)

    def test_bss_is_not_readable(self):
        bss = [s for s in codec.elf_index.sections(DATA) if s['type'] == 8 and s['name'] == '.bss']
        self.assertEqual(len(bss), 1)
        with self.assertRaises(codec.Reject):
            IMAGE.read(bss[0]['address'], 1)

    def test_name_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 12)
        self.assertEqual([r[7] for r in rows], [n.decode() for n in codec.NAMES] * 3)
        for kind, pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_record_keys_read_from_bytes(self):
        rows = self.result['record_keys']
        for va, _ in codec.RECORDS:
            mine = [r[6] for r in rows if r[0] == '0x%x' % va]
            self.assertEqual([k for k in mine if k.encode() not in codec.NAMES[:3]],
                             [k.decode() for k in codec.REC_KEYS])

    def test_wrong_reconstructions_disagree(self):
        names = codec.NAMES
        self.assertEqual(codec.wrong_prefix(b'Nax', names), 0)
        self.assertIsNone(codec.recon_classify(b'Nax'))
        self.assertEqual(codec.wrong_casefold(b'NA', names), 0)
        self.assertNotEqual(codec.wrong_swap(b'Na', names), codec.recon_classify(b'Na'))
        self.assertEqual(codec.wrong_length_only(b'xx', names), 0)
        good = codec.recon_writer(1, 64, b'')
        for kw in codec.WRITER_NEGATIVES.values():
            if 'grow_when_free' not in kw:
                self.assertNotEqual(codec.recon_writer(1, 64, b'', **kw), good)
        self.assertNotEqual(codec.recon_record(2, 0, 0, 0, None, enum_key_rule='one'),
                            codec.recon_record(2, 0, 0, 0, None))


if __name__ == '__main__':
    unittest.main()
