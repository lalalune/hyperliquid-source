"""Static corruption and boundary controls for the selected node-94 evidence."""
import csv
import hashlib
import io
import json
import struct
import unittest

from tools import re21_account_cache94 as m


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        m.check_digest(cls.data)
        cls.sections = m.elf_index.sections(cls.data)
        cls.output = m.collect(cls.data)

    def test_target_digest_and_corruption(self):
        m.check_digest(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.check_digest(b'corrupt target')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.check_digest(self.data, '0' * 64)

    def test_selected_body_byte_corruption_is_rejected(self):
        start = 0x4e8c100
        end, digest, _ = m.FUNCTIONS[start]
        body = m.data_at(self.data, self.sections, start, end - start, True)
        m.require_body(body, digest)
        damaged = bytearray(body)
        damaged[len(damaged) // 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'byte mismatch'):
            m.require_body(damaged, digest)

    def test_section_mapping_excludes_nobits_and_overlaps(self):
        secs = [dict(name='text', type=1, flags=4, address=100, offset=20, size=10),
                dict(name='bss', type=8, flags=4, address=110, offset=30, size=10)]
        self.assertEqual(m.file_offset(secs, 102, 4, True), 22)
        for va, size in ((109, 2), (110, 1), (99, 1), (100, 0), (-1, 1), (m.U64, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                m.file_offset(secs, va, size)
        secs.append(dict(name='duplicate', type=1, flags=4, address=101, offset=50, size=5))
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            m.file_offset(secs, 102, 1)

    def test_relative_transfers_sign_and_truncation(self):
        self.assertEqual(m.decode_rel_branch(0x1000, bytes.fromhex('e8fbffffff')), ('call', 5, 0x1000))
        self.assertEqual(m.decode_rel_branch(0x1000, bytes.fromhex('75fe')), ('jcc_5', 2, 0x1000))
        self.assertEqual(m.decode_rel_branch(0x1000, bytes.fromhex('0f840a000000')), ('jcc_4', 6, 0x1010))
        for raw in (b'', b'\xe8\x00', b'\x0f\x84', b'\x90\x90'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.decode_rel_branch(0x1000, raw)
        with self.assertRaises(ValueError):
            m.decode_rel_branch(0, bytes.fromhex('eb80'))

    def test_rip_displacement_and_bad_shape(self):
        self.assertEqual(m.rip_destination(0x1000, bytes.fromhex('ff15faffffff'), b'\xff\x15'), 0x1000)
        with self.assertRaises(ValueError):
            m.rip_destination(0x1000, bytes.fromhex('ff2500000000'), b'\xff\x15')
        with self.assertRaises(ValueError):
            m.rip_destination(0x1000, bytes.fromhex('ff15'), b'\xff\x15')

    def test_relocation_missing_duplicate_and_corruption(self):
        record = struct.pack('<QQq', 0x1000, 8, 0x2000)
        wanted = {0x1000: (8, 0x2000, 'synthetic')}
        sec = dict(name='r', type=4, size=24, offset=0)
        result = m.read_relocations(record, [sec], wanted)
        self.assertEqual(result[0]['addend'], '0x2000')
        with self.assertRaises(ValueError):
            m.read_relocations(b'\0' * 24, [sec], wanted)
        with self.assertRaises(ValueError):
            m.read_relocations(record * 2, [dict(sec, size=48)], wanted)
        for bad in (struct.pack('<QQq', 0x1000, 7, 0x2000),
                    struct.pack('<QQq', 0x1000, 8, 0x2001)):
            with self.assertRaises(ValueError):
                m.read_relocations(bad, [sec], wanted)
        with self.assertRaises(ValueError):
            m.read_relocations(record, [dict(sec, size=23)], wanted)

    def test_exception_table_controls(self):
        # Header: omitted LP base, indirect type encoding, type offset,
        # ULEB call-site encoding and one four-byte interval.
        blob = bytes.fromhex('ff9b06010400010800')
        header, rows = m.parse_lsda(blob, 0, len(blob), 0x1000, 0x1010)
        self.assertEqual(header.hex(), 'ff9b060104')
        self.assertEqual((rows[0]['start_va'], rows[0]['end_va_exclusive'], rows[0]['landing_va']),
                         ('0x1000', '0x1001', '0x1008'))
        for bad in (bytes.fromhex('fe9b06010400010800'),
                    bytes.fromhex('ff9b06020400010800'),
                    bytes.fromhex('ff9b06010500010800'),
                    bytes.fromhex('ff9b06010400012000')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.parse_lsda(bad, 0, len(bad), 0x1000, 0x1010)

    def test_real_exception_intervals_are_bounded(self):
        rows = list(csv.DictReader(io.StringIO(self.output['exceptions.tsv'].decode()), delimiter='\t'))
        self.assertTrue(rows)
        self.assertTrue(any(row['landing_va'] for row in rows))
        intervals = {(row['start_va'], row['end_va_exclusive'], row['landing_va']) for row in rows}
        self.assertIn(('0x4e77476', '0x4e7747f', '0x4e778f9'), intervals)
        self.assertIn(('0x4e7789c', '0x4e778a1', '0x4e778d7'), intervals)
        self.assertIn(('0x4e7717f', '0x4e7718b', '0x4e7736e'), intervals)
        for row in rows:
            start = int(row['function_va'], 16)
            end = m.FUNCTIONS[start][0]
            self.assertLessEqual(start, int(row['start_va'], 16))
            self.assertLessEqual(int(row['end_va_exclusive'], 16), end)
            if row['landing_va']:
                self.assertLess(int(row['landing_va'], 16), end)

    def test_artifact_records_and_selected_descriptor(self):
        functions = list(csv.DictReader(io.StringIO(self.output['functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(functions), 10)
        self.assertEqual(sum(int(r['size']) for r in functions), 6433)
        bindings = json.loads(self.output['bindings.json'])
        self.assertEqual(bindings['constant_address'], '25a219378dad9b3503c8268c9ca836a52427a4fb')
        self.assertEqual(len({r['masked_sha256'] for r in bindings['methods']}), 1)
        relas = {r['slot']: r for r in csv.DictReader(io.StringIO(self.output['relocations.tsv'].decode()), delimiter='\t')}
        self.assertEqual(relas['0x574bed0']['addend'], '0x4e76b20')
        self.assertEqual(relas['0x5773718']['addend'], '0x4e758a0')
        self.assertEqual(relas['0x576e3e0']['addend'], '0x5788348')
        with self.assertRaises(ValueError):
            m.data_at(self.data, self.sections, 0x5788348, 1)

    def test_retained_files_and_manifest_match(self):
        packet = m.ROOT / 'research/work-items/RE-021-account-cache-preparation-94'
        for name, expected in self.output.items():
            with self.subTest(file=name):
                self.assertEqual((packet / name).read_bytes(), expected)
        retained = {p.name for p in packet.iterdir() if p.is_file() and p.name != 'MANIFEST.sha256'}
        manifest = {}
        for line in (packet / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
            digest, name = line.split('  ', 1)
            self.assertNotIn(name, manifest)
            manifest[name] = digest
        self.assertEqual(set(manifest), retained)
        for name, digest in manifest.items():
            with self.subTest(manifest=name):
                self.assertEqual(hashlib.sha256((packet / name).read_bytes()).hexdigest(), digest)

    def test_layout_independent_known_operands(self):
        layout = json.loads(self.output['layout.json'])
        self.assertEqual(layout['outer_row_stride'], 48)
        self.assertEqual(layout['outer_row_address_offset'], 24)
        self.assertEqual((layout['outer_row_slot_pointer_offset'], layout['outer_row_slot_count_offset']), (8, 16))
        self.assertEqual(layout['address_set_bucket_stride'], 20)
        self.assertEqual((layout['account_bucket_stride'], layout['account_record_copy_bytes']), (208, 172))
        self.assertEqual((layout['account_flag_written'], layout['slot_input_stride']), (8, 32))
        self.assertEqual(layout['slot_zero_payload_bytes'], 64)
        self.assertEqual((layout['account_access_flag_test'], layout['account_access_flag_clear_mask']), (0x10, 0xef))
        self.assertEqual((layout['account_access_return_offset'], layout['journal_entry_stride'],
                          layout['journal_entry_tag']), (24, 88, 0))

    def test_access_hit_miss_and_journal_branches(self):
        rows = list(csv.DictReader(io.StringIO(self.output['branches.tsv'].decode()), delimiter='\t'))
        edges = {row['label']: row for row in rows}
        for label, kind, target in (
                ('access_account_hit', 'jcc_4', '0x4e772b5'),
                ('access_set_membership', 'call', '0x4e8c420'),
                ('access_set_hit_no_journal', 'jcc_5', '0x4e772ca'),
                ('access_hit_flag_set', 'jcc_5', '0x4e772e8'),
                ('access_no_journal_frame', 'jcc_4', '0x4e772fb'),
                ('set_contains_count_zero', 'jcc_4', '0x4e8c52c'),
                ('set_contains_full_key_hit', 'jcc_4', '0x4e8c52e'),
                ('set_contains_empty_control', 'jcc_5', '0x4e8c52c')):
            with self.subTest(edge=label):
                self.assertEqual((edges[label]['kind'], edges[label]['target_va']), (kind, target))
        m.expect_bytes(self.data, self.sections, 0x4e8c4f2, b'\xb0\x01')
        m.expect_bytes(self.data, self.sections, 0x4e8c52c, b'\x31\xc0')

    def test_set_and_account_reserve_have_distinct_ordering(self):
        rows = list(csv.DictReader(io.StringIO(self.output['branches.tsv'].decode()), delimiter='\t'))
        edges = {row['label']: row for row in rows}
        self.assertEqual(edges['set_reserve_first']['kind'], 'jcc_4')
        self.assertLess(int(edges['set_reserve_first']['site_va'], 16),
                        int(edges['set_full_key_hit']['site_va'], 16))
        self.assertLess(int(edges['entry_full_key_hit']['site_va'], 16),
                        int(edges['entry_empty_control']['site_va'], 16))
        self.assertLess(int(edges['entry_empty_control']['site_va'], 16),
                        int(edges['entry_needs_reserve']['site_va'], 16))
        m.expect_bytes(self.data, self.sections, 0x4e8c718, b'\xb0\x01')
        m.expect_bytes(self.data, self.sections, 0x4e8c7d5, b'\x31\xc0')

    def test_instruction_predicate_corruption(self):
        start = 0x4e75993
        valid = m.data_at(self.data, self.sections, start, 5, True)
        self.assertEqual(valid, bytes.fromhex('b9d0000000'))
        fake = bytearray(valid)
        fake[1] ^= 1
        section = [dict(name='tiny', type=1, flags=4, address=start, offset=0, size=len(fake))]
        with self.assertRaisesRegex(ValueError, 'predicate'):
            m.expect_bytes(bytes(fake), section, start, valid)


class ProjectionTests(unittest.TestCase):
    @staticmethod
    def fold_reference(a, b):
        # Independent shift/add multiplication rather than the product operator.
        value = 0
        for bit in range(64):
            if b >> bit & 1:
                value += a << bit
        return (value & m.U64) ^ (value >> 64)

    def test_hash_against_shift_add_reference(self):
        key = bytes.fromhex('0000000000000000000000000000000000000009')
        seed, k0, k1 = 0x123456789abcdef0, 0xfeedface11223344, 0x9876543210000001
        words = [int.from_bytes(key[i:i + 8], 'little') for i in (0, 4, 8, 12)]
        left = self.fold_reference(words[2] ^ k1, words[3] ^ k0)
        right = self.fold_reference(words[0] ^ seed, words[1] ^ k0)
        expected = self.fold_reference(left ^ right ^ 20, k0)
        self.assertEqual(m.hash_address(key, seed, k0, k1), expected)
        self.assertEqual(m.hash_address(key, seed, 0, k1), 0)
        with self.assertRaises(ValueError):
            m.hash_address(key[:-1], seed, k0, k1)
        with self.assertRaises(ValueError):
            m.hash_address(key, -1, k0, k1)

    def test_probe_full_key_all_bit_negative_controls(self):
        key = bytes.fromhex('0000000000000000000000000000000000000009')
        h = (0x37 << 57) | 5
        controls = bytearray([0xff] * 16)
        controls[5] = 0x37
        self.assertEqual(m.probe_key(bytes(controls), {5: key}, h, key), 5)
        for bit in range(160):
            other = bytearray(key)
            other[bit // 8] ^= 1 << (bit % 8)
            with self.subTest(bit=bit):
                self.assertIsNone(m.probe_key(bytes(controls), {5: bytes(other)}, h, key))

    def test_probe_deleted_groups_and_match_before_empty(self):
        key = b'\0' * 19 + b'\x09'
        controls = bytearray([0x80] * 16 + [0xff] * 48)
        controls[31] = 0x12
        self.assertEqual(m.probe_key(bytes(controls), {31: key}, 0x12 << 57, key), 31)
        controls[31] = 0xff
        self.assertIsNone(m.probe_key(bytes(controls), {}, 0x12 << 57, key))

    def test_probe_third_group_uses_triangular_stride(self):
        key = b'\0' * 19 + b'\x09'
        controls = bytearray([0x80] * 48 + [0xff] * 16)
        controls[50] = 0x12
        self.assertEqual(m.probe_key(bytes(controls), {50: key}, 0x12 << 57, key), 50)

    def test_probe_wrap_and_invalid_tables(self):
        key = b'\0' * 19 + b'\x09'
        controls = bytearray([0xff] * 64)
        controls[1] = 7
        self.assertEqual(m.probe_key(bytes(controls), {1: key}, (7 << 57) | 60, key), 1)
        with self.assertRaises(ValueError):
            m.probe_key(b'\x80' * 16, {}, 0, key)
        with self.assertRaises(ValueError):
            m.probe_key(b'\xff' * 15, {}, 0, key)
        with self.assertRaises(ValueError):
            m.probe_key(b'\x81' + b'\xff' * 15, {}, 0, key)
        with self.assertRaises(ValueError):
            m.probe_key(b'\x00' + b'\xff' * 15, {}, 0, key)
        with self.assertRaises(ValueError):
            m.probe_key(b'\xff' * 16, {}, 0, key[:-1])

    def test_reserve_matches_independent_capacity_oracle(self):
        def independent_capacity(n):
            return n - 1 if n < 8 else n - n // 8

        for n in (1, 2, 4, 8, 16, 32, 64, 128, 256):
            cap = independent_capacity(n)
            for count in range(cap + 1):
                for extra in (0, 1, 2, 7, 19):
                    plan = m.reserve_plan(n - 1, count, extra, 208)
                    need = count + extra
                    if need <= cap // 2:
                        self.assertEqual(plan, {'kind': 'rehash', 'buckets': n})
                    else:
                        required = max(cap + 1, need)
                        buckets = 4
                        while independent_capacity(buckets) < required:
                            buckets *= 2
                        self.assertEqual(plan, {'kind': 'allocate', 'buckets': buckets,
                                                'bytes': 209 * buckets + 16})

    def test_reserve_boundaries_and_corrupt_inputs(self):
        self.assertEqual(m.reserve_plan(3, 0, 1, 208), {'kind': 'rehash', 'buckets': 4})
        self.assertEqual(m.reserve_plan(3, 1, 1, 208), {'kind': 'allocate', 'buckets': 8, 'bytes': 1688})
        self.assertEqual(m.reserve_plan((1 << 62) - 1, 1, m.U64, 208), {'kind': 'overflow'})
        self.assertEqual(m.reserve_plan(7, 7, 1 << 60, 208), {'kind': 'overflow'})
        for args in ((5, 0, 1, 208), (3, 4, 1, 208), (3, 0, -1, 208), (3, 0, 1, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.reserve_plan(*args)


if __name__ == '__main__':
    unittest.main()
