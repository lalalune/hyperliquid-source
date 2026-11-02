"""Controls for the node 94 fill-vector byte evidence extractor."""
import hashlib
import struct
import unittest

from tools import book_fill_handoff94 as subject


class FillHandoffEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = subject.sections(cls.data)
        cls.result = subject.evidence(cls.data)

    def test_identity_rejects_a_corrupted_artifact(self):
        subject.authenticate(self.data)
        corrupt = bytearray(self.data)
        corrupt[64] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.authenticate(corrupt)

    def test_fde_and_full_body_digests(self):
        rows = {int(row['start_va'], 16): row for row in self.result['selected_fdes']}
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0x47dcfd0]['end_va_exclusive'], '0x47dd5a2')
        self.assertEqual(rows[0x454d800]['lsda_va'], '0xb4e8b4')
        self.assertEqual(rows[0x454dca0]['lsda_va'], '0xb4e934')
        for start, row in rows.items():
            raw = bytes.fromhex(row['bytes'])
            self.assertEqual(len(raw), row['length'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
            self.assertEqual(raw, subject.read_va(self.data, self.secs, start, len(raw)))

    def test_mutated_body_is_rejected_even_if_identity_check_is_bypassed(self):
        corrupt = bytearray(self.data)
        off = subject.file_offset(corrupt, self.secs, 0x4484518, 1)
        corrupt[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'selected body bytes mismatch'):
            subject.evidence(corrupt, check_identity=False)

    def test_mutated_context_is_rejected(self):
        corrupt = bytearray(self.data)
        off = subject.file_offset(corrupt, self.secs, 0x4d13c1b, 1)
        corrupt[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'context window bytes mismatch'):
            subject.evidence(corrupt, check_identity=False)

    def test_file_mapping_rejects_nobits_ambiguity_and_bounds(self):
        data = bytes(32)
        sec = {'type': 1, 'flags': 4, 'address': 0x1000, 'offset': 4, 'size': 16}
        self.assertEqual(subject.file_offset(data, [sec], 0x1003, 4), 7)
        with self.assertRaises(ValueError):
            subject.file_offset(data, [dict(sec, type=8)], 0x1003, 4)
        with self.assertRaises(ValueError):
            subject.file_offset(data, [sec, sec], 0x1003, 4)
        with self.assertRaises(ValueError):
            subject.file_offset(data, [sec], 0x100f, 2)
        with self.assertRaises(ValueError):
            subject.file_offset(data, [sec], -1, 1)
        with self.assertRaises(ValueError):
            subject.file_offset(data, [sec], 0x1000, 0)

    def test_conditional_branch_destinations_and_invalid_opcodes(self):
        branches = {int(row['va'], 16): row for row in self.result['conditional_branches']}
        self.assertEqual(len(branches), 37)
        for va, cc, target in [(0x4d13b7b, 0, 0x4d13c8f),
                               (0x4484557, 5, 0x4484573),
                               (0x4d1640b, 0, 0x4d1651f),
                               (0x4d164ce, 5, 0x4d16570),
                               (0x4d167a0, 5, 0x4d1681a),
                               (0x47dd02d, 4, 0x47dd0e1),
                               (0x47dd2ce, 5, 0x47dd2d7),
                               (0x4847bc2, 4, 0x4847cfd),
                               (0x4847cc5, 5, 0x4847bf0)]:
            row = branches[va]
            raw = bytes.fromhex(row['bytes'])
            self.assertEqual(subject.decode_branch(raw, va), (len(raw), cc, target))
        for invalid in (b'', b'\x75', b'\x0f\x84\x00', b'\xe9\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):
                subject.decode_branch(invalid, 0x100)
        self.assertNotEqual(subject.decode_branch(b'\x75\x01', 0x100)[2],
                            subject.decode_branch(b'\x75\x02', 0x100)[2])

    def test_calls_and_slots_reject_wrong_encoding(self):
        self.assertEqual(subject.direct_call(bytes.fromhex('e8d13bb3ff'), 0x4d13f9a), 0x4847b70)
        self.assertEqual(subject.indirect_slot(bytes.fromhex('ff151264f200'), 0x4847ba0), 0x576dfb8)
        for function, raw in [(subject.direct_call, b'\xe9\x00\x00\x00\x00'),
                              (subject.direct_call, b'\xe8\x00'),
                              (subject.indirect_slot, b'\xff\x25\x00\x00\x00\x00'),
                              (subject.indirect_slot, b'\xff\x15')]:
            with self.assertRaises(ValueError):
                function(raw, 0x100)

    def test_relative_relocation_controls(self):
        rows = self.result['relative_relocations']
        self.assertEqual([(r['slot_va'], r['addend']) for r in rows],
                         [('0x576dfb8', '0x1346068'), ('0x576dfd8', '0x54c06b0'),
                          ('0x576e010', '0x54c8cb0')])
        fake_section = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24}
        one = struct.pack('<QQq', 0x1234, 8, 0x80)
        self.assertEqual(subject.relative_relocations(one, [fake_section], {0x1234})[0]['addend'], '0x80')
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            subject.relative_relocations(struct.pack('<QQq', 0x1234, 7, 0x80), [fake_section], {0x1234})
        with self.assertRaisesRegex(ValueError, 'missing selected'):
            subject.relative_relocations(one, [fake_section], {0x1235})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            subject.relative_relocations(one * 2, [dict(fake_section, size=48)], {0x1234})
        with self.assertRaisesRegex(ValueError, 'invalid relocation'):
            subject.relative_relocations(one, [dict(fake_section, size=23)], {0x1234})

    def test_arithmetic_boundaries_and_modular_quotient(self):
        const = self.result['constants']
        stride = const['record_stride_bytes']
        limit = const['max_records']
        inverse = int(const['length_inverse_mod_2_64'], 16)
        self.assertEqual(stride, 552)
        self.assertEqual(const['adapter_initial_status_byte'], 39)
        self.assertEqual(const['adapter_error_tag_u64'], '0x8000000000000000')
        self.assertLessEqual(limit * stride, (1 << 63) - 1)
        self.assertGreater((limit + 1) * stride, (1 << 63) - 1)
        for n in (0, 1, 2, 255, limit):
            self.assertEqual(((n * stride >> 3) * inverse) & ((1 << 64) - 1), n)
        # An unaligned span does not have the claimed quotient semantics.
        self.assertNotEqual(((stride + 8 >> 3) * inverse) & ((1 << 64) - 1), 1)

    def test_pair_masks_do_not_hide_other_bytes(self):
        pairs = self.result['masked_pairs']
        self.assertEqual([p['length'] for p in pairs], [154, 169])
        self.assertEqual(pairs[0]['differing_byte_offsets'], ['0x3c', '0x3d', '0x8d', '0x8e'])
        self.assertEqual(pairs[1]['differing_byte_offsets'], ['0x4b', '0x4c', '0x9d', '0x9e', '0xa5', '0xa6'])
        with self.assertRaisesRegex(ValueError, 'outside masks'):
            subject.masked_pair(self.data, self.secs, 0x4484510, 0x44850d0, [(60, 64)])
        with self.assertRaisesRegex(ValueError, 'invalid comparison mask'):
            subject.masked_pair(self.data, self.secs, 0x4484510, 0x44850d0, [(-1, 2)])

    def test_host_window_comparison_and_unmasked_difference(self):
        pairs = self.result['masked_host_windows']
        self.assertEqual([row['length'] for row in pairs], [0x60, 0x95, 0xa2])
        self.assertEqual([row['differing_byte_offsets'] for row in pairs],
                         [['0x22'], ['0x6a', '0x6b', '0x6c'], ['0x9e', '0x9f']])
        with self.assertRaisesRegex(ValueError, 'outside masks'):
            subject.masked_window_pair(self.data, self.secs, 0x4d13bb2, 0x4d16442, 0x95, [])
        with self.assertRaisesRegex(ValueError, 'invalid comparison mask'):
            subject.masked_window_pair(self.data, self.secs, 0x4d13bb2, 0x4d16442, 0x95, [(1, 0x96)])

    def test_adapter_status_edges_and_empty_vector_encoding(self):
        init = subject.read_va(self.data, self.secs, 0x4484518, 5)
        compare = subject.read_va(self.data, self.secs, 0x4484555, 4)
        error = subject.read_va(self.data, self.secs, 0x4484573, 16)
        empty = subject.read_va(self.data, self.secs, 0x4847cd7, 17)
        self.assertEqual(init, bytes.fromhex('c644240727'))
        self.assertEqual(compare, bytes.fromhex('3c27751a'))
        self.assertEqual(subject.decode_branch(compare[2:], 0x4484557), (2, 5, 0x4484573))
        self.assertEqual(error, bytes.fromhex('88430848b80000000000000080488903'))
        self.assertEqual(empty, bytes.fromhex('41bf080000004c892f4c897f084c896f10'))
        status = init[-1]
        self.assertEqual([(value, value != status) for value in (0, 38, 39, 40, 255)],
                         [(0, True), (38, True), (39, False), (40, True), (255, True)])

    def test_tag_comparisons_read_correct_width_and_offsets(self):
        # Check fixed comparison instructions rather than executing the target.
        cases = [(0x47dcfe1, '833e01'), (0x47dcffd, '80bee400000001'),
                 (0x47dd012, '837e2801'), (0x47dd029, '4883f802'),
                 (0x47dd05c, '83be8800000001'), (0x47dd22b, '83bef800000001'),
                 (0x47dd246, '80bedc01000001'), (0x47dd257, '83be2001000001'),
                 (0x47dd2ca, '4883fa02'), (0x47dd2fe, '83be8001000001')]
        for va, encoding in cases:
            expected = bytes.fromhex(encoding)
            self.assertEqual(subject.read_va(self.data, self.secs, va, len(expected)), expected)
        # Equality of the dword tag differs from equality of a whole qword.
        raw = struct.pack('<Q', 0x100000001)
        self.assertEqual(struct.unpack_from('<I', raw)[0], 1)
        self.assertNotEqual(struct.unpack_from('<Q', raw)[0], 1)


if __name__ == '__main__':
    unittest.main()
