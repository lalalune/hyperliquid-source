"""Static controls for the node #94 matching-leg evidence."""
import hashlib
from pathlib import Path
import struct
import unittest

from tools import book_match_leg94 as m


class MatchLegEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.secs = m.sections(cls.data)
        cls.outputs = m.collect(cls.data)

    def test_authenticated_input_and_damaged_hash(self):
        m.verify_identity(self.data)
        off, _ = m.mapping(self.data, self.secs, 0x49e4210, 1, True)
        before = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
                m.verify_identity(self.data)
        finally:
            self.data[off] = before
        m.verify_identity(self.data)

    def test_fdes_and_reference_records(self):
        summary = __import__('json').loads(self.outputs['evidence.json'])
        self.assertEqual([(f['start_va'], f['end_va_exclusive']) for f in summary['functions']],
                         [('0x49e4210', '0x49e4449'), ('0x4a0e490', '0x4a0ea22')])
        self.assertEqual(summary['second_buffer_shift'], 4)
        self.assertEqual(summary['slot_stride'], 248)
        self.assertEqual(summary['vacant_tag'], 2)
        self.assertEqual(summary['slot_pointer_context_offset'], 24)
        self.assertEqual(summary['auxiliary_pointer_context_offset'], 32)
        self.assertEqual(summary['selector_stride'], 20)
        self.assertEqual(summary['slot_side_offset'], 194)
        self.assertEqual(summary['auxiliary_success_u16'], 390)
        self.assertEqual(summary['callback']['addend_va'], '0x372f930')

    def test_all_branch_edges_and_mutated_opcode_and_displacement(self):
        for _, site, target in m.BRANCHES:
            self.assertEqual(m.decode_branch(self.data, self.secs, site, target)[1], target)
        off, _ = m.mapping(self.data, self.secs, 0x49e4305, 2, True)
        before = self.data[off:off + 2]
        try:
            self.data[off] = 0x90
            with self.assertRaises(m.EvidenceError):
                m.decode_branch(self.data, self.secs, 0x49e4305, 0x49e4315)
            self.data[off:off + 2] = before
            self.data[off + 1] ^= 1
            with self.assertRaises(m.EvidenceError):
                m.decode_branch(self.data, self.secs, 0x49e4305, 0x49e4315)
        finally:
            self.data[off:off + 2] = before

    def test_function_byte_corruption_even_without_identity_check(self):
        off, _ = m.mapping(self.data, self.secs, 0x49e42d1, 1, True)
        old = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(m.EvidenceError, 'function bytes'):
                m.collect(self.data, authenticate=False)
        finally:
            self.data[off] = old

    def test_corrupted_fde_extent_is_rejected(self):
        frame = next(f for f in m.eh_frame_records(self.data, self.secs)[1]
                     if f['start'] == 0x49e4210)
        off, _ = m.mapping(self.data, self.secs, frame['fde'] + 12, 4)
        old = self.data[off:off + 4]
        try:
            self.data[off] ^= 1
            with self.assertRaises(m.EvidenceError):
                m.collect(self.data, authenticate=False)
        finally:
            self.data[off:off + 4] = old

    def test_callback_relocation_corruption_is_rejected(self):
        slot = 0x5773d68
        pos = None
        for sec in self.secs:
            if sec['type'] == 4:
                for cursor in range(sec['offset'], sec['offset'] + sec['size'], 24):
                    if struct.unpack_from('<Q', self.data, cursor)[0] == slot:
                        pos = cursor + 16
                        break
                if pos is not None:
                    break
        self.assertIsNotNone(pos)
        old = self.data[pos:pos + 8]
        try:
            self.data[pos] ^= 1
            with self.assertRaisesRegex(m.EvidenceError, 'callback relocation'):
                m.collect(self.data, authenticate=False)
        finally:
            self.data[pos:pos + 8] = old

    def test_caller_vacant_discriminant_corruption_is_rejected(self):
        off, _ = m.mapping(self.data, self.secs, 0x430e356, 1, True)
        old = self.data[off]
        try:
            self.data[off] = 3
            with self.assertRaisesRegex(m.EvidenceError, 'instruction bytes'):
                m.collect(self.data, authenticate=False)
        finally:
            self.data[off] = old

    def test_cleanup_size_shift_corruption_is_rejected(self):
        off, _ = m.mapping(self.data, self.secs, 0x4a0e5cc, 1, True)
        old = self.data[off]
        try:
            self.data[off] = 5
            with self.assertRaisesRegex(m.EvidenceError, 'function bytes'):
                m.collect(self.data, authenticate=False)
        finally:
            self.data[off] = old

    def test_call_target_corruption(self):
        for _, site, target in m.CALLS:
            self.assertEqual(m.decode_call(self.data, self.secs, site, target)[1], target)
        off, _ = m.mapping(self.data, self.secs, 0x49e437d, 5, True)
        before = self.data[off:off + 5]
        try:
            self.data[off + 2] ^= 1
            with self.assertRaises(m.EvidenceError):
                m.decode_call(self.data, self.secs, 0x49e437d, 0x4a0e490)
        finally:
            self.data[off:off + 5] = before

    def test_dispatch_corruption_and_out_of_range_target(self):
        name, va, count, expected = m.TABLES[0]
        bounds = (0x4a0e490, 0x4a0ea22)
        rows = m.decode_table(self.data, self.secs, va, count, expected, bounds)
        self.assertEqual(len(rows), 193)
        self.assertEqual(rows[0][2], 0x4a0e56e)
        off, _ = m.mapping(self.data, self.secs, va, count * 4)
        before = self.data[off:off + 4]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(m.EvidenceError, 'table bytes'):
                m.decode_table(self.data, self.secs, va, count, expected, bounds)
            struct.pack_into('<i', self.data, off, 0)
            altered = hashlib.sha256(self.data[off:off + count * 4]).hexdigest()
            with self.assertRaisesRegex(m.EvidenceError, 'outside drop FDE'):
                m.decode_table(self.data, self.secs, va, count, altered, bounds)
        finally:
            self.data[off:off + 4] = before

    def test_dispatch_boundary_entries_and_return_counts(self):
        decoded = []
        for _, base, count, expected in m.TABLES[:2]:
            decoded.append(m.decode_table(self.data, self.secs, base, count, expected,
                                          (0x4a0e490, 0x4a0ea22)))
        first, second = decoded
        self.assertEqual([first[i][2] for i in (0, 1, 192)],
                         [0x4a0e56e, 0x4a0e4b6, 0x4a0e4b6])
        self.assertEqual([second[i][2] for i in (0, 39)], [0x4a0e4f8, 0x4a0e56e])
        self.assertEqual(sum(row[2] == 0x4a0e6b0 for row in first), 172)
        self.assertEqual(sum(row[2] == 0x4a0e6b0 for row in second), 36)
        self.assertEqual([first[tag - 0x3a][2] for tag in (0x7a, 0x85, 0xbd, 0xd1, 0xd2, 0xf6)],
                         [0x4a0e586, 0x4a0e586, 0x4a0e5d2, 0x4a0e604, 0x4a0e604, 0x4a0e59a])

    def test_unbacked_and_outside_ranges_are_rejected(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(m.EvidenceError):
            m.mapping(self.data, self.secs, bss['address'], 1)
        with self.assertRaises(m.EvidenceError):
            m.mapping(self.data, self.secs, 0xffffffffffffffff, 8)
        with self.assertRaises(m.EvidenceError):
            m.mapping(self.data, self.secs, 0x49e4210, 0)

    def test_slot_or_fallback_and_status_boundaries(self):
        for selector in (0, 1):
            for flag in (0, 1):
                self.assertEqual(m.decision(selector, selector, flag, 0x186, 17),
                                 ('slot', 0, None, False, False))
            side = selector ^ 1
            self.assertEqual(m.decision(selector, side, 0, 0x186, 17),
                             ('fallback', 0, None, False, False))
            self.assertEqual(m.decision(selector, side, 1, 0x186, 17),
                             ('fallback', 1, 17, True, False))
            for status in (0, 0x185, 0x187, 0xffff):
                self.assertEqual(m.decision(selector, side, 1, status, 17),
                                 ('fallback', 1, 0, True, True))
        self.assertEqual(m.decision(0, 255, 2, 0x186, 0xffffffffffffffff),
                         ('fallback', 1, 0xffffffffffffffff, True, False))
        for args in ((2, 0, 0, 0, 0), (0, 256, 0, 0, 0), (0, 0, 0, 65536, 0)):
            with self.assertRaises(ValueError):
                m.decision(*args)

    def test_committed_outputs_match_elf(self):
        folder = m.ROOT / 'research/work-items/RE-006-match-leg-build-94'
        self.assertEqual(set(self.outputs), {'evidence.json', 'branches.tsv', 'calls.tsv',
                                             'dispatch.tsv', 'spans.tsv', 'fields.tsv'})
        for name, value in self.outputs.items():
            self.assertEqual((folder / name).read_bytes(), value.encode('utf-8'), name)


if __name__ == '__main__':
    unittest.main()
