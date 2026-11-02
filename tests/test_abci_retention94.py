import csv
import hashlib
import io
import mmap
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_retention94 as m


ITEM = m.ROOT / 'research/work-items/RE-017-quorum-retention-94'


def rows(content):
    return list(csv.DictReader(io.StringIO(content.decode('utf-8')), delimiter='\t'))


class RetentionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = m.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = m.sections(cls.data)
        cls.files = m.analyze(cls.data)
        _, fdes = m.eh_frame_records(cls.data, cls.secs)
        cls.fdes = {x['start']: x for x in fdes}
        cls.cutoff_bytes = m.read_va(cls.data, cls.secs, 0x42e6b58, 44)
        cls.max_bytes = m.read_va(cls.data, cls.secs, 0x42e6b30, 23)
        cls.header_bytes = m.read_va(cls.data, cls.secs, 0x42e6b9a, 16)
        cls.third_bytes = m.read_va(cls.data, cls.secs, 0x42e6ca2, 14)
        cls.third_loop = m.read_va(cls.data, cls.secs, 0x42e6600, 20)
        cls.third_update = m.read_va(cls.data, cls.secs, 0x42e6614, 23)
        cls.checkpoint_bytes = m.read_va(cls.data, cls.secs, 0x42e6d6e, 10)
        cls.search_bytes = m.read_va(cls.data, cls.secs, 0x428818d, 10)
        cls.copy32 = m.read_va(cls.data, cls.secs, 0x42881f5, 20)
        cls.copy56 = m.read_va(cls.data, cls.secs, 0x428b3e0, 20)
        cls.merge_bytes = m.read_va(cls.data, cls.secs, 0x4286a7b, 4)
        cls.repair32 = {
            side: tuple(m.read_va(cls.data, cls.secs, start, end - start)
                        for start, end in ranges)
            for side, ranges in (
                ('right', ((0x42883aa, 0x42883b5), (0x42883f0, 0x42883fb),
                           (0x428840a, 0x428842b))),
                ('left', ((0x4288795, 0x428879e), (0x42887e0, 0x42887ea),
                          (0x42887ea, 0x4288818))),
            )
        }

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutate(self, off):
        old = self.data[off]
        self.data[off] = old ^ 1
        self.addCleanup(self.restore, off, old)

    def restore(self, off, old):
        self.data[off] = old

    def test_authenticated_original(self):
        self.assertEqual(m.checked_digest(self.data), m.DIGEST)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.checked_digest(self.data, '0' * 64)

    def test_corrupt_digest_is_rejected(self):
        self.mutate(0)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.checked_digest(self.data)

    def test_failed_authentication_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / 'bad-node'
            bad.write_bytes(b'not the captured binary')
            out = root / 'evidence'
            with mock.patch.object(m, 'TARGET', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    m.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_emitted_files_equal_retained_evidence(self):
        for name, content in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((ITEM / name).read_bytes(), content)

    def test_independent_raw_offset_and_transfer_audit(self):
        for filename, byte_column in (('functions.tsv', 'body_hex'), ('windows.tsv', 'bytes')):
            for row in rows(self.files[filename]):
                raw = bytes.fromhex(row[byte_column])
                off = int(row['file_offset'], 16)
                self.assertEqual(self.data[off:off + len(raw)], raw)
                self.assertEqual(len(raw), int(row['end_va'], 16) - int(row['start_va'], 16))
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
        for row in rows(self.files['branches.tsv']):
            raw = bytes.fromhex(row['bytes'])
            va, off = int(row['site_va'], 16), int(row['file_offset'], 16)
            self.assertEqual(self.data[off:off + len(raw)], raw)
            if len(raw) == 2:
                displacement = struct.unpack('<b', raw[1:])[0]
            elif len(raw) == 6 and raw[0] == 0x0f:
                displacement = struct.unpack('<i', raw[2:])[0]
            else:
                self.fail('unexpected branch form')
            self.assertEqual(va + len(raw) + displacement, int(row['target_va'], 16))
            self.assertEqual(va + len(raw), int(row['fallthrough_va'], 16))
        for row in rows(self.files['calls.tsv']):
            raw = bytes.fromhex(row['bytes'])
            va, off = int(row['site_va'], 16), int(row['file_offset'], 16)
            self.assertEqual(self.data[off:off + len(raw)], raw)
            pos = 1 if row['form'] == 'rel32' else 2
            self.assertEqual(va + len(raw) + struct.unpack('<i', raw[pos:])[0],
                             int(row['target_or_slot_va'], 16))
        for row in rows(self.files['literal-refs.tsv']):
            raw = bytes.fromhex(row['bytes'])
            va, off = int(row['site_va'], 16), int(row['file_offset'], 16)
            self.assertEqual(self.data[off:off + len(raw)], raw)
            self.assertEqual(va + 7 + struct.unpack_from('<i', raw, 3)[0], int(row['literal_va'], 16))
            self.assertEqual(struct.unpack_from('<I', raw, 15)[0], int(row['length']))

    def test_selected_fdes_and_unmasked_comparisons(self):
        functions = rows(self.files['functions.tsv'])
        self.assertEqual(len(functions), 14)
        by_name = {row['name']: row for row in functions}
        self.assertEqual(by_name['low_count32']['body_hex'], by_name['shared_count32']['body_hex'])
        self.assertEqual(by_name['low_count56']['body_hex'], by_name['shared_count56']['body_hex'])
        self.assertNotEqual(by_name['low_split32']['body_hex'], by_name['shared_split32']['body_hex'])

    def test_count_walk_selection_and_returns(self):
        by_name = {row['name']: row for row in rows(self.files['branches.tsv'])}
        choices = {
            'low_count32_depth_choice': ('ae', '0x1b02ddf'),
            'low_count32_old_leaf': ('e', '0x1b02e6b'),
            'low_count32_new_leaf': ('e', '0x1b02e75'),
            'low_count32_old_no_parent': ('e', '0x1b02e6b'),
            'low_count32_new_no_parent': ('e', '0x1b02e75'),
        }
        for name, (condition, target) in choices.items():
            with self.subTest(name=name):
                self.assertEqual(by_name[name]['condition'], condition)
                self.assertEqual(by_name[name]['target_va'], target)
        self.assertEqual(m.read_va(self.data, self.secs, 0x1b02e6b, 14),
                         bytes.fromhex('4829c84889c24889c8c34829d0c3'))

    def test_all_selected_body_corruptions_are_refused(self):
        for name, start, end, digest in m.FUNCTIONS:
            with self.subTest(name=name):
                off = m.file_offset(self.secs, start + (end - start) // 2, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, start, end, digest)
                finally:
                    self.data[off] = old

    def test_all_selected_window_corruptions_are_refused(self):
        for name, start, end, digest in m.WINDOWS:
            with self.subTest(name=name):
                off = m.file_offset(self.secs, start, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, start, end, digest)
                finally:
                    self.data[off] = old

    def test_branches_have_pinned_owner_and_displacement_controls(self):
        regions = [(start, end, digest) for _, start, end, digest in m.WINDOWS]
        regions += [(start, end, digest) for _, start, end, digest in m.FUNCTIONS]
        for name, site in m.BRANCH_SITES:
            with self.subTest(name=name):
                raw = m.read_va(self.data, self.secs, site, 6)
                n, _, target = m.branch(raw, site)
                containing = next((x for x in regions if x[0] <= site and site + n <= x[1]), None)
                self.assertIsNotNone(containing)
                off = m.file_offset(self.secs, site + n - 1, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    changed = m.read_va(self.data, self.secs, site, 6)
                    self.assertNotEqual(m.branch(changed, site)[2], target)
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, *containing)
                finally:
                    self.data[off] = old

    def test_bad_branch_encodings_fail_closed(self):
        for value in (b'', b'\x90\x00', b'\x0f\x84', b'\xeb\x00', b'\x70\x00'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.branch(value, 0x1000)

    def test_call_targets_and_corrupted_displacements(self):
        regions = [(start, end, digest) for _, start, end, digest in m.WINDOWS]
        regions += [(start, end, digest) for _, start, end, digest in m.FUNCTIONS]
        for name, site, target in m.DIRECT_CALLS:
            with self.subTest(name=name):
                raw = bytearray(m.read_va(self.data, self.secs, site, 5))
                self.assertEqual(m.transfer(raw, site), target)
                region = next((x for x in regions if x[0] <= site and site + 5 <= x[1]), None)
                self.assertIsNotNone(region)
                off = m.file_offset(self.secs, site + 4, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    self.assertNotEqual(m.transfer(m.read_va(self.data, self.secs, site, 5), site), target)
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, *region)
                finally:
                    self.data[off] = old
                raw[0] = 0x90
                with self.assertRaises(ValueError):
                    m.transfer(raw, site)

    def test_indirect_call_encodings_and_slots(self):
        regions = [(start, end, digest) for _, start, end, digest in m.WINDOWS]
        regions += [(start, end, digest) for _, start, end, digest in m.FUNCTIONS]
        for name, site, slot in m.INDIRECT_CALLS:
            with self.subTest(name=name):
                raw = bytearray(m.read_va(self.data, self.secs, site, 6))
                self.assertEqual(m.transfer(raw, site, True), slot)
                region = next((x for x in regions if x[0] <= site and site + 6 <= x[1]), None)
                self.assertIsNotNone(region)
                off = m.file_offset(self.secs, site + 5, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    self.assertNotEqual(m.transfer(m.read_va(self.data, self.secs, site, 6), site, True), slot)
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, *region)
                finally:
                    self.data[off] = old
                raw[1] = 0x25
                with self.assertRaises(ValueError):
                    m.transfer(raw, site, True)

    def test_bad_relative_call_lengths(self):
        for raw, indirect in ((b'\xe8', False), (b'\xff\x15', True), (b'\x90' * 5, False)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.transfer(raw, 0, indirect)

    def test_failure_jumps_and_terminals(self):
        for name, site, target in m.FAILURE_JUMPS:
            with self.subTest(name=name):
                raw = bytearray(m.read_va(self.data, self.secs, site, 5))
                self.assertEqual(m.direct_jump(raw, site), target)
                self.assertEqual(m.read_va(self.data, self.secs, target, 2), b'\x0f\x0b')
                terminal = next((x for x in m.WINDOWS if x[1] == target and x[2] == target + 2), None)
                self.assertIsNotNone(terminal)
                off = m.file_offset(self.secs, target, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.checked_window(self.data, self.secs, *terminal[1:])
                finally:
                    self.data[off] = old
                raw[-1] ^= 1
                self.assertNotEqual(m.direct_jump(raw, site), target)
                raw[0] = 0x90
                with self.assertRaises(ValueError):
                    m.direct_jump(raw, site)

    def test_each_relocation_corruption_is_refused(self):
        slots = {slot for _, _, slot in m.INDIRECT_CALLS}
        selected = m.relocation_rows(self.data, self.secs, slots)
        for slot in sorted(slots):
            with self.subTest(slot=hex(slot)):
                off = selected[slot][3] + 8
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.relocation_rows(self.data, self.secs, slots)
                finally:
                    self.data[off] = old

    def test_missing_relocation_is_refused(self):
        with self.assertRaises(ValueError):
            m.relocation_rows(self.data, self.secs, {0})

    def test_each_lsda_corruption_is_refused(self):
        for name, start, _, _ in m.FUNCTIONS:
            if name not in m.LSDA_PINS:
                continue
            with self.subTest(name=name):
                fde = self.fdes[start]
                off = m.file_offset(self.secs, fde['lsda'] + 7, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.lsda_rows(self.data, self.secs, fde, m.LSDA_PINS[name])
                finally:
                    self.data[off] = old

    def test_actual_lsda_rows(self):
        data = rows(self.files['lsda.tsv'])
        self.assertEqual(len(data), 12)
        self.assertEqual(sum(bool(x['landing_va']) for x in data), 4)

    def test_fde_extent_corruption_is_refused(self):
        fde = self.fdes[0x4288070]
        off = m.file_offset(self.secs, fde['fde'], 16) + 12
        self.mutate(off)
        with self.assertRaises(ValueError):
            m.analyze(self.data, verify_sha=False)

    def test_unwind_index_corruption_is_refused(self):
        _, index = m.unwind_index(self.data)
        row = next(x for x in index if x['start'] == 0x4288070)
        hdr = next(x for x in self.secs if x['name'] == '.eh_frame_hdr')
        off = hdr['offset'] + 12 + row['index'] * 8 + 4
        self.mutate(off)
        with self.assertRaises(ValueError):
            m.analyze(self.data, verify_sha=False)

    def test_each_literal_corruption_is_refused(self):
        for va, expected in m.LITERALS:
            with self.subTest(va=hex(va)):
                off = m.file_offset(self.secs, va, len(expected))
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.checked_literal(self.data, self.secs, va, expected)
                finally:
                    self.data[off] = old

    def test_literal_reference_mutations_are_refused(self):
        sizes = {va: len(value) for va, value in m.LITERALS}
        for site, target in m.LITERAL_REFS:
            with self.subTest(site=hex(site)):
                self.assertEqual(m.literal_ref(self.data, self.secs, site, target, sizes[target])[1], target)
                off = m.file_offset(self.secs, site + 3, 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.literal_ref(self.data, self.secs, site, target, sizes[target])
                finally:
                    self.data[off] = old

    def test_lane_displacement_mutations_are_refused(self):
        for lane, field, site, prefix, expected, suffix in m.LAYOUT:
            with self.subTest(lane=lane, field=field):
                raw, value = m.layout_operand(self.data, self.secs, site, prefix, expected, suffix)
                self.assertEqual(value, expected)
                off = m.file_offset(self.secs, site + len(bytes.fromhex(prefix)), 1)
                old = self.data[off]
                try:
                    self.data[off] ^= 1
                    with self.assertRaises(ValueError):
                        m.layout_operand(self.data, self.secs, site, prefix, expected, suffix)
                finally:
                    self.data[off] = old

    def test_unmapped_and_invalid_intervals_fail(self):
        for va, size in ((0, 1), (-1, 1), (0x1000, 0), ((1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                m.file_offset(self.secs, va, size)

    def test_nobits_does_not_supply_file_bytes(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            m.file_offset([bss], bss['address'], 1)

    def test_ambiguous_section_is_rejected(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            m.file_offset([sec, dict(sec)], sec['address'], 1)

    def test_marker_when_old_value_exceeds_candidate(self):
        self.assertEqual(m.cutoff_model(self.cutoff_bytes, 9, 1, 30), (1, 30, 10))

    def test_selected_key_maximum_model_and_corruption(self):
        self.assertIsNone(m.max_key_model(self.max_bytes, ()))
        self.assertEqual(m.max_key_model(self.max_bytes, (0,)), 0)
        self.assertEqual(m.max_key_model(self.max_bytes, (3, 9, 9, 2, m.MAX_U64, 0)), m.MAX_U64)
        altered = bytearray(self.max_bytes)
        altered[6] ^= 1
        with self.assertRaises(ValueError):
            m.max_key_model(altered, (1, 2))

    def test_header_gate_empty_missing_and_split(self):
        for root, count, expected in ((0, 0, 'empty'), (42, 0, 'empty'),
                                      (0, 1, 'missing-root'), (42, 1, 'split')):
            with self.subTest(root=root, count=count):
                self.assertEqual(m.header_gate_model(self.header_bytes, root, count), expected)
        with self.assertRaises(ValueError):
            m.header_gate_model(bytes(16), 1, 1)

    def test_third_gate_uses_the_low_byte(self):
        self.assertFalse(m.third_gate_model(self.third_bytes, 0))
        self.assertFalse(m.third_gate_model(self.third_bytes, 0x100))
        self.assertTrue(m.third_gate_model(self.third_bytes, 2))
        with self.assertRaises(ValueError):
            m.third_gate_model(bytes(14), 2)

    def test_third_source_marker_and_cutoff_are_separate(self):
        record = lambda key: struct.pack('<Q', key) + bytes(80)
        records = record(2) + record(9) + record(3)
        self.assertEqual(m.third_source_model(self.third_loop, self.third_update, records, 1, 30),
                         (1, 30, True, 31))
        self.assertEqual(m.cutoff_model(self.cutoff_bytes, 9, 1, 30), (1, 30, 10))
        self.assertEqual(m.third_source_model(self.third_loop, self.third_update, records, 0, 30),
                         (1, 9, True, 10))
        self.assertEqual(m.third_source_model(self.third_loop, self.third_update, b'', 0, 30),
                         (0, 30, False, None))
        self.assertEqual(m.third_source_model(self.third_loop, self.third_update, b'', 2, m.MAX_U64),
                         (2, m.MAX_U64, True, m.MAX_U64))
        self.assertEqual(m.third_source_model(self.third_loop, self.third_update,
                                             record(m.MAX_U64), 1, 4),
                         (1, m.MAX_U64, True, m.MAX_U64))

    def test_third_source_rejects_corruption_and_incomplete_records(self):
        with self.assertRaises(ValueError):
            m.third_source_model(b'\x90' + self.third_loop[1:], self.third_update, bytes(88), 0, 0)
        with self.assertRaises(ValueError):
            m.third_source_model(self.third_loop, b'\x90' + self.third_update[1:], bytes(88), 0, 0)
        with self.assertRaises(ValueError):
            m.third_source_model(self.third_loop, self.third_update, bytes(87), 0, 0)

    def test_checkpoint_gate_uses_the_low_dword(self):
        self.assertFalse(m.checkpoint_gate_model(self.checkpoint_bytes, 2))
        self.assertFalse(m.checkpoint_gate_model(self.checkpoint_bytes, (1 << 32) + 2))
        self.assertTrue(m.checkpoint_gate_model(self.checkpoint_bytes, 1))
        with self.assertRaises(ValueError):
            m.checkpoint_gate_model(bytes(10), 1)

    def test_marker_absent_equal_and_raw_odd_tag(self):
        cases = [(0, 0, 7, (1, 0, 1)), (9, 1, 9, (1, 9, 10)),
                 (9, 2, 30, (1, 9, 10)), (9, 3, 30, (3, 30, 10)),
                 (30, 1, 9, (1, 30, 31))]
        for candidate, tag, old, expected in cases:
            with self.subTest(candidate=candidate, tag=tag, old=old):
                self.assertEqual(m.cutoff_model(self.cutoff_bytes, candidate, tag, old), expected)

    def test_maximum_candidate_saturates(self):
        self.assertEqual(m.cutoff_model(self.cutoff_bytes, m.MAX_U64, 1, m.MAX_U64),
                         (1, m.MAX_U64, m.MAX_U64))

    def test_cutoff_model_rejects_corrupted_bytes_and_u64s(self):
        altered = bytearray(self.cutoff_bytes)
        altered[0] ^= 1
        with self.assertRaises(ValueError):
            m.cutoff_model(altered, 1, 0, 0)
        for args in ((-1, 0, 0), (1, 1 << 64, 0), (1, 0, -1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.cutoff_model(self.cutoff_bytes, *args)

    def test_leaf_partition_at_below_equal_and_above(self):
        keys = (0, 5, 11, m.MAX_U64)
        examples = [(0, (), keys), (1, (0,), (5, 11, m.MAX_U64)),
                    (5, (0,), (5, 11, m.MAX_U64)),
                    (6, (0, 5), (11, m.MAX_U64)),
                    (m.MAX_U64, (0, 5, 11), (m.MAX_U64,))]
        for cutoff, left, right in examples:
            with self.subTest(cutoff=cutoff):
                self.assertEqual(m.leaf_model(self.search_bytes, keys, cutoff), (left, right))

    def test_leaf_empty_and_limit(self):
        self.assertEqual(m.leaf_model(self.search_bytes, (), 0), ((), ()))
        self.assertEqual(m.leaf_model(self.search_bytes, tuple(range(11)), 11), (tuple(range(11)), ()))
        for keys in (tuple(range(12)), (1, 1), (2, 1)):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                m.leaf_model(self.search_bytes, keys, 1)

    def test_leaf_search_byte_mutation_is_rejected(self):
        altered = bytearray(self.search_bytes)
        altered[-2] = 0x72
        with self.assertRaises(ValueError):
            m.leaf_model(altered, (1, 2), 2)

    def test_leaf_copy_preserves_opaque_values_for_both_strides(self):
        for width, setup in ((32, self.copy32), (56, self.copy56)):
            values = tuple((key, bytes([key]) * width) for key in (1, 3, 5))
            with self.subTest(width=width):
                self.assertEqual(m.leaf_record_model(self.search_bytes, setup, values, 3),
                                 (values[:1], values[1:]))
                self.assertEqual(m.leaf_record_model(self.search_bytes, setup, values, 6),
                                 (values, ()))

    def test_leaf_copy_rejects_wrong_width_and_changed_opcode(self):
        with self.assertRaises(ValueError):
            m.leaf_record_model(self.search_bytes, self.copy32, ((1, bytes(56)),), 1)
        setup = bytearray(self.copy56)
        setup[3] ^= 1
        with self.assertRaises(ValueError):
            m.leaf_record_model(self.search_bytes, setup, ((1, bytes(56)),), 1)

    def test_merge_capacity_boundary(self):
        for left, right, allowed in ((0, 0, True), (5, 5, True), (5, 6, False), (0, 11, False)):
            with self.subTest(left=left, right=right):
                self.assertEqual(m.merge_gate(self.merge_bytes, left, right), allowed)
        with self.assertRaises(ValueError):
            m.merge_gate(b'\x48\x83\xfa\x0b', 5, 5)

    def test_shared32_repair_thresholds_on_both_sides(self):
        right = self.repair32['right']
        left = self.repair32['left']
        self.assertEqual(m.repair32_model(*right, 'right', 5, 5), ('merge', 5, 5))
        self.assertEqual(m.repair32_model(*right, 'right', 6, 5), ('redistribute', 5, 6))
        self.assertEqual(m.repair32_model(*right, 'right', 5, 6), ('unchanged', 5, 6))
        self.assertEqual(m.repair32_model(*left, 'left', 5, 5), ('merge', 5, 5))
        self.assertEqual(m.repair32_model(*left, 'left', 5, 6), ('redistribute', 6, 5))
        self.assertEqual(m.repair32_model(*left, 'left', 6, 5), ('unchanged', 6, 5))

    def test_shared32_repair_preserves_valid_sibling_count(self):
        for side, instructions in self.repair32.items():
            for left in range(12):
                for right in range(12):
                    action, left_after, right_after = m.repair32_model(
                        *instructions, side, left, right)
                    if action == 'redistribute':
                        with self.subTest(side=side, left=left, right=right):
                            self.assertEqual(left_after + right_after, left + right)
                            self.assertGreaterEqual(min(left_after, right_after), 5)
                            self.assertEqual(right_after if side == 'right' else left_after, 6)

    def test_shared32_repair_refuses_mutations_and_invalid_counts(self):
        for side, instructions in self.repair32.items():
            for index, original in enumerate(instructions):
                broken = list(instructions)
                broken[index] = bytes([original[0] ^ 1]) + original[1:]
                with self.subTest(side=side, window=index), self.assertRaises(ValueError):
                    m.repair32_model(*broken, side, 6, 5)
            for left, right in ((-1, 2), (2, 12), (True, 2)):
                with self.subTest(side=side, counts=(left, right)), self.assertRaises(ValueError):
                    m.repair32_model(*instructions, side, left, right)


if __name__ == '__main__':
    unittest.main()
