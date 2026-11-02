"""Negative controls for the node 94 per-DEX book input extractor."""
import hashlib
import itertools
import mmap
from pathlib import Path
import struct
import tempfile
import unittest

from tools import abci_perp_book_root94 as m


class PerpBookRoot94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = m.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        m.verify_digest(cls.data)
        cls.sections = m.sections(cls.data)
        cls.frames = m.selected_frames(cls.data, cls.sections)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def flip_and_check(self, pos, callback):
        original = self.data[pos]
        try:
            self.data[pos] ^= 1
            with self.assertRaises((ValueError, struct.error)):
                callback()
        finally:
            self.data[pos] = original

    def offset(self, address, size=1, executable=False):
        return m.location(self.sections, len(self.data), address, size, executable)[1]

    def test_artifact_digest_and_changed_byte(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.SHA256)
        self.flip_and_check(0x40, lambda: m.verify_digest(self.data))

    def test_no_output_on_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            self.flip_and_check(0x40, lambda: m.generate(self.data, output))
            self.assertFalse(output.exists())

    def test_section_mapping_excludes_nobits_and_rejects_ambiguous_ranges(self):
        valid = {'name': '.data', 'type': 1, 'flags': 0, 'address': 16, 'size': 8, 'offset': 4}
        bss = {'name': '.bss', 'type': 8, 'flags': 0, 'address': 16, 'size': 8, 'offset': 1000}
        self.assertEqual(m.location([valid, bss], 12, 17, 2)[1], 5)
        for values in [([bss], 100, 16, 1), ([valid, dict(valid)], 12, 16, 1),
                       ([valid], 12, 15, 2), ([valid], 12, 16, 0),
                       ([valid], 12, (1 << 64) - 1, 2), ([valid], 5, 17, 2)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                m.location(*values)
        with self.assertRaises(ValueError):
            m.location([valid], 12, 16, 1, executable=True)

    def test_all_selected_fde_bodies_reject_mutated_bytes(self):
        self.assertEqual(len(self.frames), len(m.FDE_PINS))
        for start, frame in self.frames.items():
            with self.subTest(start=hex(start)):
                offset = self.offset(start, executable=True)
                self.flip_and_check(offset, lambda: m.check_body(self.data, self.sections, frame, start))

    def test_changed_unwind_range_rejected(self):
        frame = self.frames[0x1e5ce30]
        offset = self.offset(frame['fde'] + 12, 4)
        self.flip_and_check(offset, lambda: m.selected_frames(self.data, self.sections))

    def test_all_selected_windows_reject_changed_bytes(self):
        for name, address, expected in m.WINDOW_PINS:
            with self.subTest(name=name):
                offset = self.offset(address, executable=True)
                self.flip_and_check(offset, lambda: m.check_bytes(self.data, self.sections, address, expected))

    def test_all_selected_conditional_branches_reject_changed_opcodes_and_offsets(self):
        for group, address, expected in m.BRANCH_PINS:
            if group == 'single':
                entries = [(address, m.owner_of(address))]
            else:
                entries = [(owner + address, owner) for owner in m.PAIRS[group]]
            for site, owner in entries:
                offset = self.offset(site, len(bytes.fromhex(expected)), True)
                callback = lambda: m.branch_at(self.data, self.sections, site, expected, owner)
                with self.subTest(site=hex(site)):
                    self.flip_and_check(offset, callback)
                    self.flip_and_check(offset + len(bytes.fromhex(expected)) - 1, callback)

    def test_all_relative_transfers_reject_changed_opcode_and_displacement(self):
        for group, address, low_target, shared_target in m.TRANSFER_PINS:
            entries = [(address, low_target)] if group == 'single' else [
                (m.PAIRS[group][0] + address, low_target),
                (m.PAIRS[group][1] + address, shared_target)]
            for site, target in entries:
                offset = self.offset(site, 5, True)
                callback = lambda: m.transfer_at(self.data, self.sections, site, target)
                with self.subTest(site=hex(site)):
                    original = self.data[offset]
                    try:
                        self.data[offset] = 0
                        with self.assertRaises(ValueError):
                            callback()
                    finally:
                        self.data[offset] = original
                    self.flip_and_check(offset + 1, callback)

    def test_selected_branch_must_stay_in_owner(self):
        group, delta, expected = next(x for x in m.BRANCH_PINS if x[0] == 'outer')
        site = m.PAIRS[group][0] + delta
        with self.assertRaises(ValueError):
            m.branch_at(self.data, self.sections, site, expected, m.PAIRS[group][1])

    def test_descriptor_relocations_and_duplicate_slot_rejected(self):
        rows = m.table_rows(self.data, self.sections)
        self.assertEqual(len(rows), 2)
        slots = [table + 24 for _, table, _, _ in m.TABLES]
        found = m.relocation_index(self.data, self.sections, slots)
        offset = found[slots[0]][3]
        self.flip_and_check(offset + 8, lambda: m.table_rows(self.data, self.sections))
        section = next(s for s in self.sections if s['name'] == '.rela.dyn')
        other = section['offset']
        if other == offset or other == found[slots[1]][3]:
            other += 24
        old = bytes(self.data[other:other + 8])
        try:
            struct.pack_into('<Q', self.data, other, slots[0])
            with self.assertRaises(ValueError):
                m.relocation_index(self.data, self.sections, slots)
        finally:
            self.data[other:other + 8] = old

    def test_exception_table_hash_and_row_bounds(self):
        frame = self.frames[0x1ddb120]
        header, rows = m.parse_lsda(self.data, self.sections, frame)
        self.assertEqual(len(rows), header[4])
        raw = bytes.fromhex(header[-1])
        offset = self.offset(frame['lsda'], len(raw))
        self.flip_and_check(offset + len(raw) - 1, lambda: m.parse_lsda(self.data, self.sections, frame))
        bad = dict(frame, end=frame['start'] + 1)
        with self.assertRaises(ValueError):
            m.parse_lsda(self.data, self.sections, bad)

    def test_call_site_exception_links_and_overlaps(self):
        rows = []
        for frame in self.frames.values():
            _header, selected = m.parse_lsda(self.data, self.sections, frame)
            rows.extend(selected)
        transfers = m.selected_transfers(self.data, self.sections)
        links = m.lsda_call_links(transfers, rows)
        link = next(row for row in links if row[1] == '0x26b37d0')
        self.assertEqual((link[3], link[4], link[7]), ('0x26b37d4', 'covered', '0x26b3866'))
        relevant = next(row for row in rows if row[0] == '0x26b35b0' and
                        int(row[4], 16) <= 0x26b37d4 < int(row[5], 16))
        with self.assertRaises(ValueError):
            m.lsda_call_links(transfers, rows + [relevant])

    def test_layout_operand_mutation_rejected(self):
        rows = m.layout_rows(self.data, self.sections)
        self.assertEqual(len(rows), 19)
        self.assertEqual({r[0]: r[6] for r in rows}['slot_stride'], '0xf8')
        offset = self.offset(0x487acc5, 7, True)
        self.flip_and_check(offset + 3, lambda: m.layout_rows(self.data, self.sections))

    def test_order_fields_and_literal_corruption(self):
        fields, literals = m.field_rows(self.data, self.sections)
        self.assertEqual([(r[0], r[2]) for r in fields], [
            ('is_position_tpsl', '0x35'), ('resting_sz', '0x0'), ('orig_sz', '0x8'),
            ('user', '0x20'), ('tif', '0x34'), ('core', '0x18'), ('oid', '0x10')])
        self.assertEqual([r[-1] for r in literals], [r[0] for r in fields])
        offset = self.offset(0x49e7c3c, executable=True)
        self.flip_and_check(offset, lambda: m.field_rows(self.data, self.sections))

    def test_nonmasked_twin_differences(self):
        pairs, differences = m.twin_comparison(self.data, self.sections)
        self.assertEqual(len(pairs), 6)
        self.assertTrue(all(row[4] > 0 for row in pairs))
        self.assertEqual(sum(row[5] for row in pairs), len(differences))

    def test_synthetic_core_count_canonical_flags(self):
        for flags in itertools.product((0, 1), repeat=7):
            t, s, r, gate, d, c, b = flags
            count, present = m.core_count(t, s, r, gate, 0, 0, d, c, b)
            self.assertEqual(count, 2 + sum(flags))
            self.assertEqual(count, present)
        self.assertEqual(m.core_count(0, 256, 0, 0, 0, 0, 0, 0, 0), (258, 2))
        self.assertEqual(m.core_count(0, 0, 2, 0, 0, 0, 0, 0, 0), (4, 3))
        self.assertEqual(m.core_count(0, 0, 0, 0, 0, 2, 0, 0, 0), (3, 3))
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                m.core_count(0, 0, bad, 0, 0, 0, 0, 0, 0)

    def test_materializer_to_builder_vector_crosswalk_and_corruption(self):
        rows = m.materializer_crosswalk(self.data, self.sections)
        self.assertEqual([(r[1], r[2]) for r in rows], [
            ('0x1848', '0x3368'), ('0x1850', '0x3370'), ('0x1858', '0x3378')])
        layouts = {r[0]: r[6] for r in m.layout_rows(self.data, self.sections)}
        self.assertEqual(rows[1][2], layouts['low_dex_pointer_offset'])
        self.assertEqual(rows[2][2], layouts['low_dex_count_offset'])
        for site in (0x3751ed9, 0x375225a, 0x3752265):
            with self.subTest(site=hex(site)):
                self.flip_and_check(self.offset(site, executable=True),
                                    lambda: m.materializer_crosswalk(self.data, self.sections))

    def test_shared_capture_copy_operands_reject_corruption(self):
        rows = m.copy_rows(self.data, self.sections)
        self.assertEqual(len(rows), 7)
        self.assertEqual({r[0]: r[3] for r in rows}['core_address'], '0x20')
        for row in rows:
            for column in (1, 4):
                site = int(row[column], 16)
                with self.subTest(site=hex(site)):
                    self.flip_and_check(self.offset(site, executable=True),
                                        lambda: m.copy_rows(self.data, self.sections))

    def test_closure_result_guards_reject_corruption(self):
        rows = m.result_guard_rows(self.data, self.sections)
        self.assertEqual([r[0] for r in rows], ['low', 'shared'])
        for row in rows:
            site = int(row[2], 16)
            self.flip_and_check(self.offset(site + 2, executable=True),
                                lambda: m.result_guard_rows(self.data, self.sections))

    def test_linked_slot_synthetic_guards_and_prefix(self):
        self.assertEqual(m.slot_prefix(1, 0, [(0, 1, 1), (0, 0, 0)]), [0, 1])
        self.assertEqual(m.slot_prefix(1, 0, [(0, 2, 1), (0, 0, 0)]), [0, 1])
        self.assertEqual(m.slot_prefix(0, 0, [(0, 1, 1), (0, 0, 0)]), [])
        self.assertEqual(m.slot_prefix(1, 0, [(2, 1, 1), (0, 0, 0)]), [])
        self.assertEqual(m.slot_prefix(1, 0, [(0, 1, 1), (2, 0, 0)]), [0])
        self.assertEqual(m.slot_prefix(1, 0, [(0, 1, 100)]), [0])
        self.assertEqual(len(m.slot_case_rows()), 11)
        with self.assertRaises(ValueError):
            m.slot_prefix(1, 0, [(0, 1, 0)])
        with self.assertRaises(ValueError):
            m.slot_prefix(1, -1, [(0, 0, 0)])

    def test_labelled_decisions_are_pinned_branch_rows(self):
        branches = m.selected_branches(self.data, self.sections)
        decisions = m.decision_rows(branches)
        self.assertEqual(len(decisions), 26)
        with self.assertRaises(ValueError):
            m.decision_rows(branches[1:0])

    def test_changed_keccak_round_table_rejected(self):
        offset = self.offset(0x7d04c8)
        self.flip_and_check(offset, lambda: m.model_rows(self.data, self.sections))

    def test_header_modes_and_bounds(self):
        for mode in range(256):
            expected = (((mode ^ 1) & 15) << 4) | 0x87
            self.assertEqual(m.header_byte(mode), expected)
        self.assertEqual((m.header_byte(0), m.header_byte(1)), (0x97, 0x87))
        for mode in (-1, 256):
            with self.assertRaises(ValueError):
                m.header_byte(mode)

    def test_synthetic_nested_arrays_and_bounds(self):
        def parse(raw):
            pos = 0
            def array():
                nonlocal pos
                marker = raw[pos]
                pos += 1
                if not 0x90 <= marker <= 0x9f:
                    raise ValueError('not a short array')
                return marker & 15
            result = []
            for _ in range(array()):
                books = []
                for _ in range(array()):
                    self.assertEqual(array(), 2)
                    self.assertEqual(array(), 0)
                    self.assertEqual(array(), 0)
                    books.append(((), ()))
                result.append(books)
            self.assertEqual(pos, len(raw))
            return result
        for counts in ([], [0], [1], [0, 1], [1, 0], [2, 1, 3], [0] * 15):
            self.assertEqual([len(x) for x in parse(m.nested_empty_books(counts))], counts)
        self.assertNotEqual(m.nested_empty_books([0, 1]), m.nested_empty_books([1, 0]))
        for counts in ([16], [-1], [0] * 16):
            with self.assertRaises(ValueError):
                m.nested_empty_books(counts)

    def test_one_order_synthetic_shape_with_independent_reader(self):
        wire = m.one_order_model(self.data, self.sections)
        def parse(pos):
            marker = wire[pos]
            pos += 1
            if marker < 0x80:
                return marker, pos
            if 0x90 <= marker <= 0x9f:
                result = []
                for _ in range(marker & 15):
                    value, pos = parse(pos)
                    result.append(value)
                return result, pos
            if 0x80 <= marker <= 0x8f:
                result = []
                for _ in range(marker & 15):
                    key, pos = parse(pos)
                    value, pos = parse(pos)
                    result.append((key, value))
                return result, pos
            if 0xa0 <= marker <= 0xbf:
                length = marker & 31
                return wire[pos:pos + length].decode('ascii'), pos + length
            if marker == 0xd9:
                length = wire[pos]
                return wire[pos + 1:pos + 1 + length].decode('ascii'), pos + 1 + length
            if marker == 0xc2:
                return False, pos
            if marker == 0xc0:
                return None, pos
            raise ValueError('unsupported marker')
        parsed, end = parse(0)
        self.assertEqual(end, len(wire))
        self.assertEqual(len(wire), 120)
        self.assertEqual(len(parsed), 1)
        sides = parsed[0][0]
        self.assertEqual(len(sides), 2)
        self.assertEqual(sides[1], [])
        price, orders = sides[0][0]
        self.assertEqual(price, 1)
        order = orders[0]
        self.assertEqual([item[0] for item in order],
                         ['is_position_tpsl', 'resting_sz', 'orig_sz', 'user', 'tif', 'core', 'oid'])
        self.assertEqual(order[0][1], False)
        self.assertEqual(order[3][1], '0x' + '00' * 20)
        self.assertIsNone(order[4][1])
        self.assertEqual(order[5][1], [('s', 'B'), ('l', 1)])
        for site in (0x44356d8, 0x45a6a81, 0x4aec6ca, 0x4aeb687, 0x4ae9bf2, 0x4aed5a0, 0x4aed5db):
            with self.subTest(site=hex(site)):
                self.flip_and_check(self.offset(site, executable=True),
                                    lambda: m.one_order_model(self.data, self.sections))

    def test_keccak_known_answers_and_sha3_rate_boundaries(self):
        raw = m.read(self.data, self.sections, 0x7d04c8, 24 * 8)
        rounds = struct.unpack('<24Q', raw)
        self.assertEqual(m.keccak(b'', rounds).hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(m.keccak(b'abc', rounds).hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        for length in (0, 1, 134, 135, 136, 137, 271, 272, 273, 500):
            message = bytes(i % 256 for i in range(length))
            with self.subTest(length=length):
                self.assertEqual(m.keccak(message, rounds, delimiter=6), hashlib.sha3_256(message).digest())
        with self.assertRaises(ValueError):
            m.keccak(b'', rounds, rate=135)


if __name__ == '__main__':
    unittest.main()
