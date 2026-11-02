"""Controls for byte-backed state-loader error construction and cleanup."""
import json
import struct
import unittest

from tools import abci_loader_error94 as m


class LoaderErrorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.image = m.Image(cls.data)
        cls.spec = m.make_spec(cls.image)
        cls.files = m.collect(cls.image)

    def test_target_digest_and_byte_mutation_are_rejected(self):
        self.assertEqual(m.check_digest(self.data), m.SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.check_digest(self.data, '0'*64)
        changed = bytearray(self.data)
        offset = self.image.off(0x3c1b2cf, 1)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.check_digest(changed)
        with self.assertRaisesRegex(ValueError, 'selected function bytes'):
            m.Image(changed, authenticate=False)

    def test_all_selected_body_hashes_and_frame_membership(self):
        records = json.loads(self.files['functions.json'])
        self.assertEqual(len(records), 14)
        self.assertEqual({int(row['start_va'], 16) for row in records}, set(m.FUNCTIONS))
        for record in records:
            start = int(record['start_va'], 16)
            self.assertEqual(bytes.fromhex(record['raw_hex']), self.image.read(start, record['size']))
            self.assertEqual(int(record['end_va_exclusive'], 16), self.image.frame(start)['end'])
            self.assertEqual(int(record['fde_va'], 16), self.image.index[start])
            m.checked_body(bytes.fromhex(record['raw_hex']), record['sha256'])

    def test_actual_fde_extent_corruption_is_rejected(self):
        changed = bytearray(self.data)
        frame = self.image.frame(0x365e850)
        # This selected CIE uses a 32-bit relative pc followed by sdata4 range.
        pos = self.image.off(frame['fde'], 16)
        changed[pos+12] ^= 1
        with self.assertRaises(ValueError):
            m.Image(changed, authenticate=False)

    def test_instruction_witness_mutation_is_rejected(self):
        for va in (0x365e524, 0x3c1b2c8, 0x3272a9c, 0x3c15a38, 0x365e620):
            expected = m.ANCHORS[va][1]
            raw = bytearray(self.image.read(va, len(bytes.fromhex(expected))))
            m.checked_anchor(raw, expected)
            raw[len(raw)//2] ^= 1
            with self.assertRaisesRegex(ValueError, 'instruction bytes'):
                m.checked_anchor(raw, expected)

    def test_file_backed_mapping_rejects_bounds_and_nobits(self):
        fake = [dict(type=8, address=0x1000, offset=0, size=32, name='.bss')]
        with self.assertRaises(ValueError):
            m.map_offset(fake, 0x1000, 1)
        backed = dict(type=1, address=0x2000, offset=10, size=16, name='.text')
        self.assertEqual(m.map_offset([backed], 0x200f, 1), 25)
        for va, length in ((0x1fff, 1), (0x200f, 2), (0x2000, 0), (-1, 1)):
            with self.assertRaises(ValueError):
                m.map_offset([backed], va, length)
        with self.assertRaises(ValueError):
            m.map_offset([backed, dict(backed)], 0x2000, 1)

    def test_real_and_corrupted_relative_calls(self):
        for site, (_, target) in m.CALLS.items():
            raw = self.image.read(site, 5)
            self.assertEqual(m.decode_rel32(raw, site), target)
        raw = bytearray(self.image.read(0x365e821, 5))
        raw[0] ^= 1
        with self.assertRaises(ValueError):
            m.decode_rel32(raw, 0x365e821)
        with self.assertRaises(ValueError):
            m.decode_rel32(b'\xe8\x00', 0x365e821)

    def test_branch_targets_and_corruption(self):
        for site in m.BRANCHES:
            f = self.image.owner(site)
            r = m.decode_jcc(self.image.read(site, 6), site, f['start'], f['end'])
            self.assertTrue(f['start'] <= r['target'] < f['end'])
        f = self.image.frame(0x3c1b2c0)
        raw = self.image.read(0x3c1b2cf, 6)
        self.assertEqual(m.decode_jcc(raw, 0x3c1b2cf, f['start'], f['end'])['target'], 0x3c1b32b)
        with self.assertRaises(ValueError):
            m.decode_jcc(b'\x90\x00', 0x3c1b2cf, f['start'], f['end'])
        with self.assertRaises(ValueError):
            m.decode_jcc(b'\x77\x7f', f['end']-2, f['start'], f['end'])
        with self.assertRaises(ValueError):
            m.decode_jcc(b'\x0f\x84\x00', 0x3c1b2cf, f['start'], f['end'])

    def test_relocations_reject_duplicate_missing_type_and_symbol(self):
        slots = [0x100, 0x108]
        good = [(0x100, 8, 0x200), (0x108, 8, 0x300)]
        self.assertEqual(m.selected_relocations(good, slots), {0x100: 0x200, 0x108: 0x300})
        for bad in (good[:1], good + [good[0]], [(0x100, 7, 0x200), good[1]],
                    [(0x100, (1 << 32) | 8, 0x200), good[1]]):
            with self.assertRaises(ValueError):
                m.selected_relocations(bad, slots)
        selected = m.selected_relocations(self.image.rela_rows, [0x56f1668, 0x576e010])
        self.assertEqual(selected, {0x56f1668: 0x365e520, 0x576e010: 0x54c8cb0})

    def test_jump_table_and_out_of_range_corruption(self):
        base = self.spec['rmp_table_va']
        raw = self.image.read(base, 28)
        frame = self.image.frame(0x3c1b2c0)
        targets = m.decode_jump_table(raw, base, frame['start'], frame['end'])
        self.assertEqual(targets, [0x3c1b2f3, 0x3c1b31d, 0x3c1b32b, 0x3c1b32b,
                                   0x3c1b32b, 0x3c1b2e1, 0x3c1b2e1])
        damaged = bytearray(raw)
        struct.pack_into('<i', damaged, 0, 0)
        with self.assertRaisesRegex(ValueError, 'outside'):
            m.decode_jump_table(damaged, base, frame['start'], frame['end'])
        with self.assertRaises(ValueError):
            m.decode_jump_table(raw[:-1], base, frame['start'], frame['end'])

    def test_in_range_wrong_jump_target_is_rejected_by_model(self):
        original = self.image.read(self.spec['rmp_table_va'], 28)
        altered = bytearray(original)
        original_delta = struct.unpack_from('<i', altered, 0)[0]
        struct.pack_into('<i', altered, 0, original_delta + 1)

        class ReplacedTable:
            def read(inner, va, size):
                if va == self.spec['rmp_table_va'] and size == len(altered):
                    return bytes(altered)
                return self.image.read(va, size)

            def frame(inner, start):
                return self.image.frame(start)

        with self.assertRaisesRegex(ValueError, 'unexpected RMP table target'):
            m.make_spec(ReplacedTable())

    def test_changed_table_relocation_is_rejected_after_digest_gate(self):
        # Feed a changed parsed RELA record to the collector: this exercises its
        # linkage check independently of the mandatory whole-file digest gate.
        modified = list(self.image.rela_rows)
        index = next(i for i, row in enumerate(modified) if row[0] == 0x56f1668)
        slot, info, _ = modified[index]
        modified[index] = (slot, info, 0x365e6b0)
        altered = object.__new__(m.Image)
        altered.__dict__ = dict(self.image.__dict__)
        altered.rela_rows = modified
        with self.assertRaisesRegex(ValueError, 'table relocation targets'):
            m.collect(altered)

    def test_lsda_witnesses_and_absent_site(self):
        expected = [(0x32725d0, 0x3272a3f, 0x3272a9c),
                    (0x3c155a0, 0x3c15a40, 0x3c15c06),
                    (0x3c155a0, 0x3c15b3e, 0x3c15bae),
                    (0x3c155a0, 0x3c15a54, 0x3c15c14),
                    (0x3c155a0, 0x3c15b53, 0x3c15bbd),
                    (0x365e7e0, 0x365e7f8, 0x365e830),
                    (0x365e7e0, 0x365e821, None),
                    (0x365e850, 0x365e8d6, 0x365e8de),
                    (0x365e520, 0x365e531, 0x365e562),
                    (0x3c1b4f0, 0x3c1b53f, 0x3c1b594)]
        for owner, site, landing in expected:
            table = m.parse_lsda(self.data, self.image.secs, self.image.frame(owner))
            row = m.covering(table['rows'], site)
            self.assertEqual(row['landing'], landing)
            self.assertEqual(row['action'], 0)
        with self.assertRaises(ValueError):
            m.covering([], 0)
        with self.assertRaises(ValueError):
            m.covering([{'begin': 0, 'end': 2}, {'begin': 0, 'end': 2}], 1)

    def test_lsda_rejects_bad_header_truncation_and_range(self):
        sec = [dict(name='.gcc_except_table', type=1, address=0x800, offset=0, size=8)]
        frame = dict(start=0x1000, end=0x1010, lsda=0x800)
        valid = bytes.fromhex('ffff010400010100')
        decoded = m.parse_lsda(valid, sec, frame)
        self.assertEqual(decoded['rows'][0]['landing'], 0x1001)
        for raw in (bytes.fromhex('00ff010400010100'), bytes.fromhex('ffff010500010100'),
                    bytes.fromhex('ffff010400200100'), bytes.fromhex('ffff010400010180')):
            with self.assertRaises(ValueError):
                m.parse_lsda(raw, sec, frame)

        real = self.image.frame(0x365e850)
        start = self.image.off(real['lsda'], 64)
        window = bytearray(self.data[start:start+64])
        local = [dict(name='.gcc_except_table', type=1, address=real['lsda'], offset=0, size=len(window))]
        self.assertTrue(m.parse_lsda(window, local, real)['rows'])
        window[0] = 0
        with self.assertRaisesRegex(ValueError, 'unsupported LSDA header'):
            m.parse_lsda(window, local, real)

    def test_all_256_rmp_tags(self):
        tagged = [('callback', 0x220), ('release', 0x220, 8, 0), ('release', 0x100, 24, 0)]
        buffer = [('release', 0x330, 3, 0)]
        for tag in range(256):
            actual = m.rmp_actions(self.spec, tag, tagged=0x101, data_ptr=0x220, size=8,
                                   alignment=8, callback=True, buffer_ptr=0x330, buffer_capacity=3)
            expected = tagged if tag in (0, 1) else buffer if tag in (5, 6) else []
            self.assertEqual(actual, expected, tag)
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                m.rmp_actions(self.spec, bad)

    def test_tagged_pointer_low_bits_and_optional_callback(self):
        for low in range(4):
            for callback in (False, True):
                for unwinds in (False, True):
                    got = m.io_actions(self.spec, 0x100+low, 0x220, 8, 8, callback, unwinds)
                    if low != 1:
                        self.assertEqual(got, [])
                        continue
                    expected = ([('callback', 0x220)] if callback else [])
                    expected += [('release', 0x220, 8, 0), ('release', 0x100, 24, 0)]
                    if callback and unwinds:
                        expected += [('resume_unwind',)]
                    self.assertEqual(got, expected)

    def test_zero_payload_still_releases_tag_wrapper(self):
        for callback in (False, True):
            actions = m.io_actions(self.spec, 0x101, 0x220, 0, 0, callback)
            expected = ([('callback', 0x220)] if callback else []) + [('release', 0x100, 24, 0)]
            self.assertEqual(actions, expected)
        self.assertEqual(m.rmp_actions(self.spec, 5, buffer_ptr=3, buffer_capacity=0), [])

    def test_alignment_conditions_and_invalid_zero_alignment(self):
        for size, align, expected in ((1, 1, 0), (1, 8, 3), (8, 8, 0), (15, 16, 4),
                                      (16, 16, 0), (17, 16, 0), (32, 32, 5), (32, 17, 0)):
            self.assertEqual(m.align_code(size, align, self.spec['align_cutoff']), expected)
        with self.assertRaises(ValueError):
            m.align_code(1, 0, self.spec['align_cutoff'])

    def test_json_release_order_and_callback_unwind(self):
        self.assertEqual(m.json_actions(self.spec, 0, 0x400, buffer_ptr=0x330, buffer_capacity=3),
                         [('release', 0x330, 3, 0), ('release', 0x400, 40, 0)])
        self.assertEqual(m.json_actions(self.spec, 2, 0x400), [('release', 0x400, 40, 0)])
        self.assertEqual(m.json_actions(self.spec, 1, 0x400, tagged=0x101, data_ptr=0x220,
                         size=8, alignment=8, callback=True, callback_unwinds=True),
                         [('callback', 0x220), ('release', 0x220, 8, 0),
                          ('release', 0x100, 24, 0), ('release', 0x400, 40, 0), ('resume_unwind',)])
        self.assertEqual(m.json_actions(self.spec, 1, 0x400, tagged=0x102, data_ptr=0x220,
                         size=8, alignment=8, callback=True, callback_unwinds=True),
                         [('release', 0x400, 40, 0)])

    def test_rmp_callback_unwind_has_no_json_outer_release(self):
        for tag in (0, 1):
            self.assertEqual(m.rmp_actions(self.spec, tag, tagged=0x101, data_ptr=0x220, size=8,
                             alignment=8, callback=True, callback_unwinds=True),
                             [('callback', 0x220), ('release', 0x220, 8, 0),
                              ('release', 0x100, 24, 0), ('resume_unwind',)])

    def test_record_drop_heap_stack_and_unwind(self):
        self.assertEqual(m.record_drop_actions(self.spec, 2, 0x220, 3, 0x400, True, True),
                         [('trace_drop',), ('release', 0x220, 3, 0),
                          ('release', 0x400, 80, 0), ('resume_unwind',)])
        self.assertEqual(m.record_drop_actions(self.spec, 2, 0x220, 3, 0x400, False, True),
                         [('trace_drop',), ('release', 0x220, 3, 0), ('resume_unwind',)])
        self.assertEqual(m.record_drop_actions(self.spec, 1, 0x220, 0, 0x400, True, True),
                         [('release', 0x400, 80, 0)])

    def test_trace_mode_gate_and_vector_arithmetic(self):
        entries = [{'sub_base': 0x500, 'capacity': 1, 'items': [
            {'first_ptr': 0x600, 'first_size': 0, 'variant': 0, 'second_ptr': 0x700, 'second_size': 3},
            {'first_ptr': 0x610, 'first_size': 1 << 63, 'variant': 1, 'second_ptr': 0x710, 'second_size': 4},
            {'first_ptr': 0x620, 'first_size': 5, 'variant': 2, 'second_ptr': 0x720, 'second_size': 9},
        ]}]
        expected = [('trace_item',), ('release', 0x700, 3, 0), ('release', 0x710, 8, 0),
                    ('release', 0x620, 5, 0), ('release', 0x500, 72, 0), ('release', 0x900, 56, 0)]
        for mode in (0, 3):
            self.assertEqual(m.trace_list_actions(self.spec, mode, 0x900, 1, entries), expected)
        self.assertEqual(m.trace_list_actions(self.spec, 2, 0x900, 1, entries), [])
        for mode in (1, 4, 0xffffffff):
            self.assertEqual(m.trace_list_actions(self.spec, mode, 0x900, 1, entries), [('diagnostic',)])
        self.assertEqual(m.trace_item_actions(self.spec, 0x500, 1 << 63, []),
                         [('release', 0x500, 0, 0)])
        with self.assertRaises(ValueError):
            m.trace_list_actions(self.spec, 1 << 32, 0x900, 1, entries)

    def test_type_comparator_requires_all_sixteen_bytes(self):
        expected = self.spec['type_id']
        self.assertEqual(m.type_match(self.spec, expected, 0x400), 0x438)
        for offset in range(len(expected)):
            for replacement in range(256):
                mutated = bytearray(expected)
                mutated[offset] = replacement
                value = m.type_match(self.spec, bytes(mutated), 0x400)
                self.assertEqual(value, 0x438 if replacement == expected[offset] else 0)
        with self.assertRaises(ValueError):
            m.type_match(self.spec, expected[:-1], 0x400)

    def test_generated_outputs_are_stable_and_report_selected_scope(self):
        self.assertEqual(self.files, m.collect(self.image))
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['target']['sha256'], m.SHA256)
        self.assertEqual(summary['metrics']['selected_fdes'], 14)
        self.assertEqual(summary['metrics']['rmp_table_entries'], 7)
        self.assertEqual(summary['metrics']['descriptor_relocations'], 6)
        self.assertEqual(summary['metrics']['external_boundary_relocations'], 5)
        self.assertEqual(summary['metrics']['synthetic_cases'], 326)
        self.assertIn('prior-caller-boundary', self.files['instructions.tsv'].decode())
        self.assertIn('called `Result::unwrap()` on an `Err` value', summary['diagnostic_ascii'])


if __name__ == '__main__':
    unittest.main()
