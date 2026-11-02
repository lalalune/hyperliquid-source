# SPDX-License-Identifier: MIT
"""Static corruption controls and bounded projections for the RE-006 packet."""
import csv
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import book_two_insert94 as packet


class Overlay:
    """Alter one byte for selected-window validation without cloning the ELF."""
    def __init__(self, data, offset):
        self.data, self.offset = data, offset

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self.data))
            value = bytearray(self.data[key])
            if step == 1 and start <= self.offset < stop:
                value[self.offset - start] ^= 1
            return value
        return self.data[key] ^ (key == self.offset)


class TwoInsert94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.BINARY.read_bytes()
        cls.image = packet.parse_image(cls.data)
        cls.constants = {r['label']: r['value'] for r in packet.collect_constants(cls.image)}
        cls.tag = cls.constants['error-tag']

    def mutated_image(self, va):
        offset = packet.file_offset(self.data, self.image['secs'], va, 1, executable=True)
        return dict(self.image, data=Overlay(self.data, offset))

    def test_authenticated_fdes_and_raw_file_windows(self):
        rows = packet.collect_functions(self.image)
        self.assertEqual([r['size'] for r in rows], [238, 119, 1995, 296, 834])
        self.assertEqual(len(packet.collect_witnesses(self.image)), 36)
        self.assertEqual(len(packet.collect_branches(self.image)), 69)
        self.assertEqual(len(packet.collect_calls(self.image)), 46)
        self.assertEqual(len(packet.collect_twins(self.image)), 10)
        self.assertEqual(len(packet.collect_sites(self.image)), 44)
        self.assertEqual(len(packet.collect_constants(self.image)), 25)
        for row in rows:
            raw = bytes.fromhex(row['raw'])
            self.assertEqual(len(raw), row['end'] - row['start'])
            self.assertEqual(raw, self.data[row['file_offset']:row['file_offset'] + row['size']])
            self.assertEqual(packet.digest(raw), row['sha256'])

    def test_output_tables_are_byte_derived(self):
        files = packet.build_evidence(self.data)
        self.assertEqual(set(files), {'functions.tsv', 'witnesses.tsv', 'branches.tsv',
                                      'calls.tsv', 'sites.tsv', 'merge-cases.tsv', 'twins.tsv', 'constants.tsv',
                                      'relocations.tsv', 'summary.json'})
        summary = json.loads(files['summary.json'])
        self.assertEqual(summary['artifact_sha256'], packet.EXPECTED_SHA256)
        self.assertEqual((summary['selected_function_fdes'], summary['selected_branches'],
                          summary['selected_transfers_and_rip_loads']), (5, 69, 46))
        self.assertEqual((summary['selected_constants'], summary['selected_relocations']), (25, 7))
        self.assertEqual(summary['selected_instruction_sequences'], 44)
        self.assertEqual(summary['projected_merge_cases'], 4)
        self.assertEqual(summary['compared_host_windows'], 10)
        self.assertEqual((summary['host_windows_raw_equal'], summary['host_windows_normalized_only']), (4, 6))
        for content in files.values():
            self.assertTrue(content.endswith(b'\n'))
            self.assertNotIn(b'\r', content)
        # Independently check exported positions and signed displacements
        # against the original bytes, rather than trusting the collector's
        # decoded addresses.  Only selected instruction forms are allowed.
        def table(name):
            return list(csv.DictReader(io.StringIO(files[name].decode('utf-8')), delimiter='\t'))

        def source(va, n):
            matches = [s for s in self.image['secs'] if s['type'] != 8 and
                       s['address'] <= va and va + n <= s['address'] + s['size']]
            self.assertEqual(len(matches), 1)
            section = matches[0]
            off = section['offset'] + va - section['address']
            return self.data[off:off + n]

        for row in table('branches.tsv'):
            va, raw = int(row['site'], 16), bytes.fromhex(row['raw'])
            self.assertEqual(raw, source(va, len(raw)))
            if len(raw) == 2:
                self.assertTrue(0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb)
                delta = struct.unpack_from('<b', raw, 1)[0]
            else:
                self.assertTrue((len(raw) == 5 and raw[0] == 0xe9) or
                                (len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f))
                delta = struct.unpack_from('<i', raw, len(raw) - 4)[0]
            self.assertEqual(va + len(raw), int(row['fallthrough'], 16))
            self.assertEqual(va + len(raw) + delta, int(row['target'], 16))
        for row in table('calls.tsv'):
            va, raw = int(row['site'], 16), bytes.fromhex(row['raw'])
            self.assertEqual(raw, source(va, len(raw)))
            prefixes = {'direct': b'\xe8', 'indirect-slot': b'\xff\x15',
                        'indirect-jump-slot': b'\xff\x25'}
            if row['kind'] == 'rip-load-slot':
                self.assertIn(raw[:3], (bytes.fromhex('4c8b3d'), bytes.fromhex('4c8b25')))
            else:
                self.assertTrue(raw.startswith(prefixes[row['kind']]))
            self.assertEqual(va + len(raw) + struct.unpack_from('<i', raw, len(raw) - 4)[0],
                             int(row['destination'], 16))
        for name in ('functions.tsv', 'witnesses.tsv', 'sites.tsv'):
            for row in table(name):
                va = int(row.get('start', row.get('site')), 16)
                off, raw = int(row['file_offset'], 16), bytes.fromhex(row['raw'])
                self.assertEqual(raw, source(va, len(raw)))
                self.assertEqual(raw, self.data[off:off + len(raw)])

    def test_hash_mismatch_precedes_output(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.verify_identity(b'bad target')
        with patch.object(packet, 'EXPECTED_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                packet.verify_identity(self.data)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'uncreated'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                packet.write_evidence(b'bad target', dest)
            self.assertFalse(dest.exists())

    def test_corrupt_function_and_witness_bytes_are_rejected(self):
        changed = self.mutated_image(0x4302371)
        with self.assertRaisesRegex(ValueError, 'witness mismatch'):
            packet.collect_functions(changed)
        with self.assertRaisesRegex(ValueError, 'witness mismatch'):
            packet.collect_witnesses(changed)
        with self.assertRaisesRegex(ValueError, 'instruction mismatch'):
            packet.collect_constants(changed)
        with self.assertRaisesRegex(ValueError, 'instruction sequence mismatch'):
            packet.collect_sites(changed)
        with self.assertRaisesRegex(ValueError, 'witness mismatch'):
            packet.collect_witnesses(self.mutated_image(0x4d146f2))

    def test_branch_and_call_opcode_and_displacement_controls(self):
        site = 0x4471e2e
        raw = packet.read_instruction(self.image, site, 2)
        self.assertEqual(packet.checked_branch(raw, site, '71', 0x4471e51)['target'], 0x4471e51)
        for bad in (b'\x70' + raw[1:], raw[:1] + bytes([raw[1] ^ 1]), b'\x0f\x84'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                packet.checked_branch(bad, site, '71', 0x4471e51)
        near = packet.read_instruction(self.image, 0x4d144b3, 5)
        self.assertEqual(packet.checked_branch(near, 0x4d144b3, 'e9', 0x4d146d5)['target'], 0x4d146d5)
        with self.assertRaises(ValueError):
            packet.decode_branch(near[:4], 0x4d144b3)
        site = 0x4d14654
        raw = packet.read_instruction(self.image, site, 5)
        self.assertEqual(packet.checked_call(raw, site, 0x4471d80), 0x4471d80)
        for bad in (b'\xe9' + raw[1:], raw[:1] + bytes([raw[1] ^ 1]) + raw[2:]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                packet.checked_call(bad, site, 0x4471d80)
        indirect = packet.read_instruction(self.image, 0x4d1475d, 6)
        self.assertEqual(packet.checked_call(indirect, 0x4d1475d, 0x57747b8, indirect=True), 0x57747b8)
        with self.assertRaises(ValueError):
            packet.checked_call(b'\xff\x25' + indirect[2:], 0x4d1475d, 0x57747b8, indirect=True)
        jump = packet.read_instruction(self.image, 0x447b826, 6)
        self.assertEqual(packet.decode_indirect_jump(jump, 0x447b826), 0x576e010)
        with self.assertRaises(ValueError):
            packet.decode_indirect_jump(b'\xff\x15' + jump[2:], 0x447b826)
        with self.assertRaises(ValueError):
            packet.collect_branches(self.mutated_image(0x4d146f6))
        with self.assertRaises(ValueError):
            packet.collect_calls(self.mutated_image(0x4d14654))

    def test_twin_comparison_rejects_mutations_inside_and_outside_masks(self):
        rows = packet.collect_twins(self.image)
        self.assertEqual(sum(row['raw_equal'] for row in rows), 4)
        with self.assertRaisesRegex(ValueError, 'outside call displacements'):
            packet.collect_twins(self.mutated_image(0x4d16eee))
        with self.assertRaisesRegex(ValueError, 'call destination mismatch'):
            packet.collect_twins(self.mutated_image(0x4d16ee5))

    def test_address_mapping_and_fde_boundaries_fail_closed(self):
        small = bytes(16)
        text = {'name': '.text', 'type': 1, 'flags': 4, 'address': 0x100, 'offset': 0, 'size': 8}
        bss = {'name': '.bss', 'type': 8, 'flags': 4, 'address': 0x200, 'offset': 0, 'size': 8}
        self.assertEqual(packet.file_offset(small, [text, bss], 0x107, 1, executable=True), 7)
        for va, size in ((0x200, 1), (0x107, 2), (0xff, 1), (0x100, 0), ((1 << 64)-1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                packet.file_offset(small, [text, bss], va, size, executable=True)
        with self.assertRaises(ValueError):
            packet.file_offset(small, [text, dict(text)], 0x100, 1, executable=True)
        actual_bss = next(s for s in self.image['secs'] if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            packet.file_offset(self.data, self.image['secs'], actual_bss['address'], 1)
        with self.assertRaises(ValueError):
            packet.containing_fde(self.image, 0x430237d, 2)

    def test_relocation_records_and_negative_controls(self):
        rows = packet.selected_relocations(self.data, self.image['secs'])
        self.assertEqual(len(rows), 7)
        self.assertEqual({r['symbol_name'] for r in rows if r['symbol_name']}, {'memcpy', 'memmove', 'memcmp'})
        rela = struct.pack('<QQq', 0x1000, (1 << 32) | 6, 0)
        syms = bytes(24) + struct.pack('<I', 1) + bytes(20)
        names = b'\0memcpy\0'
        blob = rela + syms + names
        sections = [
            {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24},
            {'name': '.dynsym', 'type': 11, 'offset': 24, 'size': 48},
            {'name': '.dynstr', 'type': 3, 'offset': 72, 'size': len(names)},
        ]
        expected = ((0x1000, 6, 0, 'memcpy'),)
        self.assertEqual(packet.selected_relocations(blob, sections, expected)[0]['symbol_name'], 'memcpy')
        for bad in (struct.pack('<QQq', 0x1000, (1 << 32) | 7, 0) + syms + names,
                    struct.pack('<QQq', 0x1000, (2 << 32) | 6, 0) + syms + names,
                    rela + syms + b'\0otherx\0'):
            with self.subTest(bad=bad[:24]), self.assertRaises(ValueError):
                packet.selected_relocations(bad, sections, expected)
        with self.assertRaises(ValueError):
            packet.selected_relocations(blob, sections, ((0x1000, 6, 1, 'memcpy'),))
        with self.assertRaises(ValueError):
            packet.selected_relocations(blob, sections + [dict(sections[0], type=8)], expected)
        duplicate = rela + rela + syms + names
        shifted = [dict(sections[0], size=48), dict(sections[1], offset=48), dict(sections[2], offset=96)]
        with self.assertRaisesRegex(ValueError, 'duplicate relocation'):
            packet.selected_relocations(duplicate, shifted, expected)

    def test_merge_choice_exact_tag_not_merely_sign_bit(self):
        tag = self.tag
        for a, b, expected in ((tag, tag, 'a-error'), (tag, 0, 'b'), (0, tag, 'a'),
                               (0, 0, 'combine'), (tag + 1, 0, 'combine'),
                               (tag - 1, tag, 'a'), (tag, tag + 1, 'b')):
            with self.subTest(a=a, b=b):
                self.assertEqual(packet.project_merge_choice(a, b, tag), expected)
        rows = packet.collect_merge_cases(self.image, packet.collect_branches(self.image),
                                          packet.collect_constants(self.image))
        self.assertEqual([(r['selected'], r['output_block']) for r in rows],
                         [('a-error', 0x4471e35), ('b', 0x4471e8b),
                          ('a', 0x4471e56), ('combine', 0x4471ec0)])
        with self.assertRaisesRegex(ValueError, 'compare changed'):
            packet.collect_merge_cases(self.mutated_image(0x4471e30), packet.collect_branches(self.image),
                                       packet.collect_constants(self.image))

    def test_remaining_saturates_and_absent_summary_keeps_input(self):
        project = packet.project_remaining
        for original, present, filled, expected in ((10, False, 99, 10), (10, True, 0, 10),
                                                     (10, True, 4, 6), (10, True, 10, 0),
                                                     (10, True, 11, 0), (0, True, 1, 0),
                                                     ((1 << 64)-1, True, 1, (1 << 64)-2)):
            with self.subTest(original=original, present=present, filled=filled):
                self.assertEqual(project(original, present, filled), expected)
        for original, present, filled in ((-1, True, 0), (0, True, 1 << 64), (1, 2, 0)):
            with self.assertRaises(ValueError):
                project(original, present, filled)

    def test_success_content_order_empty_and_sentinel_control(self):
        a, b, c, d = (bytes([i]) * 20 for i in range(4))
        original = {a: [3, 5], b: [8]}
        entries = [(a, 2, [13, 21]), (c, 0, []), (d, self.tag, []), (b, 1, [34])]
        result, fills = packet.project_success_contents(original, entries, ['a1', 'a2'], ['b1'], self.tag)
        self.assertEqual(result, {a: [3, 5, 13, 21], b: [8], c: []})
        self.assertEqual(fills, ['a1', 'a2', 'b1'])
        self.assertEqual(original, {a: [3, 5], b: [8]})
        with self.assertRaises(ValueError):
            packet.project_success_contents({b'short': []}, [], [], [], self.tag)
        with self.assertRaises(ValueError):
            packet.project_success_contents({}, [(a, 0, [1])], [], [], self.tag)

    def test_host_classification_independently_uses_saved_first_tag(self):
        route = packet.project_host_route
        tag = self.tag
        cases = ((tag, 1, 0, ('clear', 'rewrite')), (tag, 1, tag, ()),
                 (0, 0, 0, ('opaque-helper', 'rewrite')),
                 (0, 1, 0, ('opaque-helper', 'slot-write', 'rewrite')),
                 (0, 2, 0, ('clear', 'rewrite')),
                 (0, 3, tag, ('opaque-helper', 'slot-write')),
                 (0, 255, 0, ('opaque-helper', 'slot-write', 'rewrite')))
        for a, flag, saved, expected in cases:
            with self.subTest(a=a, flag=flag, saved=saved):
                self.assertEqual(route(a, flag, saved, tag), expected)
        for flag in (-1, 256):
            with self.assertRaises(ValueError):
                route(0, flag, 0, tag)

    def test_slot_write_empty_collision_wrapping_and_bounds(self):
        apply = packet.project_slot_write
        c = self.constants
        controls = bytearray([0xff] * 16)
        slots = [(0, 42), (1, 43)]
        self.assertEqual(apply(0, b'', {}, 0, slots, 99, c), (False, slots))
        self.assertEqual(apply(0, controls, {}, 1, slots, 99, c), (False, slots))
        controls[0] = controls[1] = 0
        buckets = {0: (0, 0), 1: (22, 1)}
        self.assertEqual(apply(22, controls, buckets, 2, slots, 99, c), (True, [(0, 42), (1, 99)]))
        self.assertEqual(apply(0, controls, {0: (0, 2), 1: (22, 1)}, 2, slots, 99, c), (False, slots))
        vacant = [(0x100000002, 42), (1, 43)]
        self.assertEqual(apply(0, controls, buckets, 2, vacant, 99, c), (False, vacant))
        controls32 = bytearray([0x80] * 16 + [0xff] * 16)
        controls32[16] = 0
        self.assertEqual(apply(0, controls32, {16: (0, 0)}, 1, slots, 99, c), (True, [(0, 99), (1, 43)]))
        with self.assertRaisesRegex(ValueError, 'terminating'):
            apply(0, bytearray([0x80] * 16), {}, 1, slots, 99, c)
        with self.assertRaises(ValueError):
            apply(1 << 64, controls, buckets, 2, slots, 99, c)

    def test_fill_row_count_limit_and_invalid_extent(self):
        c = self.constants
        stride, limit = c['fill-row-stride'], c['fill-maximum-row-count']
        self.assertEqual(limit, ((1 << 63) - 1) // stride)
        self.assertEqual((c['fill-row-count-multiplier'] * (stride // 8)) & ((1 << 64)-1), 1)
        first = limit // 2
        self.assertEqual(packet.project_fill_bound(first * stride, (limit - first) * stride, c), (limit, True))
        self.assertEqual(packet.project_fill_bound(0, (limit + 1) * stride, c), (limit + 1, False))
        for bad in (-1, 1, 1 << 64):
            with self.assertRaises(ValueError):
                packet.project_fill_bound(0, bad, c)


if __name__ == '__main__':
    unittest.main()
