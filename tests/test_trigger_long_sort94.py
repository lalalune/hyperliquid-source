"""Target-grounded controls for the trigger long-sort evidence collector."""
import json
import itertools
from pathlib import Path
import sys
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import trigger_long_sort94 as t
from elf_index import sections, unwind_index


class TriggerLongSortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = t.TARGET.read_bytes()
        t.authenticate(cls.data)
        cls.fdes = {f['start']: f for rows in t.fde_map(cls.data).values() for f in rows}
        cls.pins = {name: t.read_va(cls.data, va, len(bytes.fromhex(raw)), True)
                    for name, va, raw in t.PINS}
        cls.constants = t.constants(cls.pins)

    def test_authenticated_input_and_corrupt_hash(self):
        t.authenticate(self.data)
        with self.assertRaises(t.EvidenceError):
            t.authenticate(b'corrupt target')
        with self.assertRaises(t.EvidenceError):
            t.authenticate(self.data[:-1])

    def test_eight_distinct_extents(self):
        self.assertEqual(len(t.FUNCTIONS), 8)
        self.assertEqual(len({row[1] for row in t.FUNCTIONS}), 8)
        _, header = unwind_index(self.data)
        index = {row['start']: row['fde'] for row in header}
        for name, start, end in t.FUNCTIONS:
            with self.subTest(name=name):
                self.assertEqual(self.fdes[start]['end'], end)
                self.assertEqual(index[start], self.fdes[start]['fde'])
                self.assertEqual(len(t.read_va(self.data, start, end - start, True)), end - start)

    def test_all_fixed_windows_reject_corruption(self):
        for name, _, raw in t.PINS:
            with self.subTest(name=name):
                expected = bytes.fromhex(raw)
                actual = self.pins[name]
                t.check_pin(actual, expected)
                changed = bytearray(actual)
                changed[len(changed) // 2] ^= 1
                with self.assertRaises(t.EvidenceError):
                    t.check_pin(bytes(changed), expected)

    def test_address_mapping_rejects_out_of_range_and_nobits(self):
        text = next(s for s in sections(self.data) if s['name'] == '.text')
        bss = next(s for s in sections(self.data) if s['name'] == '.bss')
        t.file_offset(self.data, text['address'], 1, True)
        with self.assertRaises(t.EvidenceError):
            t.file_offset(self.data, bss['address'], 1)
        for va, size in ((0, 1), (text['address'] + text['size'] - 1, 2),
                         (bss['address'], 1), (text['address'], 0)):
            with self.subTest(va=va, size=size), self.assertRaises(t.EvidenceError):
                t.file_offset(self.data, va, size, True)

    def test_slot_calls_and_corrupt_displacement(self):
        relocs = t.relative_relocations(self.data, {x[2] for x in t.SLOT_CALLS})
        for name, site, slot, target in t.SLOT_CALLS:
            with self.subTest(name=name):
                raw = t.read_va(self.data, site, 6, True)
                self.assertEqual(t.slot_target(raw, site, relocs), (slot, target))
                changed = bytearray(raw)
                changed[2] ^= 1
                with self.assertRaises(t.EvidenceError):
                    t.slot_target(changed, site, relocs)
        with self.assertRaises(t.EvidenceError):
            t.relative_relocations(self.data, {0})
        first_slot = t.SLOT_CALLS[0][2]
        altered = bytearray(self.data)
        struct.pack_into('<Q', altered, relocs[first_slot]['file_offset'] + 8, 0)
        with self.assertRaises(t.EvidenceError):
            t.relative_relocations(altered, {first_slot})

    def test_direct_calls_and_bad_opcode(self):
        for name, site, target in t.DIRECT_CALLS:
            with self.subTest(name=name):
                raw = t.read_va(self.data, site, 5, True)
                self.assertEqual(t.direct_target(raw, site), target)
                self.assertNotEqual(t.direct_target(raw[:1] + bytes([raw[1] ^ 1]) + raw[2:], site), target)
                with self.assertRaises(t.EvidenceError):
                    t.direct_target(b'\x90' + raw[1:], site)

    def test_conditional_branches_and_bad_opcode(self):
        for name, site, opcode in t.BRANCH_SITES:
            with self.subTest(name=name):
                row = t.decode_branch(self.data, site, opcode)
                self.assertTrue(row['target'].startswith('0x'))
                with self.assertRaises(t.EvidenceError):
                    t.decode_branch(self.data, site, opcode ^ 1)

    def test_copy_masks_and_unmasked_instruction_control(self):
        for _, a, b, masks in t.PAIRS:
            self.assertTrue(t.compare_pair(self.data, self.fdes, a, b, masks))
        altered = bytearray(self.data)
        a, b, masks = t.PAIRS[0][1:]
        offset = t.file_offset(self.data, a, 1, True)
        altered[offset] ^= 1
        with self.assertRaises(t.EvidenceError):
            t.compare_pair(altered, self.fdes, a, b, masks)
        altered[offset] ^= 1
        opcode = t.file_offset(self.data, a + masks[0] - 2, 1, True)
        altered[opcode] ^= 1
        with self.assertRaises(t.EvidenceError):
            t.compare_pair(altered, self.fdes, a, b, masks)

    def test_selector_buffer_boundary_cases(self):
        c = self.constants
        expectations = {
            0: ('no_sort', None, None), 1: ('no_sort', None, None),
            2: ('selector_short', None, None), 20: ('selector_short', None, None),
            21: ('stack', 102, 1), 64: ('stack', 102, 1),
            65: ('stack', 102, 0), 102: ('stack', 102, 0),
            103: ('heap', 103, 0), 200000: ('heap', 200000, 0),
            200001: ('heap', 200000, 0), 400000: ('heap', 200000, 0),
            400001: ('heap', 200001, 0),
        }
        for n, expected in expectations.items():
            with self.subTest(count=n):
                row = t.buffer_case(n, c)
                self.assertEqual((row['path'], row['scratch_entries'], row['small_flag']), expected)
        self.assertEqual(t.buffer_case(102, c)['scratch_bytes'], 4080)
        self.assertEqual(t.buffer_case(103, c)['scratch_bytes'], 4120)
        for invalid in (-1, 1 << 64):
            with self.assertRaises(t.EvidenceError):
                t.buffer_case(invalid, c)

    def test_capacity_check_arithmetic_controls(self):
        c = self.constants
        limit = c['arithmetic_half_limit']
        self.assertEqual(t.buffer_case(2 * limit, c)['path'], 'heap')
        self.assertEqual(t.buffer_case(2 * limit + 1, c)['path'], 'capacity_error')
        self.assertEqual(t.buffer_case(2 * limit, c)['scratch_bytes'], (1 << 63) - 8)

    def test_run_threshold_boundaries(self):
        c = self.constants
        for n, expected in ((2, 1), (3, 2), (127, 64), (128, 64),
                            (4096, 64), (4097, 64), (8191, 95), (8192, 96)):
            with self.subTest(count=n):
                self.assertEqual(t.run_threshold(n, c), expected)
        with self.assertRaises(t.EvidenceError):
            t.run_threshold(1, c)

    def test_merge_ties_in_selected_static_instructions(self):
        # The pinned compare/conditional-move sequences select left on a tie
        # for forward output and right on a tie for backward output. These are
        # local rules, not execution or a full proof of the complete sorter.
        self.assertIn(bytes.fromhex('483b0e0f92c10f93c24889f7480f42fd'), self.pins['merge_forward'])
        self.assertIn(bytes.fromhex('483b55d8498d5424d8400f92c6480f42d1'), self.pins['merge_backward'])
        for left, right, forward, backward in ((0, 0, 'left', 'right'),
                                                (3, 4, 'left', 'right'),
                                                (4, 3, 'right', 'left'),
                                                ((1 << 64) - 1, (1 << 64) - 1, 'left', 'right')):
            with self.subTest(left=left, right=right):
                self.assertEqual('right' if right < left else 'left', forward)
                self.assertEqual('left' if right < left else 'right', backward)

    def test_natural_run_direction_preserves_equal_boundary(self):
        # Reading the first key pair uses unsigned order. A descending run is
        # extended only while the next key is strictly smaller; the ascending
        # run admits equality. This tests a model of those pinned conditions.
        self.assertIn(bytes.fromhex('4d39d30f83'), self.pins['descending_test'])
        self.assertIn(bytes.fromhex('4d39c873'), self.pins['descending_extend'])
        self.assertIn(bytes.fromhex('4d39c872'), self.pins['ascending_extend'])

        def run(rows):
            descending = rows[1][0] < rows[0][0]
            end = 2
            while end < len(rows):
                previous, current = rows[end - 1][0], rows[end][0]
                if (current >= previous) if descending else (current < previous):
                    break
                end += 1
            selected = rows[:end]
            return (list(reversed(selected)) if descending else selected), rows[end:]

        self.assertEqual(run([(3, 'x'), (2, 'first'), (2, 'second'), (1, 'y')]),
                         ([(2, 'first'), (3, 'x')], [(2, 'second'), (1, 'y')]))
        self.assertEqual(run([(1, 'first'), (1, 'second'), (2, 'x'), (0, 'y')]),
                         ([(1, 'first'), (1, 'second'), (2, 'x')], [(0, 'y')]))

    def test_forward_and_backward_merge_models_keep_tie_order(self):
        def merge(left, right, backwards):
            result = []
            left, right = list(left), list(right)
            while left and right:
                if backwards:
                    result.append(left.pop() if right[-1][0] < left[-1][0] else right.pop())
                else:
                    result.append(right.pop(0) if right[0][0] < left[0][0] else left.pop(0))
            if backwards:
                result.extend(reversed(right))
                result.extend(reversed(left))
                result.reverse()
            else:
                result.extend(left)
                result.extend(right)
            return result

        left = [(1, 'left-a'), (2, 'left-b'), (2, 'left-c'), (7, 'left-d')]
        right = [(0, 'right-a'), (2, 'right-b'), (2, 'right-c'), (8, 'right-d')]
        expected = [(0, 'right-a'), (1, 'left-a'), (2, 'left-b'), (2, 'left-c'),
                    (2, 'right-b'), (2, 'right-c'), (7, 'left-d'), (8, 'right-d')]
        self.assertEqual(merge(left, right, False), expected)
        self.assertEqual(merge(left, right, True), expected)

    def test_four_row_network_and_tie_mutant(self):
        # The collector pins the complete selection window before using this
        # model. The reference is Python's stable sort, not the transcription.
        mismatches = 0
        count = 0
        for keys in itertools.product(range(4), repeat=4):
            rows = list(zip(keys, range(4)))
            expected = sorted(rows, key=lambda row: row[0])
            self.assertEqual(t.four_row_network(rows), expected)
            mismatches += t.four_row_network(rows, mutant=True) != expected
            count += 1
        self.assertEqual(count, 256)
        self.assertEqual(mismatches, 84)
        high_keys = (0, 1 << 63, (1 << 64) - 1)
        for keys in itertools.product(high_keys, repeat=4):
            rows = list(zip(keys, range(4)))
            self.assertEqual(t.four_row_network(rows), sorted(rows, key=lambda row: row[0]))
        signed_example = list(zip((0, 1 << 63, (1 << 64) - 1, 1), range(4)))
        signed_order = sorted(signed_example, key=lambda row: row[0] - (1 << 64) if row[0] >= 1 << 63 else row[0])
        self.assertNotEqual(t.four_row_network(signed_example), signed_order)
        with self.assertRaises(t.EvidenceError):
            t.four_row_network([(0, 0)])

    def test_small_partition_model_against_stable_order(self):
        # Exhaust every three-key vector at the first size using both pinned
        # four-row networks; the reference uses a library stable sort.
        mutants = 0
        for keys in itertools.product(range(3), repeat=8):
            rows = list(zip(keys, range(8)))
            expected = sorted(rows, key=lambda row: row[0])
            self.assertEqual(t.small_sort_model(rows), expected)
            mutants += t.small_sort_model(rows, mutant=True) != expected
        self.assertEqual(mutants, 4445)
        for size in (2, 7, 8, 9, 31, 32):
            for keys in ((0,) * size, tuple(reversed(range(size))),
                         tuple((i * 4 + 1) % 5 for i in range(size))):
                rows = list(zip(keys, range(size)))
                self.assertEqual(t.small_sort_model(rows), sorted(rows, key=lambda row: row[0]))
        for size in (1, 33):
            with self.assertRaises(t.EvidenceError):
                t.small_sort_model([(0, i) for i in range(size)])

    def test_generated_files_equal_retained_evidence(self):
        work_item = ROOT / 'research/work-items/RE-006-trigger-long-sort-94'
        names = ('evidence.json', 'windows.tsv', 'calls.tsv', 'branches.tsv',
                 'buffer-boundaries.tsv', 'run-boundaries.tsv', 'small-network-model.tsv', 'small-sort-model.tsv')
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            result = t.generate(self.data, out)
            self.assertEqual(len(result['calls']), 25)
            self.assertEqual(result['model_summary'], {'four_row_cases': 256,
                'four_row_mutant_mismatches': 84, 'small_sort_cases': 9933,
                'small_sort_mutant_mismatches': 4469})
            self.assertEqual(json.loads((out / 'evidence.json').read_text())['target_sha256'], t.TARGET_SHA)
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual((out / name).read_bytes(), (work_item / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
