"""Static and adversarial controls for cancellation-ID sorting evidence."""
import itertools
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import book_cancel_sort94 as subject


class CancelSortEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.image = subject.Image(cls.data)
        cls.result = subject.analyze(cls.data)

    def test_five_unique_indexed_fde_ranges(self):
        rows = self.result['functions.tsv'][1]
        self.assertEqual(len(rows), 5)
        self.assertEqual([(r[1], r[2]) for r in rows], [
            ('0x4497a90', '0x4498022'), ('0x45c35b0', '0x45c366f'),
            ('0x4912a50', '0x4912d13'), ('0x4918d30', '0x49190b7'),
            ('0x4dbd490', '0x4dbdb5e')])
        self.assertEqual([r[5] for r in rows if r[1] == '0x4918d30'], ['0xb8638c'])

    def test_input_digest_is_required(self):
        data = bytearray(self.data)
        data[100] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.analyze(data)

    def test_every_selected_anchor_rejects_corruption(self):
        data = bytearray(self.data)
        for name, address, _ in subject.PINS:
            offset = self.image.offset(address, 1)
            data[offset] ^= 1
            try:
                with self.assertRaises(ValueError, msg=name):
                    subject.pin_rows(subject.Image(data))
            finally:
                data[offset] ^= 1

    def test_unpinned_function_byte_is_still_checked(self):
        data = bytearray(self.data)
        offset = self.image.offset(0x4497a90, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'function body bytes changed'):
            subject.function_rows(subject.Image(data))

    def test_range_and_nobits_rejection(self):
        for address, size in ((-1, 1), (1 << 64, 1), (0x4497a90, -1)):
            with self.assertRaises(ValueError):
                self.image.read(address, size)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read(0x5774f50, 1, executable=True)

    def test_decoded_constants(self):
        self.assertEqual(subject.constants(self.image), {
            'external_sort_min': 21, 'scratch_max_stack': 512, 'scratch_cap': 1000000,
            'flag_limit': 65, 'run_long_min': 4097, 'run_small_cap': 64,
            'partition_small_min': 33, 'pivot_recursive_min': 64, 'small_scratch_extra': 16,
        })

    def test_book_and_slot_layout_immediates(self):
        rows = {r[0]: r[-1] for r in subject.layout_rows(self.image)}
        self.assertEqual(rows['book user-map root offset'], '0xb8')
        self.assertEqual(rows['book user-map height offset'], '0xc0')
        self.assertEqual(rows['slot stride'], '0xf8')
        self.assertEqual(rows['vacant low-dword tag'], '0x2')
        self.assertEqual(rows['live slot key offset'], '0xd8')
        damaged = bytearray(self.data)
        offset = self.image.offset(0x2563692, 1)
        damaged[offset] ^= 1
        with self.assertRaises(ValueError):
            subject.layout_rows(subject.Image(damaged))

    def test_context_long_sort_relocation_and_run_call(self):
        rows = self.result['calls.tsv'][1]
        self.assertEqual(len(rows), 21)
        self.assertIn(('context user sweep to collector adapter', '0x26e4441', 'e84a381000', '', '0x27e7c90'), rows)
        self.assertIn(('context order removal', '0x26e457f', 'e84c9effff', '', '0x26de3d0'), rows)
        self.assertIn(('context long-sort entry', '0x27e7ea6', 'ff15a4d0f802', '0x5774f50', '0x4486d10'), rows)
        self.assertIn(('context wrapper to run', '0x4486db8', 'e8d3669300', '', '0x4dbd490'), rows)
        self.assertIn(('run to partition', '0x4dbd5d1', 'ff15c9929b00', '0x57768a0', '0x4497a90'), rows)
        self.assertIn(('partition fallback to run', '0x4497fd1', 'e8ba549200', '', '0x4dbd490'), rows)

    def test_call_opcode_and_displacement_corruption(self):
        data = bytearray(self.data)
        for address in (0x4486db8, 0x27e7ea6, 0x4dbd5d1):
            offset = self.image.offset(address + 3, 1)
            data[offset] ^= 1
            try:
                with self.assertRaises(ValueError, msg=hex(address)):
                    subject.calls(subject.Image(data))
            finally:
                data[offset] ^= 1

    def test_relative_relocation_corruption(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            if int.from_bytes(data[off:off + 8], 'little') == 0x57768a0:
                data[off + 8] ^= 1
                break
        else:
            self.fail('relative relocation missing')
        with self.assertRaises(ValueError):
            subject.calls(subject.Image(data))

    def test_conditional_targets_and_bad_opcode(self):
        rows = self.result['branches.tsv'][1]
        self.assertEqual(len(rows), 21)
        self.assertIn(('0x27e7da5', 'candidate count >= 21', '0f83f0000000', '0x27e7e9b', '0x27e7dab'), rows)
        self.assertIn(('0x4497ba3', 'scratch length below current partition length', '0f8248040000', '0x4497ff1', '0x4497ba9'), rows)
        data = bytearray(self.data)
        offset = self.image.offset(0x4497ba3, 1)
        data[offset] = 0x90
        with self.assertRaises(ValueError):
            subject.branch(subject.Image(data), 0x4497ba3)

    def test_context_threshold_projection(self):
        c = subject.constants(self.image)
        self.assertEqual(c['external_sort_min'] - 1, 20)
        self.assertEqual(c['external_sort_min'], 21)
        self.assertEqual(subject.buffer_projection(64, c)[2], 1)
        self.assertEqual(subject.buffer_projection(65, c)[2], 0)

    def test_scratch_boundaries_and_cap(self):
        c = subject.constants(self.image)
        self.assertEqual(subject.buffer_projection(512, c), (512, 'stack', 0))
        self.assertEqual(subject.buffer_projection(513, c), (513, 'heap', 0))
        self.assertEqual(subject.buffer_projection(1000001, c)[0], 1000000)
        self.assertEqual(subject.buffer_projection(2000001, c)[0], 1000001)

    def test_run_scale_and_threshold_boundaries(self):
        c = subject.constants(self.image)
        for n in (2, 21, 64, 65, 4096, 4097, 8192, 1000001):
            threshold, scale = subject.run_projection(n, c)
            self.assertEqual(scale, (1 << 62) // n + int((1 << 62) % n != 0))
            self.assertGreater(threshold, 0)
        self.assertEqual(subject.run_projection(4096, c)[0], 64)
        self.assertEqual(subject.run_projection(4097, c)[0], 64)
        with self.assertRaises(ValueError):
            subject.run_projection(1, c)

    def test_four_key_network_against_independent_sort(self):
        differences = 0
        for values in itertools.product(range(4), repeat=4):
            result = subject.four_network(values)
            self.assertEqual(result, tuple(sorted(values)))
            differences += subject.four_network(values, mutant=True) != result
        self.assertEqual(differences, self.result['summary.json']['network_mutant_differences'])
        self.assertEqual(differences, 92)
        v = ((1 << 64) - 1, 0, 1 << 63, 1)
        self.assertEqual(subject.four_network(v), tuple(sorted(v)))

    def test_four_network_rejects_out_of_range_input(self):
        for bad in ((1, 2, 3), (0, 0, 0, -1), (0, 0, 0, 1 << 64)):
            with self.assertRaises(ValueError):
                subject.four_network(bad)

    def test_pivot_leaf_against_independent_median(self):
        differences = 0
        for values in itertools.product(range(4), repeat=3):
            selected = subject.pivot_leaf(values)
            self.assertEqual(values[selected], sorted(values)[1])
            differences += values[subject.pivot_leaf(values, mutant=True)] != values[selected]
        self.assertEqual(differences, self.result['summary.json']['pivot_mutant_differences'])
        self.assertGreater(differences, 0)

    def test_pivot_rejects_bad_inputs(self):
        for bad in ((1, 2), (0, 0, -1), (0, 0, 1 << 64)):
            with self.assertRaises(ValueError):
                subject.pivot_leaf(bad)

    def test_small_sort_exception_range_and_cleanup(self):
        rows = subject.lsda_rows(self.image, 0x4918d30, 0x49190b7, 0xb8638c)
        self.assertEqual(rows[1], (0x4919091, 0x4919097, 0x4919099, 0))
        self.assertEqual(len(rows), 3)

    def test_corrupted_lsda_is_rejected(self):
        data = bytearray(self.data)
        offset = self.image.offset(0xb8638c, 1)
        data[offset] ^= 1
        with self.assertRaises(ValueError):
            subject.lsda_rows(subject.Image(data), 0x4918d30, 0x49190b7, 0xb8638c)

    def test_changed_lsda_landing_fails_full_analysis(self):
        data = bytearray(self.data)
        offset = self.image.offset(0xb8638c + 12, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'cleanup landing changed'):
            subject.analyze(data, verify_digest=False)

    def test_equal_key_merge_projection(self):
        rows = self.result['merge-projections.tsv'][1]
        equal = next(row for row in rows if row[:2] == (1, 1))
        self.assertEqual(equal[2:], (1, 1, 'second', 'second'))
        self.assertEqual(self.result['summary.json']['scope'].split('.')[0], 'Selected static paths only')


if __name__ == '__main__':
    unittest.main()
