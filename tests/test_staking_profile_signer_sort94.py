import hashlib
import itertools
from pathlib import Path
import tempfile
import unittest

from tools import staking_profile_signer_sort94 as subject


class SignerSortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), subject.SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'node'
            bad.write_bytes(b'not the captured image')
            with self.assertRaisesRegex(subject.EvidenceError, 'SHA-256'):
                subject.load_image(bad)

    def test_all_function_bounds_and_hashes(self):
        subject.validate_image(self.image)
        for start, size in subject.SIZES.items():
            self.assertEqual(self.image.exact_fde(start), (start, start+size))
            self.assertEqual(hashlib.sha256(subject.bytes_at(self.image, start, size, True)).hexdigest(),
                             subject.HASHES[start])

    def test_reject_outside_address_and_nonstart(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(0, 1, True)
        with self.assertRaises(subject.EvidenceError):
            self.image.exact_fde(0x386a1e1)
        nobits = next(sec for sec in self.image.sections if sec['name'] == '.bss' and sec['type'] == 8)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(nobits['address'], 1)

    def test_reject_mutated_subject_and_context(self):
        original = self.image.blob
        data = bytearray(original)
        try:
            for va in (0x386a1e0, 0x3bb292f):
                off = self.image.offset(va, 1, True)
                data[off] ^= 1
                self.image.blob = data
                with self.assertRaises(subject.EvidenceError):
                    subject.validate_image(self.image)
                data[off] ^= 1
        finally:
            self.image.blob = original

    def test_reject_duplicate_or_wrong_relocation(self):
        original = self.image.relocations
        def duplicate():
            yield from original()
            yield (0x5775f58, 8, 0x3879d30, 0)
        def changed():
            for slot, kind, addend, index in original():
                if slot == 0x5775f58:
                    addend += 1
                yield slot, kind, addend, index
        try:
            self.image.relocations = duplicate
            with self.assertRaisesRegex(subject.EvidenceError, 'duplicate'):
                subject.relocation_records(self.image)
            self.image.relocations = changed
            with self.assertRaisesRegex(subject.EvidenceError, 'unexpected'):
                subject.relocation_records(self.image)
        finally:
            self.image.relocations = original

    def test_profile_context_calls(self):
        self.assertEqual(subject.slot_target(self.image, 0x3bb297a), 0x5776298)
        self.assertEqual(subject.call_target(self.image, 0x3bc131a), 0x386a1e0)
        self.assertEqual(subject.call_target(self.image, 0x3879e29), 0x3860890)
        with self.assertRaises(subject.EvidenceError):
            subject.call_target(self.image, 0x3bb297a)

    def test_unsigned_and_last_byte_order(self):
        values = [b'\x80'*19 + bytes([x]) for x in (255, 0, 128, 1, 127)] * 5
        values += [b'\xff'+b'\x00'*19, b'\x00'+b'\xff'*19]
        runner, got = subject.evaluate_sort(self.image, values)
        self.assertEqual(got, sorted(values))
        self.assertGreater(runner.comparisons, 0)
        self.assertEqual(got[0], b'\x00'+b'\xff'*19)
        self.assertEqual(got[-1], b'\xff'+b'\x00'*19)

    def test_duplicates_and_sorted_reverse(self):
        for name, rows in subject.fixtures():
            if name in ('equal_21', 'duplicates_65', 'ascending_64', 'descending_65'):
                _, got = subject.evaluate_sort(self.image, rows)
                self.assertEqual(got, sorted(rows))
                self.assertEqual(len(got), len(rows))

    def test_small_capacity_boundary(self):
        for n in (0, 1):
            self.assertEqual(subject.small_probe(self.image, n, 0)[1], 'sorted')
        for n in (2, 5, 20, 32):
            self.assertEqual(subject.small_probe(self.image, n, n+15)[1], 'trap')
            self.assertEqual(subject.small_probe(self.image, n, n+16)[1], 'sorted')
        with self.assertRaises(ValueError):
            subject.small_probe(self.image, 33, 49)

    def test_reject_invalid_fixtures(self):
        with self.assertRaises(ValueError):
            subject.evaluate_sort(self.image, [bytes(20)]*20)
        with self.assertRaises(ValueError):
            subject.evaluate_sort(self.image, [bytes(19)]*21)

    def test_partition_budget_and_fallback(self):
        shallow, _ = subject.partition_probe(self.image, 32, 0)
        self.assertNotIn(0x387a2c5, shallow.machine.seen)
        fallback, _ = subject.partition_probe(self.image, 65, 0)
        self.assertIn(0x387a2c5, fallback.machine.seen)
        deep, _ = subject.partition_probe(self.image, 65, 5)
        self.assertIn(0x3860890, deep.machine.seen)
        self.assertNotIn(0x387a2c5, deep.machine.seen)
        with self.assertRaises(ValueError):
            subject.partition_probe(self.image, 1, 0)

    def test_pivot_three_and_recursive(self):
        for n in (0, 7):
            for values in itertools.permutations((0, 127, 255)):
                _, _, chosen = subject.pivot_probe(self.image, n, values)
                self.assertEqual(chosen, bytes([127])*20)
        for values, median in (((127,127,255),127), ((0,127,127),127), ((0,0,0),0)):
            _, _, chosen = subject.pivot_probe(self.image, 0, values)
            self.assertEqual(chosen, bytes([median])*20)
        for n, count in ((8,9),(64,27)):
            _, used, selected = subject.pivot_probe(self.image, n, [(i*73+131)%256 for i in range(count)])
            self.assertEqual(len(used), count)
            self.assertIn(selected[0], used)
        with self.assertRaises(ValueError):
            subject.pivot_probe(self.image, 8, (1, 2, 3))

    def test_pivot_branch_corruption(self):
        subject.pivot_probe(self.image, 0, (0,127,255))
        with self.assertRaises(subject.Halt):
            subject.pivot_probe(self.image, 0, (0,127,255), {0x386092d:0x79})

    def test_comparator_and_partition_corruption_controls(self):
        rows = [((i*37) % 65).to_bytes(20, 'big') for i in range(65)]
        subject.evaluate_sort(self.image, rows)
        for va, value in ((0x3389e31, 0x98), (0x3879efc, 0x49), (0x3389de8, 0x83)):
            with self.assertRaises((subject.Halt, subject.Panicked)):
                subject.evaluate_sort(self.image, rows, {va: value})


if __name__ == '__main__':
    unittest.main()
