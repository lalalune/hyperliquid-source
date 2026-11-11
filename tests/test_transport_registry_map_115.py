import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_registry_map_115 as tr  # noqa: E402


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tr.load_image()
        tr.IMAGE_FOR_CONTROLS = cls.image

    def run_suite(self, check, count, seed, rig=None):
        rig = rig or tr.Rig(self.image)
        rng = tr.Rng(seed)
        failed = []
        for index in range(count):
            strings = tr.make_strings(rng, 24)
            ok, label = check(rig, rng, index, strings)
            if not ok:
                failed.append((index, label))
        return rig, failed


class ModelMatchesBytes(Fixture):
    def test_hasher_both_key_shapes(self):
        _, failed = self.run_suite(tr.check_hash, 400, 1)
        self.assertEqual(failed, [])

    def test_entry_probe_and_growth(self):
        _, failed = self.run_suite(tr.check_entry, 400, 2)
        self.assertEqual(failed, [])

    def test_reserve_rehash_resize_in_place_and_errors(self):
        rig, failed = self.run_suite(tr.check_reserve, 500, 3)
        self.assertEqual(failed, [])
        self.assertIn(0x4764749, rig.covered | rig.machine.seen)          # the swap with a DELETED slot is reached

    def test_record_sum_count_max_and_lock(self):
        rig, failed = self.run_suite(tr.check_record, 400, 4)
        self.assertEqual(failed, [])
        self.assertIn(0x4772158, rig.covered | rig.machine.seen)          # contended lock path is reached

    def test_each_function_range_decodes_to_its_fde_end(self):
        for name, lo, hi in tr.FUNCTIONS:
            self.assertTrue(0 <= hi - self.image.exact_fde(lo)[1] < 16, name)          # the rest is int3 padding
            self.assertTrue(tr.decode_range(self.image, lo, hi), name)


class ModelRules(unittest.TestCase):
    def test_sum_clamp_rules(self):
        inf = 0x7FF0000000000000
        self.assertEqual(tr.saturate_sum(0xBFF0000000000000, 7), 0)                # negative becomes +0
        self.assertEqual(tr.saturate_sum(0x8000000000000000, 7), 0x8000000000000000)   # -0.0 stays
        self.assertEqual(tr.saturate_sum(inf, 7), 7)                                # +inf becomes the constant
        self.assertEqual(tr.saturate_sum(inf | 1 << 63, 7), 0)
        self.assertEqual(tr.saturate_sum(inf + 1, 7), 0)                            # NaN becomes +0
        self.assertEqual(tr.saturate_sum(0x3FF0000000000000, 7), 0x3FF0000000000000)
        self.assertEqual(tr.saturate_sum(1, 7), 1)                                  # subnormals stay

    def test_capacity_rules(self):
        self.assertEqual([tr.capacity_to_buckets(cap) for cap in (1, 3, 4, 7, 8, 14, 15, 28)], [4, 4, 8, 8, 16, 16, 32, 32])
        self.assertEqual([tr.mask_to_capacity(mask) for mask in (3, 7, 15, 63)], [3, 7, 14, 56])

    def test_tag_is_compared_as_32_bits_and_shapes_differ(self):
        strings = {0x1000: b"abc"}
        self.assertTrue(tr.keys_equal((0x1000, 3, 5), (0x1000, 3, 5 | 1 << 40), strings))
        self.assertFalse(tr.keys_equal((0x1000, 3, 5), (0, 0x1000, 3), strings))
        self.assertNotEqual(tr.key_hash((0x1000, 3, 0), strings), tr.key_hash((0, 0x1000, 3), strings))

    def test_hash_depends_on_every_length_class(self):
        seen = set()
        for size in (0, 1, 3, 4, 7, 8, 16, 17, 32, 33, 49):
            seen.add(tr.key_hash((0, 0x2000, size), {0x2000: bytes(range(size))}))
        self.assertEqual(len(seen), 11)


class NegativeControls(Fixture):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(tr.EvidenceError):
            tr.load_image(expected="0" * 64)

    def test_misaligned_function_end_is_rejected(self):
        with self.assertRaises(tr.EvidenceError):
            tr.decode_range(self.image, tr.HASHER, tr.HASHER_END - 1)

    def test_address_outside_functions_is_rejected(self):
        with self.assertRaises(tr.EvidenceError):
            self.image.exact_fde(tr.ENTRY + 1)

    def test_changed_rotate_amount_in_the_hasher_is_detected(self):
        rows = [row for row in tr.decode_range(self.image, tr.HASHER, tr.HASHER_END) if row.op == "rol"]
        at = rows[0].va + rows[0].imm_at
        patched = self.image.blob[self.image.offset(at)] ^ 1
        found = tr.first_divergence(self.image, {at: patched}, (("hash", tr.check_hash, 30),))
        self.assertIsNotNone(found)

    def test_flipped_overflow_branch_in_reserve_is_detected(self):
        row = [row for row in tr.decode_range(self.image, tr.RESERVE, tr.RESERVE_END) if row.va == 0x47642ED][0]
        self.assertEqual(row.op, "jcc")
        at = row.va + (0 if row.size == 2 else 1)
        found = tr.first_divergence(self.image, {at: self.image.blob[self.image.offset(at)] ^ 1}, (("reserve", tr.check_reserve, 200),))
        self.assertIsNotNone(found)

    def test_wrong_model_constant_is_detected(self):
        old = tr.HASH_K1
        tr.HASH_K1 = old ^ 1
        try:
            rig, failed = self.run_suite(tr.check_hash, 30, 1)
        finally:
            tr.HASH_K1 = old
        self.assertTrue(failed)

    def test_bent_expectations_are_rejected_by_the_comparison(self):
        results = tr.state_controls(self.image)
        self.assertEqual(len(results), 4)
        self.assertTrue(all(caught for _, _, caught in results))

    def test_input_controls_all_rejected(self):
        results = tr.input_controls(self.image)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(caught for _, _, caught in results))


class Determinism(Fixture):
    def test_cases_are_reproducible(self):
        first = [(index, digest, steps) for index, _, _, digest, steps in tr.suite_cases(tr.Rig(self.image), tr.check_hash, 40, 5)]
        second = [(index, digest, steps) for index, _, _, digest, steps in tr.suite_cases(tr.Rig(self.image), tr.check_hash, 40, 5)]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
