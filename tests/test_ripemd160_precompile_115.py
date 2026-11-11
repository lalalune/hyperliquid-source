import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ripemd160_precompile_115 as T  # noqa: E402


class RipemdPrecompileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.ctl = T.control_inputs(cls.image)

    def test_published_vectors_model_and_machine(self):
        rows = T.check_vectors(self.image)
        self.assertEqual(len(rows), len(T.VECTORS))

    def test_wrong_published_vector_is_refused(self):
        original = T.VECTORS
        try:
            T.VECTORS = ((b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfd"),)
            with self.assertRaises(T.ToolError):
                T.check_vectors(self.image)
        finally:
            T.VECTORS = original

    def test_block_function_matches_model(self):
        matched, steps, rows = T.run_compress_cases(self.image, 60, 3, seed=77)
        self.assertEqual(matched, 60)
        self.assertEqual(len(rows), 3)
        self.assertGreater(steps, 60 * 1500)

    def test_wrapper_boundaries_with_real_block_function(self):
        rig = T.Rig(self.image)
        rng = T.Rng(5)
        for n in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 200):
            data = rng.blob(n)
            got, events, _ = rig.run_wrapper(data)
            want, wevents = T.wrapper_model(data)
            self.assertEqual(got, want, n)
            self.assertEqual([e for e in events if e[0] != "compress"], [e for e in wevents if e[0] != "compress"], n)
            self.assertEqual(got[:12], bytes(12))

    def test_wrapper_event_sequence_with_stubbed_block_function(self):
        rig = T.Rig(self.image, stub_compress=True)
        for n in (0, 55, 56, 63, 64, 130):
            data = T.Rng(n + 1).blob(n)
            got, events, _ = rig.run_wrapper(data)
            want, wevents = T.wrapper_model(data)
            self.assertEqual((got, events), (want, wevents), n)

    def test_block_count_per_tail_length(self):
        blocks = {n: sum(1 for e in T.wrapper_model(bytes(n))[1] if e[0] == "compress") for n in (0, 55, 56, 63, 64, 119, 120)}
        self.assertEqual(blocks, {0: 1, 55: 1, 56: 2, 63: 2, 64: 2, 119: 2, 120: 4 - 1})

    def test_relocation_and_table_evidence(self):
        slots = {row[0]: row for row in T.slot_rows(self.image)}
        self.assertEqual(slots["compress pointer"][4], T.COMPRESS)
        self.assertEqual(slots["table entry ripemd body"][4], T.WRAPPER)
        self.assertEqual(slots["table entry sha256 body"][4], T.SHA_BODY)
        self.assertEqual(slots["compress pointer"][2], 8)

    def test_function_bounds(self):
        rows = {r[0]: r for r in T.function_rows(self.image)}
        self.assertEqual(rows["ripemd_wrapper"][1], T.WRAPPER)
        self.assertEqual(rows["ripemd_wrapper"][2], 0x5BEDBC7)
        self.assertEqual(rows["ripemd_block"][2], 0x5C3E4EB)

    def test_every_constant_appears_sixteen_times(self):
        for side, rnd, k, count in T.constant_rows(self.image):
            self.assertEqual(count, 0 if k == 0 else 16, (side, rnd))

    def test_rotation_histogram(self):
        for count, want, got in T.rotation_rows(self.image):
            if count == 10:
                self.assertEqual((want, got), (160, 158))
            else:
                self.assertEqual(want, got, count)

    def test_all_model_mutants_are_detected(self):
        mutants = T.model_mutants() + T.pad_mutants()
        self.assertGreaterEqual(len(mutants), 40)
        for name, kind, param in mutants:
            self.assertTrue(T.model_mutant_detected(kind, param, self.ctl), name)

    def test_unmutated_model_is_not_flagged(self):
        self.assertFalse(T.model_mutant_detected("model-table", T.Tables(), self.ctl))
        self.assertFalse(T.model_mutant_detected("model-padding", T.PadOptions(), self.ctl))

    def test_byte_corruptions_are_detected(self):
        block = T.byte_mutants_block(self.image)
        wrapper = T.byte_mutants_wrapper(self.image)
        self.assertEqual((len(block), len(wrapper)), (22, 10))
        for name, kind, param in block[:2] + block[-2:]:
            self.assertTrue(T.machine_mutant_detected(self.image, kind, param, self.ctl), name)
        for name, kind, param in wrapper[:5]:
            self.assertTrue(T.machine_mutant_detected(self.image, kind, param, self.ctl), name)

    def test_equivalent_mutants_really_are_equivalent(self):
        flagged = {name for name, kind, param in T.byte_mutants_wrapper(self.image)
                   if not T.machine_mutant_detected(self.image, kind, param, self.ctl)}
        self.assertEqual(len(flagged), 2)
        for name in flagged:
            self.assertTrue(any(key in name for key, _ in T.EQUIVALENT), name)

    def test_out_of_range_inputs_are_refused(self):
        rows = T.range_controls(self.image)
        self.assertEqual(len(rows), 7)
        self.assertTrue(all(detected for _, _, detected in rows), rows)

    def test_wrong_binary_is_refused(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image_bytes(bytes(self.image.blob[:-1]))

    def test_non_fde_start_is_refused(self):
        with self.assertRaises(T.EvidenceError):
            self.image.exact_fde(T.WRAPPER + 4)

    def test_hook_panic_slot_raises(self):
        rig = T.Rig(self.image)
        with self.assertRaises(T.Panicked):
            rig.hook_panic(rig.m)


class Sha256PortableArmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.ctl = T.sha_control_inputs(cls.image)

    def test_constants_derived_from_primes(self):
        self.assertEqual(T.SHA_K[0], 0x428A2F98)
        self.assertEqual(T.SHA_K[63], 0xC67178F2)
        self.assertEqual(T.SHA_INIT[0], 0x6A09E667)
        self.assertEqual(T.SHA_INIT[7], 0x5BE0CD19)

    def test_machine_matches_hashlib(self):
        self.assertEqual(len(T.sha_check_vectors(self.image)), 6)

    def test_block_function_matches_model(self):
        count, steps, rows = T.run_sha_compress_cases(self.image, 40, 2, seed=9)
        self.assertEqual((count, len(rows)), (40, 2))
        self.assertGreater(steps, 40 * 3000)

    def test_wrapper_event_sequence(self):
        rig = T.ShaRig(self.image, stub_compress=True)
        for n in (0, 55, 56, 63, 64, 65, 127, 128, 200):
            data = T.Rng(n + 3).blob(n)
            got, events, _ = rig.run_wrapper(data)
            self.assertEqual((got, events), T.sha_wrapper_model(data), n)

    def test_wrapper_with_real_block_bytes(self):
        rig = T.ShaRig(self.image)
        for n in (0, 1, 55, 56, 64, 119, 120, 130):
            data = T.Rng(n + 5).blob(n)
            self.assertEqual(rig.run_wrapper(data)[0], T.hashlib.sha256(data).digest(), n)

    def test_all_model_and_padding_mutants_are_detected(self):
        for name, kind, param in T.sha_model_mutants():
            self.assertTrue(T.sha_mutant_detected(param, self.ctl), name)
        for name, kind, param in T.sha_pad_mutants():
            self.assertTrue(T.sha_pad_detected(param), name)
        self.assertFalse(T.sha_mutant_detected(T.ShaTables(), self.ctl))

    def test_byte_corruptions_are_detected(self):
        mutants = T.sha_machine_mutants(self.image)
        self.assertEqual(len(mutants), 16)
        for name, kind, param in mutants[:3] + mutants[-3:]:
            self.assertTrue(T.sha_machine_mutant_detected(self.image, kind, param, self.ctl), name)

    def test_relocation_evidence(self):
        slots = {row[0]: row for row in T.slot_rows(self.image)}
        self.assertEqual(slots["sha256 compress pointer"][4], T.SHA_COMPRESS)

    def test_every_round_constant_present_in_portable_arm(self):
        for round_index, constant, count in T.sha_constant_rows(self.image):
            self.assertGreaterEqual(count, 1, round_index)


if __name__ == "__main__":
    unittest.main()
