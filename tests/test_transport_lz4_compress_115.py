"""Tests for the node #115 LZ4 compressor drivers reconstruction: model against interpreted bytes, plus negative controls."""
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import transport_lz4_compress_115 as t  # noqa: E402


def machine_for(patches=None):
    return t.build_machine(t.IMAGE, patches)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t.IMAGE = t.load_image()


class IdentityTests(Base):
    def test_binary_digest_is_enforced(self):
        self.assertEqual(hashlib.sha256(t.IMAGE.blob).hexdigest(), t.SHA256)
        with self.assertRaises(t.EvidenceError):
            t.load_image_bytes(b"not the node")
        with self.assertRaises(t.EvidenceError):
            t.load_image_bytes(bytes(t.IMAGE.blob[:-1]))

    def test_function_extents_are_fde_starts(self):
        for entry, (start, _end) in t.SIG_EXPECT.items():
            self.assertEqual(t.IMAGE.exact_fde(entry)[0], start)
            with self.assertRaises(t.EvidenceError):
                t.IMAGE.exact_fde(entry + 1)

    def test_addresses_outside_file_sections_are_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.IMAGE.offset(0x10)


class ModelUnitTests(unittest.TestCase):
    def test_excess_bytes_follow_the_255_convention(self):
        for amount, expected in ((0, [0]), (254, [254]), (255, [255, 0]), (256, [255, 1]), (510, [255, 255, 0])):
            out = bytearray()
            t.put_excess(out, 99, amount, t.Flags())
            self.assertEqual(list(out), expected)

    def test_full_sink_panics_before_the_byte_that_does_not_fit(self):
        with self.assertRaises(t.ModelPanic):
            t.put_excess(bytearray(2), 2, 0, t.Flags())
        with self.assertRaises(t.ModelPanic):
            t.put_literals(bytearray(1), 3, b"abcdef", 0, 3)

    def test_hash_cells(self):
        flags = t.Flags()
        self.assertEqual(t.hash_cell(t.SMALL, b"\0\0\0\0", 0, flags), 0)
        self.assertEqual(t.hash_cell(t.SMALL, b"\1\0\0\0", 0, flags), (0x9E3779B1 & 0xFFFFFFFF) >> 20)
        self.assertEqual(t.hash_cell(t.LARGE, b"\1\0\0\0\0\0\0\0", 0, flags), (0xCF1BBCDCBB000000) >> 52)
        for word in (b"\xff" * 8, b"abcdefgh"):
            self.assertLess(t.hash_cell(t.SMALL, word, 0, flags), 4096)
            self.assertLess(t.hash_cell(t.LARGE, word, 0, flags), 4096)

    def test_count_bounds(self):
        data = bytes(range(20)) * 3
        matched, end = t.model_count(data, 0, data, 20)
        self.assertEqual(end, matched)
        self.assertLessEqual(matched, len(data) - 6)
        with self.assertRaises(t.ModelPanic):
            t.model_count(data, 60, data, 0)
        with self.assertRaises(t.ModelPanic):
            t.model_count(data, 0, data, 61)

    def test_short_input_is_tail_only(self):
        for size in range(0, 13):
            src = bytes(range(size))
            status, out = t.model_compress(t.SMALL, src, 0, 0, 200, 0, [0] * 4096)
            self.assertEqual(status, 0)
            self.assertEqual(out, bytes([size << 4]) + src)

    def test_short_room_returns_status_one(self):
        status, out = t.model_compress(t.SMALL, bytes(100), 0, 0, 100, 0, [0] * 4096)
        self.assertEqual((status, out), (1, b""))

    def test_contract_violations_panic(self):
        with self.assertRaises(t.ModelPanic):
            t.model_compress(t.SMALL, b"abc", 4, 0, 99, 0, [0] * 4096)
        with self.assertRaises(t.ModelPanic):
            t.model_compress(t.LARGE, b"abc", 0, 0, 99, 0, [0] * 4096, arg7=1)
        with self.assertRaises(t.ModelPanic):
            t.model_compress(t.LARGE, b"abc", 0, 0, 3, 9, [0] * 4096)


class NativeAgreementTests(Base):
    def test_known_vector_on_both_drivers(self):
        data = b"abcdabcdabcdabcdabcdabcdabcdxyz12345678"
        expected = b"Oabcd\x04\x00\x05\xb0xyz12345678"
        for kind in (t.SMALL, t.LARGE):
            machine = machine_for()
            table = [0] * 4096
            result = t.native_compress(machine, kind, data, 0, 0, 120, 0, table)
            self.assertEqual(result[:2], (0, expected))
            modelled = [0] * 4096
            self.assertEqual(t.model_compress(kind, data, 0, 0, 120, 0, modelled), (0, expected))
            self.assertEqual(table, modelled)

    def test_random_states_agree(self):
        for kind in (t.SMALL, t.LARGE):
            machine = machine_for()
            rng = t.Lcg(0x7E57 + kind)
            for _ in range(120):
                state = t.make_state(rng, kind)
                agree, _label, _steps = t.compare_compress(machine, kind, *state)
                self.assertTrue(agree, (kind, state[1:5]))

    def test_special_states_agree(self):
        for kind in (t.SMALL, t.LARGE):
            machine = machine_for()
            for spec in (("distance", 65535, 0), ("distance", 65536, 0), ("distance", 65537, 1), ("literal", 270), ("literal", 1291)):
                agree, _label, _steps = t.compare_compress(machine, kind, *t.special_state(kind, spec))
                self.assertTrue(agree, spec)

    def test_distance_limit_is_exclusive_at_65536(self):
        machine = machine_for()
        outputs = {}
        for kind in (t.SMALL, t.LARGE):
            for distance in (65535, 65536):
                src, start, ext, cap, pos0, table = t.boundary_state(kind, distance, 0)
                _status, produced, _steps = t.native_compress(machine, kind, src, start, ext, cap, pos0, table)
                outputs[kind, distance] = produced
            self.assertIn(b"\xff\xff", outputs[kind, 65535])
            self.assertNotIn(b"\xff\xff", outputs[kind, 65536])
            self.assertLess(len(outputs[kind, 65535]), len(outputs[kind, 65536]))

    def test_helpers_agree(self):
        machine = machine_for()
        rng = t.Lcg(0x4E1F)
        for _ in range(150):
            src = t.make_input(rng)
            while len(src) < 6:
                src = t.make_input(rng)
            other = src[rng.below(len(src) + 1):] + bytes(rng.below(20))
            pos, q = rng.below(len(src) + 1), rng.below(len(other) + 1)
            self.assertEqual(t.native_count(machine, src, pos, other, q), t.safe_count(src, pos, other, q))
            origin = rng.below(len(src) + 2)
            cap = rng.pick((len(src) + 40, len(src) // 2))
            self.assertEqual(t.native_tail(machine, src, origin, cap, 0), t.safe_tail(src, origin, cap, 0))


class NegativeControlTests(Base):
    def test_wrong_models_are_caught(self):
        for name, change in (("shift", dict(shift=19)), ("gap", dict(tail_gap=11)), ("nibble", dict(nibble=14)),
                             ("backward", dict(backward=False)), ("step", dict(step_shift=6)),
                             ("store", dict(store_first=True)), ("excess", dict(excess_base=254))):
            self.assertTrue(t.detects_model(t.SMALL, t.Flags(**change), 60), name)

    def test_boundary_variants_are_caught_only_by_the_64k_cases(self):
        self.assertTrue(t.detects_model(t.SMALL, t.Flags(dist_limit=0xFFFF), 0))
        self.assertTrue(t.detects_model(t.SMALL, t.Flags(dist_limit=0x10001), 0))
        self.assertTrue(t.detects_model(t.LARGE, t.Flags(dist_limit=0x10001), 0))

    def test_corrupted_code_bytes_are_caught(self):
        for name, patches in t.CODE_PATCHES:
            if name in ("small-hash-shift", "small-token-match-cap", "small-step-start", "tail-nibble-shift"):
                self.assertTrue(t.detects_patch(t.IMAGE, patches, 40), name)

    def test_equivalent_patches_really_emit_identical_bytes(self):
        for name, patches in t.CODE_PATCHES:
            if name not in t.EQUIVALENT_REASON:
                continue
            plain, patched = machine_for(), machine_for(dict(patches))
            for count in (270, 1289, 1290, 2100):
                for kind in (t.SMALL, t.LARGE):
                    state = t.literal_state(kind, count)
                    first = t.native_compress(plain, kind, *state[:5], list(state[5]))
                    second = t.native_compress(patched, kind, *state[:5], list(state[5]))
                    self.assertEqual(first[:2], second[:2], (name, count))

    def test_unpatched_bytes_are_not_flagged(self):
        self.assertFalse(t.detects_patch(t.IMAGE, [], 40))

    def test_patch_addresses_hold_the_expected_original_bytes(self):
        original = {0x477EABA: 0xB1, 0x477EAC0: 0x14, 0x477EAE6: 0x01, 0x477E9DF: 0x0C, 0x477EC3A: 0x0F, 0x477F777: 0x04}
        for address, value in original.items():
            self.assertEqual(t.IMAGE.blob[t.IMAGE.offset(address)], value, hex(address))

    def test_range_controls_all_refuse(self):
        for name, refused in t.range_controls():
            self.assertTrue(refused, name)

    def test_corrupted_input_changes_the_output(self):
        machine = machine_for()
        rng = t.Lcg(5)
        src = t.make_input(rng)
        while len(src) < 100:
            src = t.make_input(rng)
        first = t.native_compress(machine, t.SMALL, src, 0, 0, 400, 0, [0] * 4096)
        second = t.native_compress(machine, t.SMALL, t.mutate_bytes(src, rng), 0, 0, 400, 0, [0] * 4096)
        self.assertNotEqual(first[:2], second[:2])


if __name__ == "__main__":
    unittest.main()
